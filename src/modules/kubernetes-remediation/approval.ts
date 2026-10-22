import { getDeliveryAdapter, reenterGuardedDeliveryAction, registerDeliveryAction } from '../../delivery.js';
import { ALLOW, DENY, HOLD, defineGuardedAction, type GuardInput } from '../../guard/index.js';
import { log } from '../../log.js';
import { notifyAgent, registerApprovalHandler, requestApproval } from '../approvals/index.js';
import { pickApprovalDelivery } from '../approvals/primitive.js';
import { isAutoApproved, validateRemediationPlan } from './policy.js';
import type { HelmReleaseExecutor } from './helm-release.js';
import { tagMatchesDigest, type RegistryFetch } from './registry.js';
import {
  REMEDIATION_ACTION,
  type HelmValuesPlan,
  type ManifestEditPlan,
  type RemediationExecutor,
  type ValidatedPlan,
  type ValuesEdit,
} from './types.js';
import type { Session } from '../../types.js';

const AUTO_APPROVER = 'auto:low-risk';
// The guard is module-scoped, so the T1 list from the runtime config lands here at registration.
let t1: ReadonlySet<string> = new Set();

/** A plan after the host's async checks; precheck, guard and handler of one consult share it. */
interface Prepared {
  validated: ValidatedPlan;
  auto: boolean;
  diff: string[];
}
const preparedFor = new WeakMap<Record<string, unknown>, Prepared>();

function decide(input: GuardInput) {
  if (input.actor.kind !== 'agent') return DENY('remediation proposals must originate from the dedicated agent group');
  validateRemediationPlan(input.payload.plan);
  return preparedFor.get(input.payload)?.auto
    ? ALLOW('the owner lists this plan as automatic')
    : HOLD('this remediation plan requires an explicit Matrix approval');
}

const remediationGuard = defineGuardedAction({
  action: 'kubernetes.remediation.apply',
  grantActionName: REMEDIATION_ACTION,
  decide,
  grantCoversRequest: (grant, input) => {
    try {
      const held = JSON.parse(grant.payload) as { plan?: unknown; digest?: unknown };
      const replayed = validateRemediationPlan(input.payload.plan);
      return held.digest === replayed.digest;
      // eslint-disable-next-line no-catch-all/no-catch-all -- malformed grants fail closed
    } catch {
      return false;
    }
  },
});

function planInput(content: Record<string, unknown>): unknown {
  return content.plan;
}

const tagOf = (image: string) =>
  image.split('@')[0].split('/').at(-1)?.split(':')[1] ?? image.split('@')[1]?.slice(7, 19);

const edits = (set: ValuesEdit[], arrow = '→') =>
  set.map((e) => `${e.path} ${JSON.stringify(e.before)} ${arrow} ${JSON.stringify(e.after)}`).join(', ');

/** What the plan does, in one line; `full` spells out every value and argument for the approval question. */
function describe({ plan }: ValidatedPlan, full: boolean): string {
  const { target, operation: op } = plan;
  const where = `${target.namespace ?? '_cluster'}/${target.name}`;
  switch (op.type) {
    case 'patch-image':
      return full
        ? `${op.containers.map((c) => (c.initContainer ? `init:${c.name}` : c.name)).join(', ')}: ${op.before} -> ${op.after}`
        : `update ${where} image ${tagOf(op.before)} → ${tagOf(op.after)}`;
    case 'scale':
      return `scale ${where} ${op.before} → ${op.after}`;
    case 'restart':
      return full ? `restart at ${op.restartedAt}` : `restart ${where}`;
    case 'helm-values':
      return full
        ? `helm release ${target.name}, ${op.file}: ${edits(op.set, '->')}`
        : `helm ${where}: ${edits(op.set)}`;
    case 'helm-sync-values':
      return `sync helm values of ${where} from live into ${op.file}`;
    case 'helm-install':
      return `install ${op.chart} ${op.version} as ${where} with ${op.file}`;
    case 'helm-uninstall':
      return `uninstall helm release ${where}`;
    case 'repo-write':
      return full
        ? `write ${op.path} and apply its objects:\n${op.content.length > 2000 ? `${op.content.slice(0, 2000)}…` : op.content}`
        : `write and apply ${op.path}`;
    case 'manifest-edit':
      return full
        ? `${op.file}, ${target.kind} ${where}: ${edits(op.set, '->')}`
        : `edit ${target.kind} ${where}: ${edits(op.set)}`;
    case 'manifest-sync':
      return `sync ${target.kind} ${where} from live into ${op.file}`;
    case 'pod-exec':
      return full
        ? `exec in ${where} container ${op.container}: ${JSON.stringify(op.command)}`
        : `exec in ${where}: ${op.command.join(' ')}`;
    case 'build-image':
      return `build ${op.image} from ${op.dockerfile}`;
    default:
      return `delete ${target.kind} ${where}`;
  }
}

/** One line that tells plans apart in the approver's acks and the agent's pending list. */
function summary(validated: ValidatedPlan): string {
  const text = describe(validated, false);
  return text.length > 80 ? `${text.slice(0, 79)}…` : text;
}

function renderQuestion(validated: ValidatedPlan, diff: string[] = []): string {
  const { plan, lane, digest, automaticWriteCap } = validated;
  return [
    `lane: ${lane === 'C' ? 'C, applied with the break-glass identity' : lane}`,
    `target: ${plan.target.namespace ?? '_cluster'}/${plan.target.kind}/${plan.target.name}`,
    `uid: ${plan.target.uid}`,
    `resourceVersion: ${plan.target.resourceVersion}`,
    `change: ${describe(validated, true)}`,
    ...(diff.length ? [`values diff against live: ${diff.join('; ')}`] : []),
    `reason: ${plan.reason}`,
    `automatic same-target recovery writes: ${automaticWriteCap}`,
    `expires: ${plan.expiresAt}`,
    `plan sha256: ${digest}`,
  ].join('\n');
}

export async function notifyApprover(userId: string, text: string): Promise<void> {
  const adapter = getDeliveryAdapter();
  const target = adapter && (await pickApprovalDelivery([userId], ''));
  if (!adapter || !target) {
    log.error('Auto-approved remediation notice has no Matrix delivery', { userId });
    return;
  }
  const { channel_type, platform_id, instance } = target.messagingGroup;
  try {
    await adapter.deliver(
      channel_type,
      platform_id,
      null,
      'chat',
      JSON.stringify({ text }),
      undefined,
      instance ?? undefined,
    );
    // eslint-disable-next-line no-catch-all/no-catch-all -- a throw here would make delivery replay an applied plan
  } catch (error) {
    log.error('Auto-approved remediation notice failed', { userId, error });
  }
}

export function registerKubernetesRemediationApproval(options: {
  agentGroupId: string;
  approverUserId: string;
  executor: RemediationExecutor;
  helm?: HelmReleaseExecutor;
  breakGlassHelm?: HelmReleaseExecutor;
  registry?: RegistryFetch;
  t1: ReadonlySet<string>;
}): void {
  t1 = options.t1;
  const verify = async (images: Array<string | undefined>) => {
    for (const image of images) {
      if (image && options.registry && (await tagMatchesDigest(image, options.registry)) === false)
        throw new Error(`the registry serves a different digest for the tag of ${image}`);
    }
  };
  const prepare = async (content: Record<string, unknown>): Promise<Prepared> => {
    let validated = validateRemediationPlan(planInput(content));
    const { operation } = validated.plan;
    const repo = validated.lane === 'C' ? options.breakGlassHelm : options.helm;
    if (operation.type === 'helm-values' || operation.type === 'manifest-edit') {
      if (!repo) throw new Error('the Helm and manifest path is not configured');
      if (operation.type === 'manifest-edit') {
        await verify(operation.set.filter((e) => /(?:^|\.)image$/.test(e.path)).map((e) => String(e.after)));
        validated = validateRemediationPlan(await repo.bindManifest(validated.plan as ManifestEditPlan));
        return { validated, auto: isAutoApproved(validated, t1), diff: [] };
      }
      const binding = await repo.bind(validated.plan as HelmValuesPlan);
      await verify(Object.values(binding.images).map((image) => image.after));
      validated = validateRemediationPlan(binding.plan);
      return { validated, auto: isAutoApproved(validated, t1, binding), diff: binding.diff };
    }
    await verify(operation.type === 'patch-image' ? [operation.after] : []);
    return { validated, auto: isAutoApproved(validated, t1), diff: [] };
  };
  const precheck = async (content: Record<string, unknown>, session: Session) => {
    if (session.agent_group_id !== options.agentGroupId) return false;
    try {
      preparedFor.set(content, await prepare(content));
      return true;
      // eslint-disable-next-line no-catch-all/no-catch-all -- agent proposals are untrusted input
    } catch (error) {
      await notifyAgent(
        session,
        `kubernetes remediation rejected: ${error instanceof Error ? error.message : String(error)}`,
      );
      return false;
    }
  };

  registerDeliveryAction(
    REMEDIATION_ACTION,
    async (content, session) => {
      const prepared = preparedFor.get(content) ?? (await prepare(content));
      const auto = prepared.auto;
      if (!auto && content.approvedBy !== options.approverUserId)
        throw new Error('approval came from the wrong Matrix user');
      // An approved plan runs exactly as approved, never re-bound.
      const validated = auto ? prepared.validated : validateRemediationPlan(planInput(content));
      let message: string;
      try {
        const result = await options.executor.execute(validated, {
          approvalRowId: auto ? '' : String(content.approvalRowId ?? ''),
          approverUserId: auto ? AUTO_APPROVER : String(content.approvedBy),
          planId: validated.plan.id,
          planDigest: validated.digest,
        });
        message = result.message;
      } catch (error) {
        if (!auto) throw error;
        message = `Auto-approved plan ${validated.plan.id} failed: ${error instanceof Error ? error.message : String(error)}`;
      }
      await notifyAgent(session, message);
      if (auto) {
        await notifyApprover(
          options.approverUserId,
          `Auto-applied remediation\n${renderQuestion(validated, prepared.diff)}\noutcome: ${message}`,
        );
      }
    },
    {
      guardAction: remediationGuard,
      precheck,
      requestHold: async (content, session) => {
        const { validated, diff } = preparedFor.get(content) ?? (await prepare(content));
        await requestApproval({
          session,
          agentName: 'Kubernetes Remediator',
          action: REMEDIATION_ACTION,
          payload: { plan: validated.plan, digest: validated.digest },
          title: summary(validated),
          question: renderQuestion(validated, diff),
          approverUserId: options.approverUserId,
        });
      },
      onDeny: (_content, session, reason) => notifyAgent(session, `kubernetes remediation denied: ${reason}`),
    },
  );

  registerApprovalHandler(REMEDIATION_ACTION, async (ctx) => {
    const validated = validateRemediationPlan(ctx.payload.plan);
    if (ctx.payload.digest !== validated.digest) throw new Error('stored approval payload digest mismatch');
    const handler = reenterGuardedDeliveryAction(REMEDIATION_ACTION);
    await handler({
      session: ctx.session,
      approval: ctx.approval,
      payload: { plan: validated.plan, approvalRowId: ctx.approval.approval_id, approvedBy: ctx.userId },
    });
  });
}
