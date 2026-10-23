import { getDeliveryAdapter, reenterGuardedDeliveryAction, registerDeliveryAction } from '../../delivery.js';
import { ALLOW, DENY, HOLD, defineGuardedAction, type GuardInput } from '../../guard/index.js';
import { log } from '../../log.js';
import { notifyAgent, registerApprovalHandler, requestApproval } from '../approvals/index.js';
import { pickApprovalDelivery } from '../approvals/primitive.js';
import fs from 'node:fs';

import {
  canonicalPlan,
  checkImageUpdate,
  isAutoApproved,
  standingGrant,
  validateRemediationPlan,
  type StandingGrant,
} from './policy.js';
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
  /** Only the repo or Helm record changes; the cluster stays as it is. */
  unchanged?: boolean;
  /** Why an approval-class plan needs no card: a standing grant or an earlier yes to the same change. */
  approvedBefore?: string;
}

const DAY = 24 * 60 * 60_000;
// Plans being applied right now; a host shutdown waits for them instead of killing helm or a rollout midway.
const running = new Set<Promise<unknown>>();
let draining = false;

export async function drainRemediation(): Promise<void> {
  draining = true;
  await Promise.allSettled([...running]);
}

/** The change itself, without the per-submission identity, expiry and binding. */
function changeKey({ plan }: ValidatedPlan): string {
  return canonicalPlan({
    ...plan,
    id: '',
    incidentIds: [],
    reason: '',
    expiresAt: '',
    target: { ...plan.target, uid: '', resourceVersion: '' },
  });
}
const preparedFor = new WeakMap<Record<string, unknown>, Prepared>();

function decide(input: GuardInput) {
  if (input.actor.kind !== 'agent') return DENY('remediation proposals must originate from the dedicated agent group');
  // The prepared plan carries what the host bound from the cluster, the running digest; the agent's never does.
  validateRemediationPlan(preparedFor.get(input.payload)?.validated.plan ?? input.payload.plan);
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
        ? `helm release ${target.name}${op.chart?.version ? ` chart ${op.chart.version}` : ''}, ${op.file}: ${edits(op.set, '->')}`
        : `helm ${where}${op.chart?.version ? ` chart ${op.chart.version}` : ''}: ${edits(op.set)}`;
    case 'helm-sync-values':
      return `sync helm values of ${where} from live into ${op.file}`;
    case 'helm-install':
      return `install ${op.chart} ${op.version} as ${where} with ${op.file}`;
    case 'write-secret':
      return `write Secret ${where} (${op.secretType}) keys ${Object.keys(op.stringData).join(', ')}`;
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
    case 'node-cordon':
    case 'node-uncordon':
    case 'node-reboot':
    case 'tang-start':
    case 'tang-stop':
      return `${op.type} ${target.name}`;
    case 'batocera-exec':
      return `batocera ${target.name}: ${op.command}`;
    case 'remove-attachment-ticket':
      return `remove attachment ticket ${op.ticket} from ${target.kind} ${target.name}`;
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
  /** Orfie's group and the agents it works with; only they may propose. */
  team: (agentGroupId: string) => Promise<boolean>;
  approverUserId: string;
  executor: RemediationExecutor;
  helm?: HelmReleaseExecutor;
  breakGlassHelm?: HelmReleaseExecutor;
  registry?: RegistryFetch;
  t1: ReadonlySet<string>;
  grants?: () => StandingGrant[];
  /** The digest a workload's pods run, for a tag-only image moving to another repository. */
  runningDigest?: (target: ValidatedPlan['plan']['target'], containers: string[]) => Promise<string | undefined>;
  /** Approved changes by changeKey, so a resubmission after the card expired applies for a day. */
  yesFile?: string;
}): void {
  t1 = options.t1;
  const yeses = (): Record<string, number> => {
    if (!options.yesFile || !fs.existsSync(options.yesFile)) return {};
    const all = JSON.parse(fs.readFileSync(options.yesFile, 'utf8')) as Record<string, number>;
    return Object.fromEntries(Object.entries(all).filter(([, at]) => Date.now() - at < DAY));
  };
  const approvedBefore = (validated: ValidatedPlan): string | undefined => {
    const grant = standingGrant(validated, options.grants?.() ?? []);
    if (grant) return `applied under your standing yes from ${grant.grantedAt.slice(0, 10)}`;
    return yeses()[changeKey(validated)] ? 'applied under your earlier yes to this change' : undefined;
  };
  const verify = async (images: Array<string | undefined>) => {
    for (const image of images) {
      if (image && options.registry && (await tagMatchesDigest(image, options.registry)) === false)
        throw new Error(`the registry serves a different digest for the tag of ${image}`);
    }
  };
  const withApproval = (prepared: Prepared): Prepared => {
    if (prepared.auto) return prepared;
    const because = approvedBefore(prepared.validated);
    return because ? { ...prepared, auto: true, approvedBefore: because } : prepared;
  };
  /** Binds runningDigest from the live pods; whatever the agent put there is never trusted. */
  const bindRunningDigest = async (input: unknown): Promise<unknown> => {
    const plan = (input ?? {}) as { operation?: Record<string, unknown>; target?: ValidatedPlan['plan']['target'] };
    const op = plan.operation;
    if (!op || !plan.target || (op.type !== 'patch-image' && op.type !== 'manifest-edit')) return input;
    const { runningDigest: _untrusted, ...rest } = op;
    const images = (Array.isArray(op.set) ? op.set : []).filter(
      (e: { path?: string; before?: unknown }) =>
        /(?:^|\.)image$/.test(String(e.path)) && !String(e.before ?? '').includes('@sha256:'),
    );
    const tagOnly = op.type === 'patch-image' ? !String(op.before ?? '').includes('@sha256:') : images.length > 0;
    const containers =
      op.type === 'patch-image'
        ? (Array.isArray(op.containers) ? op.containers : []).map((c: { name?: string }) => String(c.name))
        : images.map((e: { path?: string }) => /(?:initC|c)ontainers\.\d+(?=\.image$)/.exec(String(e.path))?.[0] ?? '');
    const digest =
      tagOnly && options.runningDigest
        ? await options.runningDigest(plan.target, containers).catch(() => undefined)
        : undefined;
    return { ...plan, operation: { ...rest, ...(digest ? { runningDigest: digest } : {}) } };
  };
  const prepare = async (content: Record<string, unknown>): Promise<Prepared> => {
    let validated = validateRemediationPlan(await bindRunningDigest(planInput(content)));
    const { operation } = validated.plan;
    const repo = validated.lane === 'C' ? options.breakGlassHelm : options.helm;
    if (operation.type === 'helm-values' || operation.type === 'manifest-edit') {
      if (!repo) throw new Error('the Helm and manifest path is not configured');
      if (operation.type === 'manifest-edit') {
        await verify(operation.set.filter((e) => /(?:^|\.)image$/.test(e.path)).map((e) => String(e.after)));
        const bound = await repo.bindManifest(validated.plan as ManifestEditPlan);
        validated = validateRemediationPlan(bound.plan);
        return withApproval({
          validated,
          auto: bound.unchanged || isAutoApproved(validated, t1),
          diff: [],
          unchanged: bound.unchanged,
        });
      }
      const binding = await repo.bind(validated.plan as HelmValuesPlan);
      // What the chart composes from the edited values, which is what the cluster will run.
      for (const { before, after } of Object.values(binding.images))
        checkImageUpdate(before ?? after ?? '', after ?? '');
      await verify(Object.values(binding.images).map((image) => image.after));
      validated = validateRemediationPlan(binding.plan);
      return withApproval({
        validated,
        auto: binding.unchanged || isAutoApproved(validated, t1, binding),
        diff: binding.diff,
        unchanged: binding.unchanged,
      });
    }
    await verify(operation.type === 'patch-image' ? [operation.after] : []);
    return withApproval({ validated, auto: isAutoApproved(validated, t1), diff: [] });
  };
  const precheck = async (content: Record<string, unknown>, session: Session) => {
    if (!(await options.team(session.agent_group_id))) return false;
    if (draining) {
      await notifyAgent(session, 'kubernetes remediation paused: the host is restarting; resubmit once it is back');
      return false;
    }
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
        const execution = options.executor.execute(validated, {
          approvalRowId: auto ? '' : String(content.approvalRowId ?? ''),
          approverUserId: auto ? AUTO_APPROVER : String(content.approvedBy),
          planId: validated.plan.id,
          planDigest: validated.digest,
        });
        running.add(execution);
        const result = await execution.finally(() => running.delete(execution));
        message = [
          prepared.unchanged && result.applied ? 'record updated, nothing changed' : '',
          prepared.approvedBefore ?? '',
          result.message,
        ]
          .filter(Boolean)
          .join('; ');
      } catch (error) {
        if (!auto) throw error;
        message = `Auto-approved plan ${validated.plan.id} failed: ${error instanceof Error ? error.message : String(error)}`;
      }
      await notifyAgent(
        session,
        `${auto ? 'auto-applied' : 'approved and ran'}: ${summary(validated)}; outcome: ${message}\nTell the approver in one plain sentence.\n${renderQuestion(validated, prepared.diff)}`,
      );
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
    if (options.yesFile) {
      fs.writeFileSync(`${options.yesFile}.tmp`, JSON.stringify({ ...yeses(), [changeKey(validated)]: Date.now() }));
      fs.renameSync(`${options.yesFile}.tmp`, options.yesFile);
    }
    const handler = reenterGuardedDeliveryAction(REMEDIATION_ACTION);
    await handler({
      session: ctx.session,
      approval: ctx.approval,
      payload: { plan: validated.plan, approvalRowId: ctx.approval.approval_id, approvedBy: ctx.userId },
    });
  });
}
