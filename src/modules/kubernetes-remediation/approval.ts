import { getDeliveryAdapter, reenterGuardedDeliveryAction, registerDeliveryAction } from '../../delivery.js';
import { ALLOW, DENY, HOLD, defineGuardedAction, type GuardInput } from '../../guard/index.js';
import { log } from '../../log.js';
import { notifyAgent, registerApprovalHandler, requestApproval } from '../approvals/index.js';
import { pickApprovalDelivery } from '../approvals/primitive.js';
import { isAutoApproved, validateRemediationPlan } from './policy.js';
import type { HelmReleaseExecutor } from './helm-release.js';
import { REMEDIATION_ACTION, type HelmValuesPlan, type RemediationExecutor, type ValidatedPlan } from './types.js';
import type { Session } from '../../types.js';

const AUTO_APPROVER = 'auto:low-risk';
// The guard is module-scoped, so the T1 list from the runtime config lands here at registration.
let t1: ReadonlySet<string> = new Set();

function decide(input: GuardInput) {
  if (input.actor.kind !== 'agent') return DENY('remediation proposals must originate from the dedicated agent group');
  return isAutoApproved(validateRemediationPlan(input.payload.plan), t1)
    ? ALLOW('low-risk Lane A plan is auto-approved')
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

/** One line that tells plans apart in the approver's acks and the agent's pending list. */
function summary({ plan }: ValidatedPlan): string {
  const { target, operation } = plan;
  const where = `${target.namespace ?? '_cluster'}/${target.name}`;
  const text =
    operation.type === 'patch-image'
      ? `update ${where} image ${tagOf(operation.before)} → ${tagOf(operation.after)}`
      : operation.type === 'scale'
        ? `scale ${where} ${operation.before} → ${operation.after}`
        : operation.type === 'restart'
          ? `restart ${where}`
          : operation.type === 'helm-values'
            ? `helm ${where}: ${operation.set.map((e) => `${e.path} ${String(e.before)} → ${String(e.after)}`).join(', ')}`
            : `delete ${target.kind} ${where}`;
  return text.length > 80 ? `${text.slice(0, 79)}…` : text;
}

function renderQuestion({ plan, lane, digest, automaticWriteCap }: ValidatedPlan): string {
  const operation = plan.operation;
  const change =
    operation.type === 'patch-image'
      ? `${operation.containers.map((c) => (c.initContainer ? `init:${c.name}` : c.name)).join(', ')}: ${operation.before} -> ${operation.after}`
      : operation.type === 'scale'
        ? `replicas: ${operation.before} -> ${operation.after}`
        : operation.type === 'restart'
          ? `restart at ${operation.restartedAt}`
          : operation.type === 'delete-storage' || operation.type === 'delete-job'
            ? `delete ${plan.target.kind}`
            : `helm release ${plan.target.name}, ${operation.file}: ${operation.set.map((e) => `${e.path}: ${JSON.stringify(e.before)} -> ${JSON.stringify(e.after)}`).join(', ')}`;
  return [
    `lane: ${lane === 'C' ? 'C, applied with the break-glass identity' : lane}`,
    `target: ${plan.target.namespace ?? '_cluster'}/${plan.target.kind}/${plan.target.name}`,
    `uid: ${plan.target.uid}`,
    `resourceVersion: ${plan.target.resourceVersion}`,
    `change: ${change}`,
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
  t1: ReadonlySet<string>;
}): void {
  t1 = options.t1;
  const validate = async (content: Record<string, unknown>, session: Session) => {
    if (session.agent_group_id !== options.agentGroupId) return false;
    try {
      validateRemediationPlan(planInput(content));
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
      let validated = validateRemediationPlan(planInput(content));
      const auto = isAutoApproved(validated, t1);
      if (!auto && content.approvedBy !== options.approverUserId)
        throw new Error('approval came from the wrong Matrix user');
      let message: string;
      try {
        if (auto && validated.plan.operation.type === 'helm-values') {
          if (!options.helm) throw new Error('the Helm path is not configured');
          validated = validateRemediationPlan(await options.helm.bind(validated.plan as HelmValuesPlan));
        }
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
          `Auto-applied remediation\n${renderQuestion(validated)}\noutcome: ${message}`,
        );
      }
    },
    {
      guardAction: remediationGuard,
      precheck: validate,
      requestHold: async (content, session) => {
        let validated = validateRemediationPlan(planInput(content));
        if (validated.plan.operation.type === 'helm-values') {
          try {
            const helm = validated.lane === 'C' ? options.breakGlassHelm : options.helm;
            if (!helm) throw new Error('the Helm path is not configured');
            validated = validateRemediationPlan(await helm.bind(validated.plan as HelmValuesPlan));
            // eslint-disable-next-line no-catch-all/no-catch-all -- the agent hears why its plan got no card
          } catch (error) {
            await notifyAgent(
              session,
              `kubernetes remediation rejected: ${error instanceof Error ? error.message : String(error)}`,
            );
            return;
          }
        }
        await requestApproval({
          session,
          agentName: 'Kubernetes Remediator',
          action: REMEDIATION_ACTION,
          payload: { plan: validated.plan, digest: validated.digest },
          title: summary(validated),
          question: renderQuestion(validated),
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
