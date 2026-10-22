import { getDeliveryAdapter, reenterGuardedDeliveryAction, registerDeliveryAction } from '../../delivery.js';
import { ALLOW, DENY, HOLD, defineGuardedAction, type GuardInput } from '../../guard/index.js';
import { log } from '../../log.js';
import { notifyAgent, registerApprovalHandler, requestApproval } from '../approvals/index.js';
import { pickApprovalDelivery } from '../approvals/primitive.js';
import { isLowRiskAutoApprove, validateRemediationPlan } from './policy.js';
import { REMEDIATION_ACTION, type RemediationExecutor, type ValidatedPlan } from './types.js';
import type { Session } from '../../types.js';

const AUTO_APPROVER = 'auto:low-risk';

function decide(input: GuardInput) {
  if (input.actor.kind !== 'agent') return DENY('remediation proposals must originate from the dedicated agent group');
  return isLowRiskAutoApprove(validateRemediationPlan(input.payload.plan))
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
            : `manual Lane C request: ${operation.requestedChange}`;
  return [
    `lane: ${lane}`,
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

async function notifyApprover(userId: string, text: string): Promise<void> {
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
}): void {
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
      const validated = validateRemediationPlan(planInput(content));
      const auto = isLowRiskAutoApprove(validated);
      if (!auto && content.approvedBy !== options.approverUserId)
        throw new Error('approval came from the wrong Matrix user');
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
          `Auto-approved low-risk remediation\n${renderQuestion(validated)}\noutcome: ${message}`,
        );
      }
    },
    {
      guardAction: remediationGuard,
      precheck: validate,
      requestHold: async (content, session) => {
        const validated = validateRemediationPlan(planInput(content));
        await requestApproval({
          session,
          agentName: 'Kubernetes Remediator',
          action: REMEDIATION_ACTION,
          payload: { plan: validated.plan, digest: validated.digest },
          title: 'Kubernetes remediation approval',
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
