import { reenterGuardedDeliveryAction, registerDeliveryAction } from '../../delivery.js';
import { DENY, HOLD, defineGuardedAction, type GuardInput } from '../../guard/index.js';
import { notifyAgent, registerApprovalHandler, requestApproval } from '../approvals/index.js';
import { validateRemediationPlan } from './policy.js';
import { REMEDIATION_ACTION, type RemediationExecutor } from './types.js';
import type { Session } from '../../types.js';

function decide(input: GuardInput) {
  return input.actor.kind === 'agent'
    ? HOLD('every remediation plan requires an explicit Matrix approval')
    : DENY('remediation proposals must originate from the dedicated agent group');
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

function renderQuestion(value: unknown): string {
  const validated = validateRemediationPlan(value);
  const { plan, lane, digest, automaticWriteCap } = validated;
  const operation = plan.operation;
  const change =
    operation.type === 'patch-image'
      ? `${operation.container}: ${operation.before} -> ${operation.after}`
      : operation.type === 'scale'
        ? `replicas: ${operation.before} -> ${operation.after}`
        : operation.type === 'restart'
          ? `restart at ${operation.restartedAt}`
          : operation.type === 'delete-storage'
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
      if (content.approvedBy !== options.approverUserId) throw new Error('approval came from the wrong Matrix user');
      const result = await options.executor.execute(validated, {
        approvalRowId: String(content.approvalRowId ?? ''),
        approverUserId: String(content.approvedBy ?? ''),
        planId: validated.plan.id,
        planDigest: validated.digest,
      });
      await notifyAgent(session, result.message);
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
          question: renderQuestion(validated.plan),
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
