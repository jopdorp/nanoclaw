/**
 * Handle an admin's response to an approval card.
 *
 * Two categories of pending_approvals rows exist:
 *   1. Module-initiated actions — the module called `requestApproval()` with
 *      some free-form `action` string and registered a handler via
 *      `registerApprovalHandler(action, handler)`. On approve, we look up the
 *      handler and call it; on plain reject we relay a decline to the agent; on
 *      "Reject with reason…" we hold the row and capture the admin's next DM as
 *      a one-line reason (see reason-capture.ts). Reject finalization is shared
 *      via finalizeReject.
 *
 * The response handler is registered via core's `registerResponseHandler`;
 * core iterates handlers and the first one to return `true` claims the response.
 */
import type { InboundEvent } from '../../channels/adapter.js';
import { getMessagingGroup } from '../../db/messaging-groups.js';
import { getDeliveryAdapter, registerDeliveryAction } from '../../delivery.js';
import { unguarded } from '../../guard/index.js';
import { requestWake } from '../../request-wake.js';
import {
  deletePendingApproval,
  getPendingApproval,
  getPendingApprovalsInChat,
  getSession,
  transitionPendingApprovalStatus,
} from '../../db/sessions.js';
import type { ResponsePayload } from '../../response-registry.js';
import { log } from '../../log.js';
import { registerMessageInterceptor } from '../../router.js';
import { writeSessionMessage } from '../../session-manager.js';
import type { PendingApproval, Session } from '../../types.js';
import { hasAdminPrivilege, isGlobalAdmin, isOwner } from '../permissions/db/user-roles.js';
import { finalizeReject } from './finalize.js';
import { getApprovalHandler, notifyAgent, notifyApprovalResolved, REJECT_WITH_REASON_VALUE } from './primitive.js';
import { armReasonCapture, clampReason } from './reason-capture.js';

export async function handleApprovalsResponse(payload: ResponsePayload): Promise<boolean> {
  const approval = await getPendingApproval(payload.questionId);
  if (!approval) return false;

  if (!(await isAuthorizedApprovalClick(approval, payload))) {
    log.warn('Ignoring unauthorized approval response', {
      approvalId: approval.approval_id,
      action: approval.action,
      userId: payload.userId,
      channelType: payload.channelType,
    });
    return true;
  }

  await handleRegisteredApproval(approval, payload.value, namespacedUserId(payload) ?? '');
  return true;
}

async function handleRegisteredApproval(
  approval: PendingApproval,
  selectedOption: string,
  userId: string,
  reason?: string,
): Promise<void> {
  if (!approval.session_id) {
    await deletePendingApproval(approval.approval_id);
    return;
  }
  const session = await getSession(approval.session_id);
  if (!session) {
    await deletePendingApproval(approval.approval_id);
    return;
  }

  // "Reject with reason…" — hold the row and capture the admin's next DM
  // instead of finalizing now. The agent is notified exactly once: after the
  // reason arrives, or after the sweep's timeout if the admin ghosts.
  if (selectedOption === REJECT_WITH_REASON_VALUE) {
    await armReasonCapture(approval, session, userId);
    return;
  }

  // Plain Reject (or any other non-approve value) — instant fast path.
  if (selectedOption !== 'approve') {
    await finalizeReject(approval, session, userId, reason);
    return;
  }

  if (!(await transitionPendingApprovalStatus(approval.approval_id, 'pending', 'approved'))) return;

  // Approved — dispatch to the module that registered for this action.
  const notify = (text: string): Promise<void> =>
    writeSessionMessage(session.agent_group_id, session.id, {
      id: `appr-note-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      kind: 'chat',
      timestamp: new Date().toISOString(),
      platformId: session.agent_group_id,
      channelType: 'agent',
      threadId: null,
      content: JSON.stringify({ text, sender: 'system', senderId: 'system' }),
    });

  const handler = getApprovalHandler(approval.action);
  if (!handler) {
    log.warn('No approval handler registered — row dropped', {
      approvalId: approval.approval_id,
      action: approval.action,
    });
    await notify(`Your ${approval.action} was approved, but no handler is installed to apply it.`);
    await deletePendingApproval(approval.approval_id);
    await notifyApprovalResolved({ approval, session, outcome: 'approve', userId });
    await requestWake(session, 'approval-response');
    return;
  }

  const payload = JSON.parse(approval.payload);
  try {
    await handler({ session, payload, approval, userId, notify });
    log.info('Approval handled', { approvalId: approval.approval_id, action: approval.action, userId });
  } catch (err) {
    log.error('Approval handler threw', { approvalId: approval.approval_id, action: approval.action, err });
    await notify(
      `Your ${approval.action} was approved, but applying it failed: ${err instanceof Error ? err.message : String(err)}.`,
    );
  }

  await deletePendingApproval(approval.approval_id);
  await notifyApprovalResolved({ approval, session, outcome: 'approve', userId });
  await requestWake(session, 'approval-response');
}

const onlyPhrases = (phrases: string) => new RegExp(`^(?:(?:${phrases}|i|please|thanks|it)(?:[\\s.,!]+|$))+$`);
const APPROVE_REPLY = onlyPhrases(
  "yes|yep|ok|okay|approved?|go ahead|go|do it|fix it|that's fine|fine|sure|ship it|proceed|lgtm",
);
const REJECT_REPLY = onlyPhrases("no|nope|rejected?|don't|do not|stop|wait|hold|cancel|not now");
const APPROVER_MESSAGE_TTL_MS = 60 * 60 * 1000;

interface ChatAddress {
  channelType: string;
  platformId: string;
  threadId: string | null;
  instance: string;
}

/** Approver messages handed to the agent with pending approvals attached; each approval resolves once per message. */
const approverMessages = new Map<string, ChatAddress & { userId: string; approvalIds: string[]; at: number }>();

/**
 * The approver's answer, typed in the chat the approval belongs to; the sender
 * is checked exactly like a button click. A bare yes or no decides the card it
 * replies to, or the only approval pending; anything else reaches the agent
 * with the pending approvals attached, and the agent answers through
 * resolve_approval.
 */
export async function handleApprovalTextReply(event: InboundEvent): Promise<boolean> {
  let content: Record<string, unknown>;
  try {
    content = JSON.parse(event.message.content);
    // eslint-disable-next-line no-catch-all/no-catch-all -- content that is not JSON is not an approval answer
  } catch {
    return false;
  }
  const chat: ChatAddress = {
    channelType: event.channelType,
    platformId: event.platformId,
    threadId: event.threadId,
    instance: event.instance ?? event.channelType,
  };
  const payload: ResponsePayload = {
    questionId: '',
    value: '',
    userId: typeof content.senderId === 'string' ? content.senderId : null,
    ...chat,
  };
  const mine: PendingApproval[] = [];
  for (const a of await getPendingApprovalsInChat(chat.channelType, chat.platformId)) {
    if ((a.instance ?? a.channel_type) === chat.instance && (await isAuthorizedApprovalClick(a, payload))) mine.push(a);
  }
  if (mine.length === 0) return false;
  const userId = namespacedUserId(payload) ?? '';

  const replyToId = (content.replyTo as { id?: unknown } | undefined)?.id;
  const target = replyToId
    ? mine.find((a) => a.platform_message_id === replyToId)
    : mine.length === 1
      ? mine[0]
      : undefined;
  const said = (typeof content.text === 'string' ? content.text : '').trim().toLowerCase().replace(/’/g, "'");
  const option = APPROVE_REPLY.test(said) ? 'approve' : REJECT_REPLY.test(said) ? 'reject' : null;
  if (target && option) {
    await decide(target, option, userId, chat);
    return true;
  }

  const now = Date.now();
  for (const [id, m] of approverMessages) if (now - m.at > APPROVER_MESSAGE_TTL_MS) approverMessages.delete(id);
  approverMessages.set(event.message.id, { ...chat, userId, approvalIds: mine.map((a) => a.approval_id), at: now });
  // routeInbound delivers this same event object, so the context rides on its content.
  event.message.content = JSON.stringify({
    ...content,
    pendingApprovals: [
      `approverMessageId: ${event.message.id}`,
      ...mine.map(
        (a) =>
          `${a.approval_id.slice(-6)} · ${a.title} · ${a.question.split('\n')[0].slice(0, 160)} · created ${a.created_at}${a.platform_message_id ? ` · card ${a.platform_message_id}` : ''}`,
      ),
    ].join('\n'),
  });
  return false;
}

/** resolve_approval: the agent's reading of an approver message the host recorded above. */
export async function resolveApprovalAction(content: Record<string, unknown>, session: Session): Promise<void> {
  const refuse = (why: string) => notifyAgent(session, `resolve_approval refused, nothing was resolved: ${why}`);
  const { approvalIds, decision, reason, approverMessageId } = content;
  if (!Array.isArray(approvalIds) || approvalIds.length === 0 || typeof approverMessageId !== 'string') {
    return refuse('approvalIds (at least one) and approverMessageId are required.');
  }
  if (decision !== 'approve' && decision !== 'reject') return refuse('decision must be approve or reject.');
  const message = approverMessages.get(approverMessageId);
  if (!message || Date.now() - message.at > APPROVER_MESSAGE_TTL_MS) {
    return refuse(`${approverMessageId} is not a recent approver reply sent while approvals were pending.`);
  }
  const fullIds: string[] = [];
  for (const id of new Set(approvalIds)) {
    const fullId = message.approvalIds.find((full) => full === id || full.endsWith(`-${id}`));
    if (!fullId)
      return refuse(`${id} was not pending when the approver wrote ${approverMessageId}, or it already resolved.`);
    fullIds.push(fullId);
  }
  message.approvalIds = message.approvalIds.filter((id) => !fullIds.includes(id));

  const chat = session.messaging_group_id ? await getMessagingGroup(session.messaging_group_id) : undefined;
  if (
    chat?.channel_type !== message.channelType ||
    chat.platform_id !== message.platformId ||
    (chat.instance ?? chat.channel_type) !== message.instance
  ) {
    return refuse(`${approverMessageId} was not sent in this conversation.`);
  }
  const approvals: PendingApproval[] = [];
  for (const id of fullIds) {
    const approval = await getPendingApproval(id);
    if (approval?.status !== 'pending') return refuse(`${id.slice(-6)} is no longer pending.`);
    if (!(await isAuthorizedApprovalClick(approval, { questionId: id, value: decision, ...message }))) {
      return refuse(`${approverMessageId} is not from the approver of ${id.slice(-6)}.`);
    }
    approvals.push(approval);
  }
  for (const approval of approvals) {
    await decide(
      approval,
      decision,
      message.userId,
      message,
      typeof reason === 'string' ? clampReason(reason) : undefined,
    );
  }
}

async function decide(
  approval: PendingApproval,
  option: string,
  userId: string,
  chat: ChatAddress,
  reason?: string,
): Promise<void> {
  await handleRegisteredApproval(approval, option, userId, reason);
  await say(chat, `${option === 'approve' ? '✅ Done' : '❌ Not doing'}: ${approval.title}`);
}

async function say(chat: ChatAddress, text: string): Promise<void> {
  await getDeliveryAdapter()?.deliver(
    chat.channelType,
    chat.platformId,
    chat.threadId,
    'chat-sdk',
    JSON.stringify({ text }),
    undefined,
    chat.instance,
  );
}

registerMessageInterceptor(handleApprovalTextReply);
registerDeliveryAction(
  'resolve_approval',
  resolveApprovalAction,
  unguarded('it is itself an approval answer, checked against the recorded approver message'),
);

export function namespacedUserId(payload: ResponsePayload): string | null {
  if (!payload.userId) return null;
  return payload.userId.includes(':') ? payload.userId : `${payload.channelType}:${payload.userId}`;
}

export async function isAuthorizedApprovalClick(approval: PendingApproval, payload: ResponsePayload): Promise<boolean> {
  const userId = namespacedUserId(payload);
  if (!userId) return false;

  // An approval may name a specific approver; only that exact user may resolve it.
  if (approval.approver_user_id) {
    return userId === approval.approver_user_id;
  }

  const agentGroupId =
    approval.agent_group_id ?? (approval.session_id ? (await getSession(approval.session_id))?.agent_group_id : null);

  if (!agentGroupId) {
    return (await isOwner(userId)) || (await isGlobalAdmin(userId));
  }

  return hasAdminPrivilege(userId, agentGroupId);
}
