import { restartAgentGroupContainers } from '../container-restart.js';
import { getContainerConfig, updateContainerConfigScalars } from '../db/container-configs.js';
import { getMessagingGroup, getMessagingGroupByPlatform } from '../db/messaging-groups.js';
import { getDeliveryAdapter, registerDeliveryAction } from '../delivery.js';
import { unguarded } from '../guard/index.js';
import { log } from '../log.js';
import { withExistingMailboxSession } from '../session-manager.js';
import type { Session } from '../types.js';
import { hasAdminPrivilege } from './permissions/db/user-roles.js';

export const MODEL_ENGINES = {
  fable: { provider: 'claude', model: 'claude-fable-5-1' },
  opus: { provider: 'claude', model: 'claude-opus-5-5' },
  sonnet: { provider: 'claude', model: 'claude-sonnet-5-5' },
  haiku: { provider: 'claude', model: 'claude-haiku-5-5' },
  astra: { provider: 'codex', model: 'gpt-6-astra' },
  sol: { provider: 'codex', model: 'gpt-5.6-sol' },
  terra: { provider: 'codex', model: 'gpt-5.6-terra' },
  luna: { provider: 'codex', model: 'gpt-5.6-luna' },
} as const;

const EFFORTS = new Set(['low', 'medium', 'high', 'xhigh']);

export function modelForEngine(engine: string) {
  return MODEL_ENGINES[engine.toLowerCase() as keyof typeof MODEL_ENGINES];
}

function senderId(content: string, channelType: string | null): string | undefined {
  try {
    const parsed = JSON.parse(content) as {
      senderId?: unknown;
      sender?: unknown;
      author?: { userId?: unknown; isBot?: unknown };
    };
    if (parsed.author?.isBot === true) return undefined;
    const raw = [parsed.senderId, parsed.sender, parsed.author?.userId].find((value) => typeof value === 'string');
    if (typeof raw !== 'string' || raw.startsWith('cli:') || !channelType || channelType === 'agent') return undefined;
    return raw.includes(':') ? raw : `${channelType}:${raw}`;
    // eslint-disable-next-line no-catch-all/no-catch-all -- malformed chat payloads are unauthorized
  } catch {
    return undefined;
  }
}

async function triggeringAdmin(content: Record<string, unknown>, session: Session) {
  const triggerMessageId = content.triggerMessageId;
  if (typeof triggerMessageId !== 'string') return undefined;
  const message = await withExistingMailboxSession(session.agent_group_id, session.id, (mailbox) =>
    mailbox.getInboundMessage(triggerMessageId),
  );
  if (!message || !['chat', 'chat-sdk'].includes(message.kind)) return undefined;
  const userId = senderId(message.content, message.channelType);
  if (!userId || !(await hasAdminPrivilege(userId, session.agent_group_id))) return undefined;
  return message;
}

async function reply(
  session: Session,
  trigger: NonNullable<Awaited<ReturnType<typeof triggeringAdmin>>>,
  text: string,
) {
  if (!trigger.channelType || !trigger.platformId) return;
  const adapter = getDeliveryAdapter();
  if (!adapter) throw new Error('No delivery adapter configured');
  const origin = session.messaging_group_id ? await getMessagingGroup(session.messaging_group_id) : undefined;
  const destination =
    origin?.channel_type === trigger.channelType && origin.platform_id === trigger.platformId
      ? origin
      : await getMessagingGroupByPlatform(trigger.channelType, trigger.platformId);
  await adapter.deliver(
    trigger.channelType,
    trigger.platformId,
    trigger.threadId,
    'chat',
    JSON.stringify({ text }),
    undefined,
    destination?.instance,
  );
}

async function setModel(content: Record<string, unknown>, session: Session) {
  const trigger = await triggeringAdmin(content, session);
  if (!trigger) {
    log.warn('set_model denied: triggering message is not from a group admin', { sessionId: session.id });
    return;
  }
  const engine = typeof content.engine === 'string' ? content.engine.toLowerCase() : '';
  const target = modelForEngine(engine);
  const config = await getContainerConfig(session.agent_group_id);
  if (!target || !config) return reply(session, trigger, "I don't know that model.");
  const effort = typeof content.effort === 'string' ? content.effort.toLowerCase() : (config.effort ?? 'medium');
  if (!EFFORTS.has(effort)) return reply(session, trigger, "I don't know that effort.");

  const providerChanged = (config.provider ?? 'claude').toLowerCase() !== target.provider;
  await updateContainerConfigScalars(session.agent_group_id, {
    provider: target.provider === 'claude' ? null : target.provider,
    model: target.model,
    effort,
  });
  const warning = providerChanged ? 'current thread restarts, memory carries over; ' : '';
  await reply(session, trigger, `switching to ${engine}, ${effort} — ${warning}back in a minute`);
  await restartAgentGroupContainers(
    session.agent_group_id,
    `switching to ${engine}`,
    'Model switch complete. Do not reply; wait for the next human message.',
  );
}

async function currentModel(content: Record<string, unknown>, session: Session) {
  const trigger = await triggeringAdmin(content, session);
  if (!trigger) {
    log.warn('current_model denied: triggering message is not from a group admin', { sessionId: session.id });
    return;
  }
  const config = await getContainerConfig(session.agent_group_id);
  if (!config) return;
  const engine = Object.entries(MODEL_ENGINES).find(([, target]) => target.model === config.model)?.[0];
  await reply(
    session,
    trigger,
    `I am on ${engine ?? config.model ?? config.provider ?? 'claude'}, ${config.effort ?? 'medium'}`,
  );
}

registerDeliveryAction('set_model', setModel, unguarded('authorizes the triggering human against group admin roles'));
registerDeliveryAction(
  'current_model',
  currentModel,
  unguarded('authorizes the triggering human against group admin roles'),
);
