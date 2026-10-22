/**
 * Standing approvals: the approver's own words, recorded by the host, that let
 * approval-class plans apply without a card. Only a message the approver sent
 * in Orfie's chat within the last hour, used once, can grant or narrow one;
 * the grants live in the runtime config so they survive restarts.
 */
import fs from 'node:fs';

import type { InboundEvent } from '../../channels/adapter.js';
import { getMessagingGroup } from '../../db/messaging-groups.js';
import { registerDeliveryAction } from '../../delivery.js';
import { unguarded } from '../../guard/index.js';
import { registerMessageInterceptor } from '../../router.js';
import type { Session } from '../../types.js';
import { notifyAgent } from '../approvals/index.js';
import type { GrantEntry, StandingGrant } from './policy.js';

const HOUR = 60 * 60_000;

export function readGrants(configFile: string): StandingGrant[] {
  return (
    (JSON.parse(fs.readFileSync(configFile, 'utf8')) as { standingApprovals?: StandingGrant[] }).standingApprovals ?? []
  );
}

function writeGrants(configFile: string, grants: StandingGrant[]): void {
  const current = JSON.parse(fs.readFileSync(configFile, 'utf8')) as Record<string, unknown>;
  fs.writeFileSync(`${configFile}.tmp`, JSON.stringify({ ...current, standingApprovals: grants }, null, 2), {
    mode: 0o600,
  });
  fs.renameSync(`${configFile}.tmp`, configFile);
}

function entries(value: unknown): GrantEntry[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > 32)
    throw new Error('scope must be "all" or 1 to 32 entries');
  return value.map((entry) => {
    const { op, namespace, target, ...rest } = (entry ?? {}) as Record<string, unknown>;
    const fields = { op, namespace, target };
    if (Object.keys(rest).length || Object.values(fields).some((v) => v !== undefined && typeof v !== 'string'))
      throw new Error('a scope entry has only op, namespace and target strings');
    return Object.fromEntries(Object.entries(fields).filter(([, v]) => v !== undefined)) as GrantEntry;
  });
}

export function registerStandingApprovals(options: { approverUserId: string; configFile: string }): void {
  const seen = new Map<string, { channelType: string; platformId: string; text: string; at: number }>();
  registerMessageInterceptor(async (event: InboundEvent) => {
    let content: Record<string, unknown>;
    try {
      content = JSON.parse(event.message.content) as Record<string, unknown>;
      // eslint-disable-next-line no-catch-all/no-catch-all -- content that is not JSON is not the approver speaking
    } catch {
      return false;
    }
    if (content.senderId !== options.approverUserId) return false;
    const now = Date.now();
    for (const [id, m] of seen) if (now - m.at > HOUR) seen.delete(id);
    seen.set(event.message.id, {
      channelType: event.channelType,
      platformId: event.platformId,
      text: String(content.text ?? '').slice(0, 300),
      at: now,
    });
    if (!content.pendingApprovals)
      event.message.content = JSON.stringify({
        ...content,
        pendingApprovals: `approverMessageId: ${event.message.id}`,
      });
    return false;
  });

  /** The approver's message behind a grant change; the caller consumes it once the change is made. */
  const approverSaid = async (session: Session, id: unknown) => {
    const message = typeof id === 'string' ? seen.get(id) : undefined;
    const chat = session.messaging_group_id ? await getMessagingGroup(session.messaging_group_id) : undefined;
    if (!message || Date.now() - message.at > HOUR)
      throw new Error(`${String(id)} is not a recent message from the approver`);
    if (chat?.channel_type !== message.channelType || chat.platform_id !== message.platformId)
      throw new Error(`${String(id)} was not sent in this conversation`);
    return { ...message, consume: () => seen.delete(id as string) };
  };
  const action = (name: string, change: (content: Record<string, unknown>, said: { text: string }) => string) =>
    registerDeliveryAction(
      name,
      async (content, session) => {
        try {
          const said = await approverSaid(session, content.approverMessageId);
          const done = change(content, said);
          said.consume();
          await notifyAgent(session, done);
          // eslint-disable-next-line no-catch-all/no-catch-all -- refusals go back to the agent
        } catch (error) {
          await notifyAgent(session, `${name} refused: ${error instanceof Error ? error.message : String(error)}`);
        }
      },
      unguarded('it is the approver’s own message, checked like resolve_approval and used once'),
    );

  action('record_standing_approval', (content, said) => {
    const grant: StandingGrant = {
      scope: content.scope === 'all' ? 'all' : entries(content.scope),
      ...(content.except === undefined ? {} : { except: entries(content.except) }),
      grantedBy: options.approverUserId,
      grantedAt: new Date().toISOString(),
      note: said.text,
    };
    writeGrants(options.configFile, [...readGrants(options.configFile), grant]);
    return `standing yes recorded: ${JSON.stringify({ scope: grant.scope, except: grant.except ?? [] })}`;
  });
  action('revoke_standing_approval', (content) => {
    if (content.scope === 'all') {
      writeGrants(options.configFile, []);
      return 'every standing yes revoked; approval-class plans ask again';
    }
    const narrowed = entries(content.scope);
    writeGrants(
      options.configFile,
      readGrants(options.configFile).map((g) => ({ ...g, except: [...(g.except ?? []), ...narrowed] })),
    );
    return `standing yes no longer covers ${JSON.stringify(narrowed)}`;
  });
}
