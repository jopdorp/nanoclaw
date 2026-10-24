/**
 * Local-model (`ollama` provider) groups. Their OneCLI identity holds no
 * secrets, they create copies of themselves without an approval card, and each
 * copy gets its own encrypted Matrix room with the parent's admins and the
 * parent's settings, where the bot goes by the persona's name. Messages in
 * those rooms disappear after the persona's lifetime. Orfie can list the
 * personas and bring a room back, nothing more.
 * create-agent.ts gives a copy its parent's provider and model and no CLI;
 * container-runner.ts keeps their sessions off the gateway.
 */
import { execFile } from 'child_process';
import { randomUUID } from 'crypto';
import fs from 'fs';
import { promisify } from 'util';

import { lookup } from '../cli/registry.js';
import '../cli/resources/wirings.js';
import { getAgentGroup, getAllAgentGroups } from '../db/agent-groups.js';
import { getContainerConfig } from '../db/container-configs.js';
import {
  createMessagingGroup,
  deleteMessagingGroupAgent,
  getMessagingGroupAgentByPair,
  getMessagingGroupsByAgentGroup,
} from '../db/messaging-groups.js';
import { registerDeliveryAction } from '../delivery.js';
import { onOneCliAgentEnsured } from '../gateway-providers/onecli.js';
import { unguarded } from '../guard/index.js';
import { log } from '../log.js';
import { personaSettings, readSettings, SETTINGS_FILE } from '../local-persona-settings.js';
import type { AgentGroup, Session } from '../types.js';
import { getDestinations } from './agent-to-agent/db/agent-destinations.js';
import { trustCreateAgent } from './agent-to-agent/guard.js';
import { notifyAgent } from './approvals/index.js';
import { getAdminsOfAgentGroup, grantRole } from './permissions/db/user-roles.js';

const exec = promisify(execFile);
const REDACTABLE = new Set(['m.room.message', 'm.room.encrypted', 'm.reaction', 'm.sticker']);

const isLocal = async (agentGroupId: string) => (await getContainerConfig(agentGroupId))?.provider === 'ollama';

trustCreateAgent(isLocal);

onOneCliAgentEnsured(async (groupId) => {
  if (!(await isLocal(groupId))) return;
  const { data } = JSON.parse((await exec('onecli', ['agents', 'list'])).stdout) as {
    data: { id: string; identifier: string }[];
  };
  const id = data.find((a) => a.identifier === groupId)?.id;
  if (!id) return;
  await exec('onecli', ['agents', 'set-secret-mode', '--id', id, '--mode', 'selective']);
  // The CLI refuses an empty list, the API takes one.
  const res = await fetch(`${process.env.ONECLI_URL}/api/agents/${id}/secrets`, {
    method: 'PUT',
    headers: { authorization: `Bearer ${process.env.ONECLI_API_KEY}`, 'content-type': 'application/json' },
    body: JSON.stringify({ secretIds: [] }),
  });
  if (!res.ok) throw new Error(`OneCLI refused to clear the secrets of ${groupId}: ${res.status}`);
});

async function matrix(route: string, method = 'GET', body?: unknown): Promise<any> {
  const res = await fetch(`${process.env.MATRIX_BASE_URL?.replace(/\/$/, '')}/_matrix/client/v3${route}`, {
    method,
    headers: { authorization: `Bearer ${process.env.MATRIX_ACCESS_TOKEN}`, 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`Matrix ${method} ${route.split('?')[0]}: ${res.status} ${await res.text()}`);
  return res.json();
}

const roomOf = (platformId: string) => decodeURIComponent(platformId.slice('matrix:'.length));
const matrixUsers = async (agentGroupId: string) =>
  (await getAdminsOfAgentGroup(agentGroupId))
    .filter((a) => a.user_id.startsWith('matrix:'))
    .map((a) => a.user_id.slice('matrix:'.length));

export async function openLocalRoom(parentId: string, child: AgentGroup): Promise<void> {
  const now = new Date().toISOString();
  for (const admin of await getAdminsOfAgentGroup(parentId))
    await grantRole({ ...admin, agent_group_id: child.id, granted_at: now });
  const settings = readSettings();
  settings[child.id] = personaSettings(parentId);
  fs.writeFileSync(SETTINGS_FILE, JSON.stringify(settings, null, 2));
  await createRoom(child);
}

async function createRoom(group: AgentGroup): Promise<void> {
  const { room_id } = await matrix('/createRoom', 'POST', {
    name: group.name,
    room_version: '10',
    preset: 'trusted_private_chat',
    initial_state: [
      { type: 'nanoclaw.chat', state_key: '', content: {} },
      { type: 'm.room.encryption', state_key: '', content: { algorithm: 'm.megolm.v1.aes-sha2' } },
    ],
    invite: await matrixUsers(group.id),
  });
  await nameBot(room_id, group.name);
  const id = randomUUID();
  await createMessagingGroup({
    id,
    channel_type: 'matrix',
    platform_id: `matrix:${encodeURIComponent(room_id)}`,
    name: group.name,
    is_group: 0,
    unknown_sender_policy: 'strict',
    created_at: new Date().toISOString(),
  });
  await lookup('wirings-create')!.handler(
    {
      messaging_group_id: id,
      agent_group_id: group.id,
      engage_mode: 'pattern',
      engage_pattern: '.',
      sender_scope: 'known',
    },
    { caller: 'host' },
  );
}

async function localRooms(agentGroupId: string): Promise<string[]> {
  return (await getMessagingGroupsByAgentGroup(agentGroupId))
    .filter((mg) => mg.channel_type === 'matrix')
    .map((mg) => roomOf(mg.platform_id));
}

/** Redacts every message older than the persona's lifetime; pages back until it meets one redacted earlier. */
async function redactExpired(room: string, lifetimeMinutes: number): Promise<void> {
  const cutoff = Date.now() - lifetimeMinutes * 60_000;
  const encoded = encodeURIComponent(room);
  for (let from = ''; ; ) {
    const page = await matrix(`/rooms/${encoded}/messages?dir=b&limit=100${from && `&from=${from}`}`);
    let reachedRedacted = false;
    for (const event of page.chunk as { event_id: string; type: string; origin_server_ts: number; content: object }[]) {
      if (event.origin_server_ts > cutoff || !REDACTABLE.has(event.type)) continue;
      if (Object.keys(event.content).length === 0) reachedRedacted = true;
      else await matrix(`/rooms/${encoded}/redact/${encodeURIComponent(event.event_id)}/${randomUUID()}`, 'PUT', {});
    }
    if (reachedRedacted || !page.end || page.chunk.length === 0) return;
    from = page.end;
  }
}

/** In a persona's room the bot goes by the persona's name, not its global one. */
async function nameBot(room: string, name: string): Promise<void> {
  const route = `/rooms/${encodeURIComponent(room)}/state/m.room.member/${encodeURIComponent(process.env.MATRIX_USER_ID!)}`;
  const member = await matrix(route);
  if (member.displayname !== name) await matrix(route, 'PUT', { ...member, displayname: name });
}

async function sweep(): Promise<void> {
  for (const group of await getAllAgentGroups()) {
    if (!(await isLocal(group.id))) continue;
    for (const room of await localRooms(group.id))
      await Promise.all([
        nameBot(room, group.name),
        redactExpired(room, personaSettings(group.id).lifetimeMinutes),
      ]).catch((err) => log.warn('Local persona room upkeep failed', { room, err }));
  }
}
if (process.env.MATRIX_ACCESS_TOKEN) setInterval(() => void sweep(), 60_000).unref();

const isOrfie = async (session: Session) =>
  (await getAgentGroup(session.agent_group_id))?.folder === 'kubernetes-remediator';
const localPersonas = async () => {
  const all = await getAllAgentGroups();
  const local = [];
  for (const group of all) if (await isLocal(group.id)) local.push(group);
  return local;
};

registerDeliveryAction(
  'list_personas',
  async (_content, session) => {
    if (!(await isOrfie(session))) return;
    const lines = [];
    for (const group of await localPersonas()) {
      const parent = (await getDestinations(group.id)).find(
        (d) => d.target_type === 'agent' && d.local_name === 'parent',
      );
      const maker = parent && (await getAgentGroup(parent.target_id))?.name;
      lines.push(maker ? `${group.name} (made by ${maker})` : group.name);
    }
    await notifyAgent(session, lines.length ? lines.join('\n') : 'There are no local personas.');
  },
  unguarded('names only, and only for Orfie'),
);

registerDeliveryAction(
  'summon_persona',
  async (content, session) => {
    if (!(await isOrfie(session))) return;
    const group = (await localPersonas()).find((g) => g.name.toLowerCase() === String(content.name).toLowerCase());
    if (!group) return notifyAgent(session, `summon_persona: no local persona called "${String(content.name)}".`);
    const [room] = await localRooms(group.id);
    try {
      for (const user of await matrixUsers(group.id)) {
        const encoded = encodeURIComponent(room);
        const member = await matrix(`/rooms/${encoded}/state/m.room.member/${encodeURIComponent(user)}`).catch(
          () => null,
        );
        if (member?.membership === 'ban') throw new Error('banned');
        if (member?.membership !== 'join' && member?.membership !== 'invite')
          await matrix(`/rooms/${encoded}/invite`, 'POST', { user_id: user });
      }
      await notifyAgent(session, `Invited Jegor back to ${group.name}.`);
    } catch {
      // The room is gone or he is banned there, so the persona moves to a fresh room.
      for (const mg of await getMessagingGroupsByAgentGroup(group.id)) {
        const wiring = await getMessagingGroupAgentByPair(mg.id, group.id);
        if (mg.channel_type === 'matrix' && wiring) await deleteMessagingGroupAgent(wiring.id);
      }
      await createRoom(group);
      await notifyAgent(session, `${group.name} has a fresh room, Jegor is invited.`);
    }
  },
  unguarded("only Orfie, and it only re-invites the persona's own admins"),
);
