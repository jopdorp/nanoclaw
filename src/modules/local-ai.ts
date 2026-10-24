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
import path from 'path';
import { promisify } from 'util';

import { lookup } from '../cli/registry.js';
import '../cli/resources/messaging-groups.js';
import '../cli/resources/wirings.js';
import { uploadListeners } from '../channels/matrix-crypto-store.js';
import { DATA_DIR, LOCAL_AI_HOST } from '../config.js';
import { getAgentGroup, getAllAgentGroups } from '../db/agent-groups.js';
import { getContainerConfig } from '../db/container-configs.js';
import { killContainer } from '../container-runner.js';
import {
  createMessagingGroup,
  getMessagingGroupAgents,
  getMessagingGroupByPlatform,
  getMessagingGroupsByAgentGroup,
} from '../db/messaging-groups.js';
import { registerDeliveryAction } from '../delivery.js';
import { onOneCliAgentEnsured } from '../gateway-providers/onecli.js';
import { unguarded } from '../guard/index.js';
import { log } from '../log.js';
import { deleteSession, getSessionsByAgentGroup } from '../db/sessions.js';
import { personaSettings, readSettings, writeSettings } from '../local-persona-settings.js';
import { destroySessionMailbox, sessionDir } from '../session-manager.js';
import type { AgentGroup, MessagingGroup, Session } from '../types.js';
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

class MatrixHttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

async function matrix(route: string, method = 'GET', body?: unknown, admin = false): Promise<any> {
  const api = admin ? '/_synapse/admin/v1' : '/_matrix/client/v3';
  // Media deletion needs a server admin; that token is used for nothing else.
  const token = admin ? process.env.MATRIX_MEDIA_ADMIN_TOKEN : process.env.MATRIX_ACCESS_TOKEN;
  for (;;) {
    const res = await fetch(`${process.env.MATRIX_BASE_URL?.replace(/\/$/, '')}${api}${route}`, {
      method,
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (res.status === 429) {
      const { retry_after_ms } = (await res.json()) as { retry_after_ms?: number };
      await new Promise((r) => setTimeout(r, retry_after_ms ?? 1000));
      continue;
    }
    if (!res.ok)
      throw new MatrixHttpError(
        res.status,
        `Matrix ${method} ${route.split('?')[0]}: ${res.status} ${await res.text()}`,
      );
    return res.json();
  }
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
  writeSettings({ ...readSettings(), [child.id]: personaSettings(parentId) });
  await createRoom(child);
}

async function createRoom(group: AgentGroup): Promise<void> {
  const { room_id } = await matrix('/createRoom', 'POST', {
    name: group.name,
    room_version: '10',
    preset: 'trusted_private_chat',
    initial_state: [
      { type: 'nanoclaw.chat', state_key: '', content: {} },
      ...(process.env.MATRIX_RECOVERY_KEY
        ? [{ type: 'm.room.encryption', state_key: '', content: { algorithm: 'm.megolm.v1.aes-sha2' } }]
        : []),
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

/** Only rooms the host made for the persona (marked nanoclaw.chat), so an admin-wired room is never wiped. */
async function localRooms(agentGroupId: string): Promise<{ mg: MessagingGroup; room: string }[]> {
  const rooms = [];
  for (const mg of await getMessagingGroupsByAgentGroup(agentGroupId)) {
    if (mg.channel_type !== 'matrix') continue;
    const room = roomOf(mg.platform_id);
    const marked = await matrix(`/rooms/${encodeURIComponent(room)}/state/nanoclaw.chat`).catch((err) => {
      if (err instanceof MatrixHttpError && err.status === 404) return null;
      throw err;
    });
    if (!marked) continue;
    rooms.push({ mg, room });
    const settings = readSettings();
    if (!settings[agentGroupId]?.rooms?.includes(room))
      writeSettings({
        ...settings,
        [agentGroupId]: { ...settings[agentGroupId], rooms: [...(settings[agentGroupId]?.rooms ?? []), room] },
      });
  }
  return rooms;
}

/** Redacts every message older than the cutoff, paging back to the start so a failed earlier sweep is caught up. */
async function redactExpired(room: string, lifetimeMinutes: number): Promise<void> {
  const cutoff = Date.now() - lifetimeMinutes * 60_000;
  const encoded = encodeURIComponent(room);
  for (let from = ''; ; ) {
    const page = await matrix(`/rooms/${encoded}/messages?dir=b&limit=100${from && `&from=${from}`}`);
    for (const event of page.chunk as { event_id: string; type: string; origin_server_ts: number; content: object }[])
      if (event.origin_server_ts <= cutoff && REDACTABLE.has(event.type) && Object.keys(event.content).length > 0)
        await matrix(`/rooms/${encoded}/redact/${encodeURIComponent(event.event_id)}/${randomUUID()}`, 'PUT', {});
    if (!page.end || page.chunk.length === 0) return;
    from = page.end;
  }
}

/** In a persona's room the bot goes by the persona's name, not its global one. */
async function nameBot(room: string, name: string): Promise<void> {
  const route = `/rooms/${encodeURIComponent(room)}/state/m.room.member/${encodeURIComponent(process.env.MATRIX_USER_ID!)}`;
  const member = await matrix(route);
  if (member.displayname !== name) await matrix(route, 'PUT', { ...member, displayname: name });
}

const MEDIA_FILE = path.join(DATA_DIR, 'local-media.json');
const readMedia = (): Record<string, { mxc: string; ts: number }[]> =>
  fs.existsSync(MEDIA_FILE) ? JSON.parse(fs.readFileSync(MEDIA_FILE, 'utf8')) : {};

// Each change is a synchronous read-modify-write, so concurrent deletes never write back an old snapshot.
function editMedia(room: string, edit: (list: { mxc: string; ts: number }[]) => { mxc: string; ts: number }[]): void {
  const media = readMedia();
  media[room] = edit(media[room] ?? []);
  fs.writeFileSync(MEDIA_FILE, JSON.stringify(media));
}

uploadListeners.push((room, mxc) => {
  void (async () => {
    const mg = await getMessagingGroupByPlatform('matrix', `matrix:${encodeURIComponent(room)}`);
    const wirings = mg ? await getMessagingGroupAgents(mg.id) : [];
    if ((await Promise.all(wirings.map((w) => isLocal(w.agent_group_id)))).some(Boolean))
      editMedia(room, (list) => [...list, { mxc, ts: Date.now() }]);
  })();
});

/** Deletes the bot's own uploads to the room from before the cutoff; his are remote, only their cache is ours. */
async function purgeMedia(room: string, cutoff: number): Promise<void> {
  for (const { mxc } of (readMedia()[room] ?? []).filter((m) => m.ts <= cutoff)) {
    await matrix(`/media/${mxc.slice('mxc://'.length)}`, 'DELETE', undefined, true).catch((err) => {
      if (!(err instanceof MatrixHttpError && err.status === 404)) throw err;
    });
    editMedia(room, (list) => list.filter((m) => m.mxc !== mxc));
  }
}

/** The persona starts blank: its sessions, with their history and the provider's state file, go. */
async function forgetConversations(agentGroupId: string): Promise<void> {
  for (const session of await getSessionsByAgentGroup(agentGroupId)) {
    killContainer(session.id, 'its room was wiped');
    await destroySessionMailbox(agentGroupId, session.id);
    fs.rmSync(sessionDir(agentGroupId, session.id), { recursive: true, force: true });
    await deleteSession(session.id);
  }
}

/** Every step runs even if another fails, so a broken admin token never keeps the messages or the history. */
async function wipe(room: string, agentGroupId: string): Promise<void> {
  const steps = [
    redactExpired(room, 0),
    purgeMedia(room, Date.now()),
    // Synapse deletes only local media by id, so his cached uploads go with the whole remote cache.
    matrix(`/purge_media_cache?before_ts=${Date.now()}`, 'POST', {}, true),
    forgetConversations(agentGroupId),
  ];
  for (const r of await Promise.allSettled(steps))
    if (r.status === 'rejected') log.warn('Local persona wipe step failed', { room, err: r.reason });
}

export async function wipeLocalPersona(agentGroupId: string): Promise<void> {
  if (await isLocal(agentGroupId))
    for (const { room } of await localRooms(agentGroupId)) await wipe(room, agentGroupId);
}

async function upkeep(room: string, group: AgentGroup): Promise<void> {
  await nameBot(room, group.name);
  const { chunk } = await matrix(`/rooms/${encodeURIComponent(room)}/members?not_membership=leave`);
  const present = (chunk as { state_key: string; content: { membership: string } }[]).some(
    (m) => m.state_key !== process.env.MATRIX_USER_ID && ['join', 'invite'].includes(m.content.membership),
  );
  // Once he has left (and no invite is pending), the whole room goes, not just the expired part.
  if (!present) return wipe(room, group.id);
  const lifetimeMinutes = personaSettings(group.id).lifetimeMinutes;
  await redactExpired(room, lifetimeMinutes);
  await purgeMedia(room, Date.now() - lifetimeMinutes * 60_000);
}

async function sweep(): Promise<void> {
  for (const group of await getAllAgentGroups()) {
    if (!(await isLocal(group.id))) continue;
    for (const { room } of await localRooms(group.id).catch(() => []))
      await upkeep(room, group).catch((err) => log.warn('Local persona room upkeep failed', { room, err }));
  }
}
let sweeping = false;
if (process.env.MATRIX_ACCESS_TOKEN)
  setInterval(() => {
    if (sweeping) return;
    sweeping = true;
    void sweep().finally(() => (sweeping = false));
  }, 60_000).unref();

const isOrfie = async (session: Session) =>
  (await getAgentGroup(session.agent_group_id))?.folder === 'kubernetes-remediator';
const localPersonas = async () => {
  const all = await getAllAgentGroups();
  const local = [];
  for (const group of all) if (await isLocal(group.id)) local.push(group);
  return local;
};

// ComfyUI has no delete API without --enable-assets, so a sent video or song is removed over Orfie's Batocera SSH.
registerDeliveryAction(
  'local_media_delete',
  async (content, session) => {
    if (!(await isLocal(session.agent_group_id))) return;
    const names = (content.filenames as unknown[]).map(String);
    const ours = names.filter((n) => /^nanoclaw-(quick|image|video|music)_[\w.-]+$/.test(n));
    if (ours.length < names.length) log.warn('local_media_delete skipped foreign names', { names });
    if (ours.length === 0) return;
    await exec('ssh', [
      ...['-i', '/run/nanoclaw/batocera/id_ed25519', '-o', 'BatchMode=yes', '-o', 'HostKeyAlias=batocera'],
      ...['-o', 'UserKnownHostsFile=/run/nanoclaw/batocera/known_hosts', `root@${LOCAL_AI_HOST}`],
      `cd /userdata/ai/comfyui/output && rm -f ${ours.join(' ')}`,
    ]);
  },
  unguarded("a local persona removes only ComfyUI outputs named with the provider's own prefix"),
);

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
    for (const mg of await getMessagingGroupsByAgentGroup(group.id)) {
      if (mg.channel_type !== 'matrix') continue;
      const encoded = encodeURIComponent(roomOf(mg.platform_id));
      try {
        await matrix(`/rooms/${encoded}/state/nanoclaw.chat`);
        for (const user of await matrixUsers(group.id)) {
          const member = await matrix(`/rooms/${encoded}/state/m.room.member/${encodeURIComponent(user)}`).catch(
            (err) => (err instanceof MatrixHttpError && err.status === 404 ? null : Promise.reject(err)),
          );
          if (member?.membership === 'ban') return notifyAgent(session, `${user} is banned from ${group.name}'s room.`);
          if (member?.membership !== 'join' && member?.membership !== 'invite')
            await matrix(`/rooms/${encoded}/invite`, 'POST', { user_id: user });
        }
        return notifyAgent(session, `Invited Jegor back to ${group.name}.`);
      } catch (err) {
        if (!(err instanceof MatrixHttpError) || (err.status !== 403 && err.status !== 404)) throw err;
        // 404 is a room the host did not make; 403 is a room the bot is no longer in, replaced only if it was ours.
        if (err.status === 404 || !personaSettings(group.id).rooms?.includes(roomOf(mg.platform_id))) continue;
        await lookup('messaging-groups-delete')!.handler({ id: mg.id }, { caller: 'host' });
      }
    }
    await createRoom(group);
    await notifyAgent(session, `${group.name} has a fresh room, Jegor is invited.`);
  },
  unguarded("only Orfie, and it only re-invites the persona's own admins"),
);
