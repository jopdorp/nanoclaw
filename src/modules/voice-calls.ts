/**
 * Voice calls with local personas and the main agent (MatrixRTC, audio only).
 * When an admin starts a call in the main agent's DM or a local persona room, the bot joins too: it asks the
 * MatrixRTC auth service for a LiveKit token and hands it to the voice worker on the Batocera
 * box, which does the listening and speaking over one authenticated WebSocket. What he says
 * goes into the persona's normal session as a message; its text reply to that turn comes back
 * as speech, anything else is posted as usual.
 */
import { createHash, randomUUID, timingSafeEqual } from 'crypto';
import type { IncomingMessage } from 'http';
import { WebSocketServer, type WebSocket } from 'ws';

import { matrixClientListeners } from '../channels/matrix.js';
import { getContainerConfig } from '../db/container-configs.js';
import { getMessagingGroupAgents, getMessagingGroupByPlatform } from '../db/messaging-groups.js';
import { setOutboundClaim } from '../delivery.js';
import { onHostShutdown, onHostStart } from '../host-lifecycle.js';
import { personaSettings, type PersonaSettings } from '../local-persona-settings.js';
import { log } from '../log.js';
import { routeInbound } from '../router.js';
import { isLocal, matrix } from './local-ai.js';
import { getAdminsOfAgentGroup } from './permissions/db/user-roles.js';
import { spokenReply } from './spoken-reply.js';

const MEMBER = 'org.matrix.msc3401.call.member';
const MAIN_AGENT = 'ag-4be55056-f0a3-4991-a83e-a347b75de07d';
// His account is on matrix.org, so his calls run on its LiveKit; the bot's OpenID token goes to no other service.
const MATRIX_ORG_FOCUS = 'https://livekit-jwt.call.matrix.org';

type FromWorker =
  | { type: 'heard'; callId: string; turnId: string; text: string; emotion?: string; final: boolean }
  | { type: 'bargein'; callId: string; turnId: string }
  | { type: 'ended'; callId: string; reason: string };

interface Call {
  id: string;
  room: string;
  platformId: string;
  caller: string;
  voice: NonNullable<PersonaSettings['voice']>;
  rtc?: any;
  onKey?: (key: Uint8Array, index: number, membership: unknown, participant: string) => void;
  onRtcError?: (err: unknown) => void;
  keys: { participant: string; index: number; key: string }[];
  encrypted: boolean;
  started: boolean;
  turn?: string;
}

// matrix-js-sdk is not a direct dependency, so its types are not importable here.
interface MatrixEvent {
  getType(): string;
  getRoomId(): string | undefined;
  getSender(): string | undefined;
  getContent(): Record<string, unknown>;
  getTs(): number;
}

const calls = new Map<string, Call>();
const callIn = (room: string) => [...calls.values()].find((c) => c.room === room);
let worker: WebSocket | null = null;
let client: any;

const send = (message: object) => worker?.send(JSON.stringify(message));
const turnMessageId = (call: Call, turnId: string) => `voice-${call.id}-${turnId}`;
/** Who else is in the room's call, oldest first: memberships with content that have not expired. */
function inCall(room: string): MatrixEvent[] {
  const events: MatrixEvent[] = client.getRoom(room)?.currentState.getStateEvents(MEMBER) ?? [];
  return events
    .filter((e) => e.getSender() !== client.getUserId() && e.getContent().application === 'm.call')
    .filter((e) => e.getTs() + Number(e.getContent().expires ?? Infinity) > Date.now())
    .sort((a, b) => a.getTs() - b.getTs());
}

/** The call runs on the oldest member's LiveKit; ours when it names none, and nothing outside the two we trust. */
function focusOf(member: MatrixEvent): { service: string; foci: unknown[] } | undefined {
  const foci = member.getContent().foci_preferred as { type?: string; livekit_service_url?: string }[];
  const ours = process.env.MATRIX_RTC_URL!;
  const first = Array.isArray(foci) ? foci.find((f) => f.type === 'livekit') : undefined;
  if (!first)
    return { service: ours, foci: [{ type: 'livekit', livekit_service_url: ours, livekit_alias: member.getRoomId() }] };
  const service = String(first.livekit_service_url ?? '').replace(/\/$/, '');
  return [ours, MATRIX_ORG_FOCUS].includes(service) ? { service, foci } : undefined;
}

/** Only his DM with the main agent, or a room whose every wired agent is a local persona he administers. */
async function targetOf(roomId: string, caller: string): Promise<{ agent: string; platformId: string } | undefined> {
  const room = client.getRoom(roomId);
  const direct =
    !room?.currentState.getStateEvents('nanoclaw.chat', '') &&
    ((client.getAccountData('m.direct')?.getContent()[caller] as string[] | undefined) ?? []).includes(roomId);
  const platformId = direct ? `matrix:${caller}` : `matrix:${encodeURIComponent(roomId)}`;
  const mg = await getMessagingGroupByPlatform('matrix', platformId);
  const wired = mg ? await getMessagingGroupAgents(mg.id) : [];
  if (
    !wired.length ||
    !(await Promise.all(wired.map(({ agent_group_id: id }) => getAdminsOfAgentGroup(id)))).every((admins) =>
      admins.some((a) => a.user_id === `matrix:${caller}`),
    )
  )
    return undefined;
  if (direct)
    return wired.length === 1 && wired[0].agent_group_id === MAIN_AGENT ? { agent: MAIN_AGENT, platformId } : undefined;
  return (await Promise.all(wired.map(({ agent_group_id: id }) => isLocal(id)))).every(Boolean)
    ? { agent: wired[0].agent_group_id, platformId }
    : undefined;
}

async function join(room: string, member: MatrixEvent): Promise<void> {
  const caller = member.getSender()!;
  const matrixRoom = client.getRoom(room);
  const target = await targetOf(room, caller);
  const focus = focusOf(member);
  if (!focus) return log.warn('Voice call skipped, unknown LiveKit service', { room });
  if (!matrixRoom || !target || !worker || callIn(room)) return;
  const call: Call = {
    id: randomUUID(),
    room,
    platformId: target.platformId,
    caller,
    voice: personaSettings(target.agent).voice ?? {},
    keys: [],
    encrypted: matrixRoom.hasEncryptionStateEvent(),
    started: false,
  };
  calls.set(call.id, call);
  try {
    const openid = await matrix(`/user/${encodeURIComponent(client.getUserId())}/openid/request_token`, 'POST', {});
    const res = await fetch(`${focus.service}/sfu/get`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ room, openid_token: openid, device_id: client.getDeviceId() }),
      redirect: 'error',
    });
    if (!res.ok) throw new Error(`MatrixRTC auth service: ${res.status}`);
    const { url, jwt } = (await res.json()) as { url: string; jwt: string };
    // The worker's LiveKit transport wants the room name, which the auth service only puts in the token.
    const livekitRoom = JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString()).video.room;
    call.rtc = client.matrixRTC.getRoomSession(matrixRoom);
    call.onKey = (key, index, _membership, participant) => {
      const item = { participant, index, key: Buffer.from(key).toString('base64') };
      call.keys.push(item);
      if (call.started) send({ type: 'keys', callId: call.id, ...item });
    };
    call.rtc.on('encryption_key_changed', call.onKey);
    call.onRtcError = (err) => {
      log.error('Voice call membership failed', { callId: call.id, err });
      void leave(call, true);
    };
    call.rtc.on('membership_manager_error', call.onRtcError);
    const userId = client.getUserId();
    const deviceId = client.getDeviceId();
    call.rtc.joinRTCSession({ userId, deviceId, memberId: `${userId}:${deviceId}` }, focus.foci, undefined, {
      callIntent: 'audio',
      manageMediaKeys: call.encrypted,
    });
    if (!calls.has(call.id)) throw new Error('hung up while joining');
    const mode = /9b/i.test((await getContainerConfig(target.agent))?.model ?? '') ? 'call-9b' : 'call-4b';
    send({
      type: 'start',
      callId: call.id,
      livekitUrl: url,
      jwt,
      room: livekitRoom,
      voice: call.voice,
      mode,
      e2ee: call.encrypted ? { keys: call.keys } : undefined,
    });
    call.started = true;
    log.info('Voice call joined', { callId: call.id, room });
  } catch (err) {
    log.error('Voice call join failed', { room, err });
    await leave(call, false);
  }
}

async function leave(call: Call, tellWorker: boolean): Promise<void> {
  calls.delete(call.id);
  if (tellWorker) send({ type: 'stop', callId: call.id });
  if (call.onKey) call.rtc?.off('encryption_key_changed', call.onKey);
  if (call.onRtcError) call.rtc?.off('membership_manager_error', call.onRtcError);
  await call.rtc
    ?.leaveRoomSession(10_000)
    .catch((err: unknown) => log.warn('Voice call leave failed', { callId: call.id, err }));
  log.info('Voice call left', { callId: call.id });
}

const endAll = (tellWorker: boolean) => Promise.all([...calls.values()].map((call) => leave(call, tellWorker)));

function check(room: string): void {
  const [oldest] = inCall(room);
  const call = callIn(room);
  if (oldest && !call) void join(room, oldest).catch((err) => log.error('Voice call join failed', { room, err }));
  if (!oldest && call) void leave(call, true);
}

function fromWorker(message: FromWorker): void {
  const call = calls.get(message.callId);
  if (!call) return;
  if (message.type === 'ended') void leave(call, false);
  if (message.type === 'bargein' && call.turn === message.turnId) call.turn = undefined;
  if (message.type !== 'heard' || !message.final || !String(message.text ?? '').trim()) return;
  if (call.turn) send({ type: 'cancel', callId: call.id, turnId: call.turn });
  call.turn = message.turnId;
  void routeInbound({
    channelType: 'matrix',
    instance: 'matrix',
    platformId: call.platformId,
    threadId: null,
    message: {
      id: turnMessageId(call, message.turnId),
      kind: 'chat-sdk',
      content: JSON.stringify({
        text: message.text,
        sender: client.getRoom(call.room)?.getMember(call.caller)?.name ?? call.caller,
        senderId: `matrix:${call.caller}`,
        voice: true,
        emotion: message.emotion,
      }),
      timestamp: new Date().toISOString(),
      isMention: true,
      isGroup: false,
    },
  }).catch((err) => log.error('Voice turn routing failed', { callId: call.id, err }));
}

matrixClientListeners.push((c) => {
  client = c;
  client.on('RoomState.events', (event: MatrixEvent) => {
    const room = event.getRoomId();
    if (event.getType() === MEMBER && room && event.getSender() !== client.getUserId() && worker) check(room);
  });
});

onHostStart(() => {
  const token = process.env.VOICE_WORKER_TOKEN;
  if (!token || !process.env.MATRIX_RTC_URL) return;
  const digest = (s: string) => createHash('sha256').update(s).digest();
  const wss = new WebSocketServer({
    port: 3001,
    maxPayload: 64 * 1024,
    verifyClient: ({ req }: { req: IncomingMessage }) =>
      timingSafeEqual(digest(req.headers.authorization ?? ''), digest(`Bearer ${token}`)),
  });
  wss.on('error', (err) => log.error('Voice worker server failed', { err }));
  wss.on('connection', (ws) => {
    worker?.terminate();
    worker = ws;
    let missed = 0;
    const heartbeat = setInterval(() => (++missed > 2 ? ws.terminate() : ws.ping()), 10_000);
    ws.on('pong', () => (missed = 0));
    ws.on('error', (err) => log.warn('Voice worker connection failed', { err }));
    ws.on('message', (data) => {
      try {
        fromWorker(JSON.parse(String(data)));
      } catch (err) {
        log.warn('Unreadable voice worker message', { err });
      }
    });
    ws.on('close', () => {
      clearInterval(heartbeat);
      if (worker !== ws) return;
      worker = null;
      void endAll(false);
    });
    // Calls the old worker had are gone with it; the ones still going are joined again with this one.
    void endAll(false).then(() => {
      for (const room of client?.getRooms() ?? []) check(room.roomId);
    });
  });
  onHostShutdown(async () => {
    await endAll(true);
    wss.close();
  });

  setOutboundClaim(({ channelType, platformId, inReplyTo }, content) => {
    const call = channelType === 'matrix' ? callIn(decodeURIComponent(platformId.slice('matrix:'.length))) : undefined;
    if (!call?.turn || !inReplyTo?.startsWith(`${turnMessageId(call, call.turn)}:`)) return false;
    if (typeof content.text !== 'string' || content.type || content.operation) return false;
    const { chunk, style } = spokenReply(content.text, call.voice.instruct);
    if (!chunk) return false;
    send({ type: 'say', callId: call.id, turnId: call.turn, chunk, style, final: true });
    return true;
  });
});
