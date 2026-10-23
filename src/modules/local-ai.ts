/**
 * Local-model (`ollama` provider) groups. Their OneCLI identity holds no
 * secrets, they create copies of themselves without an approval card, and each
 * copy gets its own Matrix room with the parent's admins. create-agent.ts gives
 * a copy its parent's provider and model and no CLI; container-runner.ts keeps
 * their sessions off the gateway.
 */
import { execFile } from 'child_process';
import { randomUUID } from 'crypto';
import { promisify } from 'util';

import { lookup } from '../cli/registry.js';
import '../cli/resources/wirings.js';
import { getContainerConfig } from '../db/container-configs.js';
import { createMessagingGroup } from '../db/messaging-groups.js';
import { onOneCliAgentEnsured } from '../gateway-providers/onecli.js';
import type { AgentGroup } from '../types.js';
import { trustCreateAgent } from './agent-to-agent/guard.js';
import { getAdminsOfAgentGroup, grantRole } from './permissions/db/user-roles.js';

const exec = promisify(execFile);

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

export async function openLocalRoom(parentId: string, child: AgentGroup): Promise<void> {
  const now = new Date().toISOString();
  const admins = await getAdminsOfAgentGroup(parentId);
  for (const admin of admins) await grantRole({ ...admin, agent_group_id: child.id, granted_at: now });
  const res = await fetch(`${process.env.MATRIX_BASE_URL?.replace(/\/$/, '')}/_matrix/client/v3/createRoom`, {
    method: 'POST',
    headers: { authorization: `Bearer ${process.env.MATRIX_ACCESS_TOKEN}`, 'content-type': 'application/json' },
    body: JSON.stringify({
      name: child.name,
      preset: 'trusted_private_chat',
      initial_state: [{ type: 'nanoclaw.chat', state_key: '', content: {} }],
      invite: admins.filter((a) => a.user_id.startsWith('matrix:')).map((a) => a.user_id.slice('matrix:'.length)),
    }),
  });
  if (!res.ok) throw new Error(`Matrix createRoom: ${res.status} ${await res.text()}`);
  const { room_id } = (await res.json()) as { room_id: string };
  const id = randomUUID();
  await createMessagingGroup({
    id,
    channel_type: 'matrix',
    platform_id: `matrix:${encodeURIComponent(room_id)}`,
    name: child.name,
    is_group: 0,
    unknown_sender_policy: 'strict',
    created_at: now,
  });
  await lookup('wirings-create')!.handler(
    {
      messaging_group_id: id,
      agent_group_id: child.id,
      engage_mode: 'pattern',
      engage_pattern: '.',
      sender_scope: 'known',
    },
    { caller: 'host' },
  );
}
