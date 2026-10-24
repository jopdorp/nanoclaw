/**
 * Renders an image, video or song on the LAN ComfyUI box for the ollama provider.
 * The GPU instance (:8188) has one 8 GB card, shared through the box's referee
 * (:8192, see hold): the quick SD 1.5 workflow fits beside the 4B, every other
 * kind holds the media mode, which unloads the LLM, and frees the GPU after.
 * The CPU-only instance (:8189) never touches the GPU. Workflows live in each instance's user data as nanoclaw/<kind>.json,
 * with %PROMPT% (and %LYRICS% for music) where the text goes. Nothing should
 * outlive the send: images come back over the websocket instead of being saved,
 * a saved video or song is deleted on the box by the host, the history entry is
 * deleted, and the caller deletes the local file.
 */
import { randomUUID } from 'crypto';
import fs from 'fs';
import path from 'path';

import { writeMessageOut } from '../db/messages-out.js';

const host = process.env.LOCAL_AI_HOST;
const referee = `http://${host}:8192`;
const GPU_TTL = 120;
// ComfyUI prefixes binary websocket frames with an event type and an image format.
const FRAME_HEADER_BYTES = 8;

async function json(url: string, body?: unknown): Promise<any> {
  const res = await fetch(url, body === undefined ? {} : { method: 'POST', body: JSON.stringify(body) });
  if (!res.ok) throw new Error(`${url}: ${res.status} ${await res.text()}`);
  return res.json();
}

export class Busy extends Error {}

const ask = (route: string, body: object) =>
  fetch(`${referee}/${route}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ owner: process.env.LOCAL_AI_OWNER, ...body }),
  });

/** Runs `work` while holding a GPU mode on the referee; no mode when a live call already holds one. */
export async function hold<T>(mode: string | undefined, work: () => Promise<T>): Promise<T> {
  if (!mode) return work();
  const res = await ask('acquire', { mode, ttl: GPU_TTL });
  if (res.status === 409 || res.status === 503) {
    const inCall = JSON.stringify((await res.json().catch(() => ({}))).current ?? '').includes('call-');
    throw new Busy(`${inCall ? 'busy in a call' : 'the box is busy'}, try again in a minute`);
  }
  if (!res.ok) throw new Error(`referee ${res.status}: ${await res.text()}`);
  const beat = setInterval(() => ask('acquire', { mode, ttl: GPU_TTL }).catch(() => {}), (GPU_TTL * 1000) / 3);
  try {
    return await work();
  } finally {
    clearInterval(beat);
    await ask('release', {}).catch(() => {});
  }
}

export async function render(kind: string, prompt: string, lyrics = '', cpu = false): Promise<string> {
  const comfy = `http://${host}:${cpu ? 8189 : 8188}`;
  const template = await fetch(`${comfy}/api/userdata/nanoclaw%2F${kind}.json`);
  if (!template.ok) throw new Error(`no ${kind} workflow on the box`);
  const text = (value: string) => JSON.stringify(value).slice(1, -1);
  const graph = JSON.parse(
    (await template.text()).replaceAll('%PROMPT%', text(prompt)).replaceAll('%LYRICS%', text(lyrics)),
  );
  for (const node of Object.values<any>(graph)) {
    for (const key of ['seed', 'noise_seed'])
      if (typeof node.inputs?.[key] === 'number') node.inputs[key] = Math.floor(Math.random() * 2 ** 32);
    // Our own prefix in the output root, the only names the host agrees to delete there.
    if (typeof node.inputs?.filename_prefix === 'string') node.inputs.filename_prefix = `nanoclaw-${kind}`;
    if (
      (kind === 'quick' || kind === 'image') &&
      (node.class_type === 'SaveImage' || node.class_type === 'PreviewImage')
    )
      Object.assign(node, { class_type: 'SaveImageWebsocket', inputs: { images: node.inputs.images } });
  }

  if (cpu || kind === 'quick') return run(comfy, graph, kind);
  try {
    return await run(comfy, graph, kind);
  } finally {
    await json(`${comfy}/free`, { unload_models: true, free_memory: true }).catch(() => {});
  }
}

async function run(comfy: string, graph: Record<string, any>, kind: string): Promise<string> {
  const clientId = randomUUID();
  const ws = new WebSocket(`${comfy.replace('http', 'ws')}/ws?clientId=${clientId}`);
  ws.binaryType = 'arraybuffer';
  await new Promise((resolve, reject) => {
    ws.onopen = resolve;
    ws.onerror = reject;
  });
  let executing: string | null = null;
  let image: Uint8Array | undefined;
  ws.onmessage = ({ data }) => {
    if (typeof data === 'string') {
      const message = JSON.parse(data);
      if (message.type === 'executing') executing = message.data.node;
    } else if (executing && graph[executing]?.class_type === 'SaveImageWebsocket')
      image = new Uint8Array(data as ArrayBuffer).slice(FRAME_HEADER_BYTES);
  };
  const { prompt_id } = await json(`${comfy}/prompt`, { prompt: graph, client_id: clientId });
  try {
    for (const deadline = Date.now() + 540_000; Date.now() < deadline; await new Promise((r) => setTimeout(r, 3000))) {
      const entry = (await json(`${comfy}/history/${prompt_id}`))[prompt_id];
      if (entry?.status?.status_str === 'error')
        throw new Error(`ComfyUI failed: ${JSON.stringify(entry.status.messages).slice(-500)}`);
      // History can say completed before a starved CPU box has sent the image frame; the final executing:null follows it.
      if (!entry?.status?.completed || executing) continue;
      fs.mkdirSync('/workspace/agent/media', { recursive: true });
      if (image) {
        const out = path.join('/workspace/agent/media', `${kind}-${prompt_id}.png`);
        fs.writeFileSync(out, image);
        return out;
      }
      const files = Object.values<any>(entry.outputs ?? {})
        .flatMap((o) => Object.values<any>(o).flat())
        .filter((f) => f?.filename);
      const file = files[0];
      if (!file) throw new Error('ComfyUI returned no file');
      const query = new URLSearchParams({ filename: file.filename, subfolder: file.subfolder ?? '', type: file.type });
      const out = path.join('/workspace/agent/media', file.filename);
      fs.writeFileSync(out, Buffer.from(await (await fetch(`${comfy}/view?${query}`)).arrayBuffer()));
      // Video and audio have no websocket output, so the host removes every saved file on the box.
      const saved = files.filter((f) => f.type === 'output' && !f.subfolder).map((f) => f.filename);
      if (saved.length < files.length) console.error(`[ollama-media] not deleting ${JSON.stringify(files)}`);
      if (saved.length > 0)
        await writeMessageOut({
          id: `local-media-delete-${prompt_id}`,
          kind: 'system',
          content: JSON.stringify({ action: 'local_media_delete', filenames: saved }),
        });
      return out;
    }
    throw new Error('ComfyUI took longer than 9 minutes');
  } finally {
    ws.close();
    await json(`${comfy}/history`, { delete: [prompt_id] }).catch(() => {});
  }
}
