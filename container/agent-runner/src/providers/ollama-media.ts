/**
 * Renders an image, video or song on the LAN ComfyUI box, for the ollama provider. The quick SD 1.5 workflow fits beside the
 * LLM; every other kind takes the box's one GPU, so the LLM is unloaded first and
 * ComfyUI frees it again afterwards. The API workflows live in ComfyUI's user data
 * as nanoclaw/<kind>.json, with %PROMPT% (and %LYRICS% for music) where the text goes.
 */
import fs from 'fs';
import path from 'path';

const host = process.env.LOCAL_AI_HOST;
const comfy = `http://${host}:8188`;
const ollama = `http://${host}:11434`;

async function json(url: string, body?: unknown): Promise<any> {
  const res = await fetch(url, body === undefined ? {} : { method: 'POST', body: JSON.stringify(body) });
  if (!res.ok) throw new Error(`${url}: ${res.status} ${await res.text()}`);
  return res.json();
}

export async function render(kind: string, prompt: string, lyrics = ''): Promise<string> {
  const template = await fetch(`${comfy}/api/userdata/nanoclaw%2F${kind}.json`);
  if (!template.ok) throw new Error(`no ${kind} workflow on the box`);
  const text = (value: string) => JSON.stringify(value).slice(1, -1);
  const graph = JSON.parse(
    (await template.text()).replaceAll('%PROMPT%', text(prompt)).replaceAll('%LYRICS%', text(lyrics)),
  );
  for (const node of Object.values<any>(graph))
    for (const key of ['seed', 'noise_seed'])
      if (typeof node.inputs?.[key] === 'number') node.inputs[key] = Math.floor(Math.random() * 2 ** 32);

  if (kind === 'quick') return run(graph);
  for (const m of (await json(`${ollama}/api/ps`)).models ?? [])
    await json(`${ollama}/api/generate`, { model: m.name, keep_alive: 0 });
  try {
    return await run(graph);
  } finally {
    await json(`${comfy}/free`, { unload_models: true, free_memory: true }).catch(() => {});
  }
}

async function run(graph: unknown): Promise<string> {
  const { prompt_id } = await json(`${comfy}/prompt`, { prompt: graph });
  for (const deadline = Date.now() + 540_000; Date.now() < deadline; await new Promise((r) => setTimeout(r, 3000))) {
    const entry = (await json(`${comfy}/history/${prompt_id}`))[prompt_id];
    if (entry?.status?.status_str === 'error')
      throw new Error(`ComfyUI failed: ${JSON.stringify(entry.status.messages).slice(-500)}`);
    const file = Object.values<any>(entry?.outputs ?? {})
      .flatMap((o) => Object.values<any>(o).flat())
      .find((f) => f?.filename);
    if (!file) continue;
    const query = new URLSearchParams({
      filename: file.filename,
      subfolder: file.subfolder ?? '',
      type: file.type ?? 'output',
    });
    const res = await fetch(`${comfy}/view?${query}`);
    const out = path.join('/workspace/agent/media', file.filename);
    fs.mkdirSync(path.dirname(out), { recursive: true });
    fs.writeFileSync(out, Buffer.from(await res.arrayBuffer()));
    return out;
  }
  throw new Error('ComfyUI took longer than 9 minutes');
}
