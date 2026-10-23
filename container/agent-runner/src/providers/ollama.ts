/**
 * Ollama provider: a small chat loop against the LAN Ollama box (LOCAL_AI_HOST)
 * for small local models that drown in a full agent harness. The prompt is a
 * line of tool rules, the group's standing persona and the destination map; the
 * tools are media generation and creating/deleting its own copies. /image,
 * /video and /music skip the model. History lives in the session dir; past
 * three quarters of the model's num_ctx the oldest turns fold into a rolling
 * summary.
 */
import fs from 'fs';

import { createAgent, deleteAgent } from '../mcp-tools/agents.js';
import { sendFile } from '../mcp-tools/core.js';
import { render } from './ollama-media.js';
import { registerProvider } from './provider-registry.js';
import type { AgentProvider, AgentQuery, ProviderEvent, ProviderOptions, QueryInput } from './types.js';

type Args = Record<string, unknown>;
const str = { type: 'string' };
const tool = (name: string, description: string, properties: Args, run: (args: Args) => Promise<unknown>) => ({
  spec: {
    type: 'function',
    function: {
      name,
      description,
      parameters: { type: 'object', properties, required: Object.keys(properties).slice(0, 1) },
    },
  },
  run,
});
const media = (kind: (a: Args) => string) => async (a: Args) =>
  sendFile.handler({ to: a.to, path: await render(kind(a), String(a.prompt), a.lyrics ? String(a.lyrics) : '') });
const TOOLS = [
  tool(
    'generate_image',
    'Make a picture and send it to the chat. Only when asked for a picture.',
    { prompt: str, hq: { type: 'boolean', description: 'only if he asks for high quality' } },
    media((a) => (a.hq === true ? 'image' : 'quick')),
  ),
  tool(
    'generate_video',
    'Make a short video and send it to the chat. Only when asked for a video.',
    { prompt: str },
    media(() => 'video'),
  ),
  tool(
    'generate_music',
    'Make a song and send it to the chat. Only when asked for music.',
    { prompt: str, lyrics: str },
    media(() => 'music'),
  ),
  tool('create_persona', 'Create a new persona with its own chat room.', { name: str, instructions: str }, (a) =>
    createAgent.handler(a),
  ),
  tool('delete_persona', 'Delete a persona you created.', { name: str }, (a) => deleteAgent.handler(a)),
];
const SLASH: Record<string, string> = { '/image hq': 'image', '/image': 'quick', '/video': 'video', '/music': 'music' };
const RULES =
  'Reply in plain text. Use a tool only when asked for what it makes: a picture, a video, a song, a new persona or a copy of you, or deleting one. Otherwise just answer.';
const STATE_FILE = '/workspace/ollama-state.json';
const PERSONA_FILE = '/workspace/agent/instructions.prepend.md';
const KEEP = 8;

interface Message {
  role: string;
  content: string;
  tool_calls?: { function: { name: string; arguments: Record<string, unknown> } }[];
  tool_name?: string;
}
interface State {
  summary: string;
  messages: Message[];
  promptTokens: number;
}

const read = (file: string, fallback: string) => (fs.existsSync(file) ? fs.readFileSync(file, 'utf-8') : fallback);

export class OllamaProvider implements AgentProvider {
  readonly emitsMidTurnText = true;
  constructor(private readonly options: ProviderOptions) {}

  registerMemorySessionHook(): void {}

  isSessionInvalid(): boolean {
    return false;
  }

  private async chat(messages: Message[], tools = true): Promise<{ message: Message; prompt_eval_count?: number }> {
    const res = await fetch(`http://${process.env.LOCAL_AI_HOST}:11434/api/chat`, {
      method: 'POST',
      body: JSON.stringify({
        model: this.options.model,
        messages,
        tools: tools ? TOOLS.map((t) => t.spec) : undefined,
        stream: false,
        think: false,
      }),
    });
    if (!res.ok) throw new Error(`Ollama ${res.status}: ${await res.text()}`);
    return res.json();
  }

  private async compact(state: State): Promise<void> {
    let cut = state.messages.length - KEEP;
    while (cut < state.messages.length && state.messages[cut].role !== 'user') cut++;
    const old = state.messages.splice(0, cut);
    const transcript = old.map((m) => `${m.role}: ${m.content}`).join('\n');
    const { message } = await this.chat(
      [
        {
          role: 'user',
          content: `Update this memory note with what is worth keeping from the conversation below: facts, wishes, open threads. Short.\n\nNote:\n${state.summary}\n\nConversation:\n${transcript}`,
        },
      ],
      false,
    );
    state.summary = message.content;
  }

  // Each persona's Ollama model carries its own num_ctx; compact at three quarters of it.
  private async compactAt(): Promise<number> {
    const res = await fetch(`http://${process.env.LOCAL_AI_HOST}:11434/api/show`, {
      method: 'POST',
      body: JSON.stringify({ model: this.options.model }),
    });
    const numCtx = Number(
      /num_ctx\s+(\d+)/.exec(((await res.json()) as { parameters?: string }).parameters ?? '')?.[1],
    );
    return (numCtx || 8192) * 0.75;
  }

  private async *turn(state: State, system: string, prompt: string): AsyncGenerator<ProviderEvent> {
    if (state.promptTokens > (await this.compactAt())) await this.compact(state);
    // Plain text is wrapped for whoever wrote last, so a reply never depends on the model's markup.
    const from = [...prompt.matchAll(/<message[^>]*\bfrom="([^"]+)"/g)].pop()?.[1];
    const wrap = (text: string) =>
      from && !text.includes('<message') ? `<message to="${from}">${text}</message>` : text;
    state.messages.push({ role: 'user', content: prompt });
    const said = [...prompt.matchAll(/<message[^>]*>([\s\S]*?)<\/message>/g)].pop()?.[1].trim() ?? '';
    const slash = Object.keys(SLASH).find((k) => said.startsWith(k + ' '));
    if (slash) {
      yield { type: 'text', text: wrap('making it…') };
      const out = await media(() => SLASH[slash])({ to: from, prompt: said.slice(slash.length).trim() }).catch(
        (e: Error) => `Error: ${e.message}`,
      );
      state.messages.push({ role: 'assistant', content: JSON.stringify(out) });
      fs.writeFileSync(STATE_FILE, JSON.stringify(state));
      yield { type: 'result', text: null };
      return;
    }
    for (let step = 0; step < 8; step++) {
      const memory = state.summary ? `\n\n## Memory of earlier conversation\n\n${state.summary}` : '';
      const { message, prompt_eval_count } = await this.chat([
        { role: 'system', content: system + memory },
        ...state.messages,
      ]);
      state.promptTokens = prompt_eval_count ?? state.promptTokens;
      state.messages.push({ role: 'assistant', content: message.content, tool_calls: message.tool_calls });
      fs.writeFileSync(STATE_FILE, JSON.stringify(state));
      const calls = message.tool_calls ?? [];
      if (calls.length === 0) {
        const text = wrap(message.content);
        yield { type: 'text', text };
        yield { type: 'result', text };
        return;
      }
      const making = calls.some((c) => c.function.name.startsWith('generate_'));
      if (message.content || making) yield { type: 'text', text: wrap(message.content || 'making it…') };
      for (const { function: call } of calls) {
        yield { type: 'activity' };
        const run = TOOLS.find((t) => t.spec.function.name === call.name)?.run;
        const out = run
          ? await run({ ...call.arguments, to: from }).catch((e: Error) => `Error: ${e.message}`)
          : `Error: no tool ${call.name}`;
        state.messages.push({ role: 'tool', tool_name: call.name, content: JSON.stringify(out) });
      }
    }
    yield { type: 'result', text: null };
  }

  query(input: QueryInput): AgentQuery {
    const pending: string[] = [];
    let wake: (() => void) | null = null;
    let ended = false;
    const state: State = JSON.parse(read(STATE_FILE, '{"summary":"","messages":[],"promptTokens":0}'));
    const system = [RULES, read(PERSONA_FILE, ''), input.systemContext?.instructions ?? '']
      .filter(Boolean)
      .join('\n\n');
    const self = this;

    return {
      push(message) {
        pending.push(message);
        wake?.();
      },
      end() {
        ended = true;
        wake?.();
      },
      abort() {
        ended = true;
        wake?.();
      },
      events: {
        async *[Symbol.asyncIterator]() {
          yield { type: 'init', continuation: 'ollama' };
          yield* self.turn(state, system, input.prompt);
          while (!ended || pending.length > 0) {
            if (pending.length > 0) yield* self.turn(state, system, pending.shift()!);
            else await new Promise<void>((resolve) => (wake = resolve));
          }
        },
      },
    };
  }
}

registerProvider('ollama', (options) => new OllamaProvider(options));
