/**
 * Ollama provider: a small chat loop against the LAN Ollama box (LOCAL_AI_HOST)
 * for small local models that drown in a full agent harness. The prompt is a
 * line of tool rules, the group's standing persona and the destination map; the
 * tools are media generation and creating/deleting its own copies, and a text
 * persona (LOCAL_AI_TOOLS=text) only gets quick pictures from the CPU instance.
 * /image, /video and /music skip the model. History lives in the session dir; past
 * three quarters of the model's num_ctx the oldest turns fold into a rolling
 * summary.
 */
import fs from 'fs';
import path from 'path';

import { writeMessageOut } from '../db/messages-out.js';
import { createAgent, deleteAgent } from '../mcp-tools/agents.js';
import { sendFile } from '../mcp-tools/core.js';
import { MEMORY_FILE_BUDGET_CHARS, renderMemorySection } from '../memory/context.js';
import { Busy, hold, render } from './ollama-media.js';
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
const text = process.env.LOCAL_AI_TOOLS === 'text';
const thinks = process.env.LOCAL_AI_THINK === '1';
// In a live call the voice worker holds the call mode, and a 9B there only gets the context the call mode leaves it.
const gpu = { nine: false, call: false };
const CALL_CTX = 16384;
const chatMode = () => (gpu.call ? undefined : gpu.nine ? 'chat-9b' : 'chat-4b');
const media = (kind: (a: Args) => string) => async (a: Args) => {
  const k = kind(a);
  // SD 1.5 fits beside the 4B but not the 9B.
  const cpu = text || (k === 'quick' && gpu.nine);
  const file = await hold(cpu ? undefined : k === 'quick' ? chatMode() : 'media', () =>
    render(k, String(a.prompt), a.lyrics ? String(a.lyrics) : '', cpu),
  );
  try {
    return await sendFile.handler({ to: a.to, path: file });
  } finally {
    fs.rmSync(file, { force: true });
  }
};
const persona = [
  tool('create_persona', 'Create a new persona with its own chat room.', { name: str, instructions: str }, (a) =>
    createAgent.handler(a),
  ),
  tool('delete_persona', 'Delete a persona you created.', { name: str }, (a) => deleteAgent.handler(a)),
  tool('read_memory', 'Read a file of your memory, e.g. index.md.', { file: str }, async (a) =>
    read(memoryPath(a.file), '(no such file)'),
  ),
  tool(
    'write_memory',
    'Replace a file of your memory. Only for something worth keeping across conversations: a fact about him, a wish, a decision.',
    { file: str, text: str },
    async (a) => {
      const text = String(a.text ?? '');
      if (text.length > MEMORY_FILE_BUDGET_CHARS) return `Error: keep it under ${MEMORY_FILE_BUDGET_CHARS} characters.`;
      fs.mkdirSync(path.dirname(memoryPath(a.file)), { recursive: true });
      fs.writeFileSync(memoryPath(a.file), text);
      return 'Saved.';
    },
  ),
  tool('read_character', 'Show your own character prompt.', {}, async () => read(PERSONA_FILE, '(empty)')),
  tool(
    'update_character',
    'Replace your own character prompt with the full new text; saying you changed is not enough, only this call changes you.',
    { prompt: str },
    async (a) => {
      const prompt = String(a.prompt ?? '').trim();
      if (prompt.length > MAX_CHARACTER_CHARS) return `Error: keep it under ${MAX_CHARACTER_CHARS} characters.`;
      // The group folder is the only one mounted here, so this can only ever be its own prompt.
      fs.writeFileSync(PERSONA_FILE, `${prompt}\n`);
      return 'Updated.';
    },
  ),
  // Another persona's folder is not mounted here, so the host does it after checking that this one made it.
  ...(['read_persona', 'update_persona'] as const).map((action) =>
    tool(
      action,
      action === 'read_persona'
        ? 'Show the character prompt of a persona you made.'
        : 'Replace the character prompt of a persona you made; it applies from its next reply.',
      action === 'read_persona' ? { name: str } : { name: str, prompt: str },
      async (a) => {
        const id = `${action}-${Date.now()}`;
        await writeMessageOut({
          id,
          kind: 'system',
          content: JSON.stringify({ action, name: a.name, prompt: a.prompt }),
        });
        return 'Asked; the answer comes as a message.';
      },
    ),
  ),
];
const TOOLS = text
  ? [
      tool(
        'generate_image',
        'Make a picture and send it to the chat. Only when asked for a picture.',
        { prompt: str },
        media(() => 'quick'),
      ),
      ...persona,
    ]
  : [
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
      ...persona,
    ];
const SLASH: Record<string, string> = text
  ? { '/image': 'quick' }
  : { '/image hq': 'image', '/image': 'quick', '/video': 'video', '/music': 'music' };
const RULES =
  'Reply in plain text. Use a tool only when asked for what it does: a picture, a video, a song, a new persona or a copy of you, deleting one, showing or changing your own character or that of a persona you made, or remembering something worth keeping. Otherwise just answer. When he asks you to change your character or personality, call update_character in that same reply.';
const VOICE =
  'This is a live voice call: answer in one to three short spoken sentences without lists, markup or emoji, and start with [tone: a few words on how to say it].';
// The formatter names a voice message's file in the message tag, where his own text cannot put one.
async function transcribeVoice(prompt: string): Promise<string> {
  for (const [tag, file] of prompt.matchAll(/<message\b[^>]*\baudio="([^"]+)"[^>]*>/g)) {
    if (!file.startsWith('/workspace/inbox/') || path.resolve(file) !== file) continue;
    const text = await Promise.resolve()
      .then(() =>
        fetch(`http://${process.env.LOCAL_AI_HOST}:8190/transcribe`, {
          method: 'POST',
          body: fs.readFileSync(file),
          signal: AbortSignal.timeout(60_000),
        }),
      )
      .then(async (res) => (res.ok ? String(((await res.json()) as { text?: string }).text ?? '').trim() : ''))
      .catch(() => '');
    prompt = prompt.replace(
      tag,
      `${tag}${text ? `[voice message] ${text.replace(/[<>]/g, '')}` : '[voice message, could not transcribe]'}\n`,
    );
  }
  return prompt;
}
const STATE_FILE = '/workspace/ollama-state.json';
const MEMORY_DIR = '/workspace/agent/memory';
// Memory files only, never the persona prompt or anything else in the group folder.
const memoryPath = (file: unknown) => {
  // Small models write the path as `memory/index.md` as often as `index.md`.
  const full = path.resolve(MEMORY_DIR, String(file ?? 'index.md').replace(/^(\/workspace\/agent\/)?memory\//, ''));
  if (!full.startsWith(MEMORY_DIR + path.sep) || !full.endsWith('.md')) throw new Error('only .md files under memory/');
  return full;
};
const PERSONA_FILE = '/workspace/agent/instructions.prepend.md';
const MAX_CHARACTER_CHARS = 8000;
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
  characterChanged?: number;
  replyTo?: string;
}

const read = (file: string, fallback: string) => (fs.existsSync(file) ? fs.readFileSync(file, 'utf-8') : fallback);

export class OllamaProvider implements AgentProvider {
  readonly emitsMidTurnText = true;
  constructor(private readonly options: ProviderOptions) {
    gpu.nine = /9b/i.test(options.model ?? '');
  }

  registerMemorySessionHook(): void {}

  isSessionInvalid(): boolean {
    return false;
  }

  private chat(messages: Message[], tools = true): Promise<{ message: Message; prompt_eval_count?: number }> {
    return hold(chatMode(), () => this.post(messages, tools));
  }

  private async post(messages: Message[], tools: boolean): Promise<{ message: Message; prompt_eval_count?: number }> {
    const res = await fetch(`http://${process.env.LOCAL_AI_HOST}:11434/api/chat`, {
      method: 'POST',
      body: JSON.stringify({
        model: this.options.model,
        messages,
        tools: tools ? TOOLS.map((t) => t.spec) : undefined,
        stream: false,
        // The 9B calls its tools reliably only when it may think first (measured 2/10 without, 9/10 with).
        think: thinks,
        // Small models ramble; a chat reply stays a chat reply. Thinking spends from the same budget.
        options: { num_predict: thinks ? 1500 : 300, num_ctx: gpu.call && gpu.nine ? CALL_CTX : undefined },
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
    return Math.min(numCtx || 8192, gpu.call && gpu.nine ? CALL_CTX : Infinity) * 0.75;
  }

  private async *turn(state: State, system: () => string, prompt: string): AsyncGenerator<ProviderEvent> {
    prompt = await transcribeVoice(prompt);
    gpu.call = [...prompt.matchAll(/<message\b[^>]*>/g)].pop()?.[0].includes(' via="voice call"') ?? false;
    if (state.promptTokens > (await this.compactAt())) await this.compact(state);
    // Replies go to whoever wrote last and any markup is dropped, small models misname or leave tags unclosed.
    const writer = [...prompt.matchAll(/<message[^>]*\bfrom="([^"]+)"/g)].pop()?.[1];
    // Host notices (tool results) come from no destination; answer them in the room of whoever wrote before.
    if (writer && !writer.startsWith('unknown:')) state.replyTo = writer;
    const from = state.replyTo ?? writer;
    const wrap = (text: string) =>
      from ? `<message to="${from}">${text.replace(/<\/?message\b[^>]*>/g, '').trim()}</message>` : text;
    // A new character prompt loses to a long history unless the model is told once that it changed.
    const changed = fs.existsSync(PERSONA_FILE) ? fs.statSync(PERSONA_FILE).mtimeMs : 0;
    const note = state.characterChanged !== undefined && changed !== state.characterChanged;
    state.characterChanged = changed;
    state.messages.push({
      role: 'user',
      content: note
        ? `<system>Your character prompt was just updated; act on it from now on.</system>\n${prompt}`
        : prompt,
    });
    const said = [...prompt.matchAll(/<message[^>]*>([\s\S]*?)<\/message>/g)].pop()?.[1].trim() ?? '';
    const slash = Object.keys(SLASH).find((k) => said.startsWith(k + ' '));
    if (slash) {
      yield { type: 'text', text: wrap('making it…') };
      const out = await media(() => SLASH[slash])({ to: from, prompt: said.slice(slash.length).trim() }).catch(
        (e: Error) => (e instanceof Busy ? Promise.reject(e) : `Error: ${e.message}`),
      );
      state.messages.push({ role: 'assistant', content: JSON.stringify(out) });
      fs.writeFileSync(STATE_FILE, JSON.stringify(state));
      yield { type: 'result', text: null };
      return;
    }
    for (let step = 0; step < 8; step++) {
      const memory = state.summary ? `\n\n## Memory of earlier conversation\n\n${state.summary}` : '';
      const { message, prompt_eval_count } = await this.chat([
        { role: 'system', content: system() + memory + (gpu.call ? `\n\n${VOICE}` : '') },
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
      let done = false;
      for (const { function: call } of calls) {
        yield { type: 'activity' };
        const run = TOOLS.find((t) => t.spec.function.name === call.name)?.run;
        const out = run
          ? await run({ ...call.arguments, to: from }).catch((e: Error) => `Error: ${e.message}`)
          : `Error: no tool ${call.name}`;
        console.error(`[ollama] tool ${call.name} ${JSON.stringify(out).includes('Error') ? 'error' : 'ok'}`);
        state.messages.push({ role: 'tool', tool_name: call.name, content: JSON.stringify(out) });
        const later = call.name.startsWith('generate_') || call.name.endsWith('_persona');
        done ||= later && !JSON.stringify(out).includes('Error');
      }
      // The file is the reply, and a persona change is answered by the host's notice; a reply now is a guess that
      // comes out as a second message (and after a picture, as a fake <image> tag the model then copies forever).
      if (done) {
        fs.writeFileSync(STATE_FILE, JSON.stringify(state));
        yield { type: 'result', text: null };
        return;
      }
    }
    yield { type: 'result', text: null };
  }

  // A busy box is told in one line instead of loading the model anyway.
  private async *guarded(state: State, system: () => string, prompt: string): AsyncGenerator<ProviderEvent> {
    try {
      yield* this.turn(state, system, prompt);
    } catch (e) {
      if (!(e instanceof Busy)) throw e;
      const text = state.replyTo ? `<message to="${state.replyTo}">${e.message}</message>` : e.message;
      yield { type: 'text', text };
      yield { type: 'result', text };
    }
  }

  query(input: QueryInput): AgentQuery {
    const pending: string[] = [];
    let wake: (() => void) | null = null;
    let ended = false;
    const state: State = JSON.parse(read(STATE_FILE, '{"summary":"","messages":[],"promptTokens":0}'));
    const system = () =>
      [RULES, read(PERSONA_FILE, ''), renderMemorySection(), input.systemContext?.instructions ?? '']
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
          yield* self.guarded(state, system, input.prompt);
          while (!ended || pending.length > 0) {
            if (pending.length > 0) yield* self.guarded(state, system, pending.shift()!);
            else await new Promise<void>((resolve) => (wake = resolve));
          }
        },
      },
    };
  }
}

registerProvider('ollama', (options) => new OllamaProvider(options));
