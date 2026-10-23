import { writeMessageOut } from '../db/messages-out.js';
import { getCurrentInReplyTo } from '../db/session-state.js';
import { registerTools } from './server.js';
import type { McpToolDefinition } from './types.js';

const ENGINES = ['fable', 'opus', 'sonnet', 'haiku', 'astra', 'sol', 'terra', 'luna'] as const;
const EFFORTS = ['low', 'medium', 'high', 'xhigh'] as const;

async function request(action: string, fields: Record<string, unknown>) {
  const inReplyTo = getCurrentInReplyTo();
  if (!inReplyTo)
    return { content: [{ type: 'text' as const, text: 'No human message triggered this turn.' }], isError: true };
  await writeMessageOut({
    id: `model-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    in_reply_to: inReplyTo,
    kind: 'system',
    content: JSON.stringify({ action, triggerMessageId: inReplyTo, ...fields }),
  });
  return {
    content: [{ type: 'text' as const, text: 'The host will reply to the triggering chat; do not repeat it.' }],
  };
}

export const setModel: McpToolDefinition = {
  tool: {
    name: 'set_model',
    description: 'Switch your own model and optional reasoning effort. The host confirms in chat and restarts you.',
    inputSchema: {
      type: 'object',
      properties: {
        engine: { type: 'string', enum: ENGINES },
        effort: { type: 'string', enum: EFFORTS },
      },
      required: ['engine'],
    },
  },
  async handler(args) {
    const engine = typeof args.engine === 'string' ? args.engine.toLowerCase() : '';
    const effort = typeof args.effort === 'string' ? args.effort.toLowerCase() : undefined;
    if (!ENGINES.includes(engine as (typeof ENGINES)[number])) {
      return { content: [{ type: 'text', text: "I don't know that model." }], isError: true };
    }
    if (effort && !EFFORTS.includes(effort as (typeof EFFORTS)[number])) {
      return { content: [{ type: 'text', text: "I don't know that effort." }], isError: true };
    }
    return request('set_model', { engine, effort });
  },
};

export const currentModel: McpToolDefinition = {
  tool: {
    name: 'current_model',
    description: 'Tell the triggering admin which model and effort you run.',
    inputSchema: { type: 'object', properties: {} },
  },
  async handler() {
    return request('current_model', {});
  },
};

registerTools([setModel, currentModel]);
