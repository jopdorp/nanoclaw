/**
 * Agent management MCP tools: create_agent.
 *
 * send_to_agent was removed — sending to another agent is now just
 * send_message(to="agent-name") since agents and channels share the
 * unified destinations namespace.
 *
 * create_agent writes central-DB state. The host authorizes it by CLI scope:
 * trusted owner agent groups (scope 'global') create directly; confined groups
 * require admin approval (see src/modules/agent-to-agent/create-agent.ts). This
 * tool just writes the outbound request; authorization is enforced host-side,
 * not here — the container is untrusted and cannot be relied on to gate itself.
 */
import { writeMessageOut } from '../db/messages-out.js';
import { registerTools } from './server.js';
import type { McpToolDefinition } from './types.js';

function log(msg: string): void {
  console.error(`[mcp-tools] ${msg}`);
}

function generateId(): string {
  return `msg-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

function ok(text: string) {
  return { content: [{ type: 'text' as const, text }] };
}

function err(text: string) {
  return { content: [{ type: 'text' as const, text: `Error: ${text}` }], isError: true };
}

export const createAgent: McpToolDefinition = {
  tool: {
    name: 'create_agent',
    description:
      'Create a long-lived companion sub-agent (research assistant, task manager, specialist) — the name becomes your destination for it. May require admin approval before the agent is created. Fire-and-forget.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        name: { type: 'string', description: 'Human-readable name (also becomes your destination name for this agent)' },
        instructions: { type: 'string', description: 'CLAUDE.md content for the new agent (personality, role, instructions)' },
        template: {
          type: 'string',
          description:
            'Optional template ref the user chose (e.g. "sales/sdr"), from `ncl templates list`. The template supplies the persona; `instructions` is ignored.',
        },
        provider: {
          type: 'string',
          description: 'Optional provider for the new agent ("claude" or "codex"); defaults to yours',
        },
        model: { type: 'string', description: 'Optional model for the new agent, e.g. "gpt-5.6-sol" or "opus"' },
        role: {
          type: 'string',
          description:
            'Optional role file from your .claude/agents (e.g. "sre-engineer"), prepended to its instructions',
        },
      },
      required: ['name'],
    },
  },
  async handler(args) {
    const name = args.name as string;
    if (!name) return err('name is required');

    const requestId = generateId();
    await writeMessageOut({
      id: requestId,
      kind: 'system',
      content: JSON.stringify({
        action: 'create_agent',
        requestId,
        name,
        instructions: (args.instructions as string) || null,
        ...(typeof args.template === 'string' && args.template ? { template: args.template } : {}),
        provider: args.provider,
        model: args.model,
        role: args.role,
      }),
    });

    log(`create_agent: ${requestId} → "${name}"`);
    return ok(`Creating agent "${name}". You will be notified when it is ready.`);
  },
};

export const deleteAgent: McpToolDefinition = {
  tool: {
    name: 'delete_agent',
    description: 'Stop and delete an agent you created with create_agent, by its destination name. Fire-and-forget.',
    inputSchema: { type: 'object' as const, properties: { name: { type: 'string' } }, required: ['name'] },
  },
  async handler(args) {
    const requestId = generateId();
    await writeMessageOut({
      id: requestId,
      kind: 'system',
      content: JSON.stringify({ action: 'delete_agent', requestId, name: args.name }),
    });
    return ok(`Deleting agent "${String(args.name)}". You will be notified when it is gone.`);
  },
};

registerTools([createAgent, deleteAgent]);
