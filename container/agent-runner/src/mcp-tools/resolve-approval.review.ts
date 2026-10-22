import { writeMessageOut } from '../db/messages-out.js';
import { registerTools } from './server.js';
import type { McpToolDefinition } from './types.js';

export const resolveApproval: McpToolDefinition = {
  tool: {
    name: 'resolve_approval',
    description:
      "Approve or reject pending approvals from the approver's own reply. Approvals are a conversation. When the host asks you to get approval, ask the approver in one plain sentence what will change and why. Read their reply: yes, fine, do it, go and the like approve; no, wait, don't and the like reject; if it is unclear, ask one short question. Then call resolve_approval with the ids from the <pending_approvals> block on their message, the decision, and that block's approverMessageId; a reply that covers several pending items resolves them all in one call. Never show plan ids, approval ids or codes to the approver. The host only accepts the approver's own message, sent while the approvals were pending, and confirms in chat or tells you why it refused.",
    inputSchema: {
      type: 'object',
      properties: {
        approvalIds: {
          type: 'array',
          items: { type: 'string' },
          minItems: 1,
          description: 'Ids from the pending_approvals block that the reply decides',
        },
        decision: { type: 'string', enum: ['approve', 'reject'] },
        reason: { type: 'string', description: 'Why, when they reject and say why' },
        approverMessageId: { type: 'string', description: 'approverMessageId from the block of the reply you act on' },
      },
      required: ['approvalIds', 'decision', 'approverMessageId'],
    },
  },
  async handler(args) {
    await writeMessageOut({
      id: `resolve-approval-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      kind: 'system',
      content: JSON.stringify({ ...args, action: 'resolve_approval' }),
    });
    return { content: [{ type: 'text', text: 'Submitted; the host confirms in chat or tells you why it refused.' }] };
  },
};

const scope = {
  description:
    '"all", or a list of {op?, namespace?, target?} entries (op is a plan operation type, target the target name)',
};
const standing = (name: string, description: string, properties: Record<string, unknown>): McpToolDefinition => ({
  tool: {
    name,
    description,
    inputSchema: {
      type: 'object',
      properties: {
        ...properties,
        approverMessageId: {
          type: 'string',
          description: 'approverMessageId from the block on the approver message that says it',
        },
      },
      required: ['scope', 'approverMessageId'],
    },
  },
  async handler(args) {
    await writeMessageOut({
      id: `${name}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      kind: 'system',
      content: JSON.stringify({ ...args, action: name }),
    });
    return { content: [{ type: 'text', text: 'Submitted; the host confirms in chat or tells you why it refused.' }] };
  },
});

registerTools([
  resolveApproval,
  standing(
    'record_standing_approval',
    'Record the approver\'s standing yes from his own message ("you have my yes for X", "for everything"), so plans it covers apply without asking. Never-rules stay out whatever the scope.',
    { scope, except: { description: 'entries the yes does not cover, same shape as scope' } },
  ),
  standing(
    'revoke_standing_approval',
    'Take back a standing yes from the approver\'s own message ("ask me again for X"): scope "all" removes every grant, entries are excluded from all grants.',
    { scope },
  ),
]);
