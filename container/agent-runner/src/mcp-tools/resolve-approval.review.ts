import { writeMessageOut } from '../db/messages-out.js';
import { registerTools } from './server.js';
import type { McpToolDefinition } from './types.js';

export const resolveApproval: McpToolDefinition = {
  tool: {
    name: 'resolve_approval',
    description:
      "Approve or reject a pending approval from the approver's own reply. When a message from the approver arrives with a <pending_approvals> block, read their reply as an answer to those items. If it clearly approves or rejects one of them, call resolve_approval with that item's id, the decision, any reason they gave, and the approverMessageId from the block. If it is unclear which pending item they mean, or whether they decided at all, ask them instead of guessing. The host only accepts the approver's own message, sent after the card, used once. It confirms in chat or tells you why it refused.",
    inputSchema: {
      type: 'object',
      properties: {
        approvalId: { type: 'string', description: 'Id from the pending_approvals block' },
        decision: { type: 'string', enum: ['approve', 'reject'] },
        reason: { type: 'string', description: 'Why, when they reject and say why' },
        approverMessageId: { type: 'string', description: 'approverMessageId from the block of the reply you act on' },
      },
      required: ['approvalId', 'decision', 'approverMessageId'],
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

registerTools([resolveApproval]);
