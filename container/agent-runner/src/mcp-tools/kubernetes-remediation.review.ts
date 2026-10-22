/** REVIEW ARTIFACT: intentionally absent from mcp-tools/index.ts. */
import { writeMessageOut } from '../db/messages-out.js';
import { registerTools } from './server.js';
import type { McpToolDefinition } from './types.js';

export const proposeKubernetesRemediation: McpToolDefinition = {
  tool: {
    name: 'propose_kubernetes_remediation',
    description:
      'Submit one exact Kubernetes remediation plan. The host revalidates target identity, policy and expiry; a Lane A restart or delete-job applies without a card and the approver is notified, everything else waits for Matrix approval.',
    inputSchema: {
      type: 'object',
      properties: {
        plan: {
          type: 'object',
          description:
            'Keys exactly: schemaVersion (1), id, incidentIds, target {apiVersion, kind, namespace, name, uid, resourceVersion}, reason, expiresAt, operation. ' +
            'operation is one of: {type:"patch-image", containers [{name, initContainer (boolean)}], before (the exact image every listed container runs now), after (new image)}; ' +
            '{type:"restart", restartedAt}; {type:"scale", before, after}; {type:"delete-job"} (target a finished batch/v1 Job); ' +
            '{type:"delete-storage", reclaimConfirmed:true}; ' +
            '{type:"lane-c-escalation", requestedChange}. Any other change (values, probes, config) is lane-c-escalation.',
        },
      },
      required: ['plan'],
    },
  },
  async handler(args) {
    if (args.plan === null || typeof args.plan !== 'object' || Array.isArray(args.plan)) {
      return { content: [{ type: 'text', text: 'Error: plan must be an object' }], isError: true };
    }
    await writeMessageOut({
      id: `k8s-plan-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      kind: 'system',
      content: JSON.stringify({ action: 'kubernetes_remediation', plan: args.plan }),
    });
    return { content: [{ type: 'text', text: 'Plan submitted; the host reports the outcome.' }] };
  },
};

registerTools([proposeKubernetesRemediation]);
