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
            '{type:"helm-values", file ("kubernetes/helm-charts/<name>-values.yaml" in k8s.jegor.nl), set [{path (dotted values path, e.g. "image.tag"), before (the value in the file now, or null to add an absent key), after}] (1-8 string/number/boolean edits; image, tag and digest values must pin a same-repository sha256 digest)} with target {apiVersion:"v1", kind:"Secret", namespace, name (the Helm release), uid:"-", resourceVersion:"-"}: the host binds it to the latest release revision, checks every before against the repo and rejects with the actual value on a mismatch, then after approval runs helm upgrade and commits the values only if the release comes up healthy and matches any open Helm drift; ' +
            '{type:"lane-c-escalation", requestedChange}. Any other change (probes, config outside a values file) is lane-c-escalation.',
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
