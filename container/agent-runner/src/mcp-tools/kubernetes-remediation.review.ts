/** REVIEW ARTIFACT: intentionally absent from mcp-tools/index.ts. */
import { writeMessageOut } from '../db/messages-out.js';
import { registerTools } from './server.js';
import type { McpToolDefinition } from './types.js';

export const proposeKubernetesRemediation: McpToolDefinition = {
  tool: {
    name: 'propose_kubernetes_remediation',
    description:
      'Submit one exact Kubernetes remediation plan. The host revalidates target identity, policy and expiry, then sorts it by the AUTO, APPROVAL and NEVER lists in your instructions: AUTO applies at once and Jegor hears the outcome, APPROVAL waits for his answer and then applies (kube-system/longhorn-system through the break-glass identity), NEVER is rejected.',
    inputSchema: {
      type: 'object',
      properties: {
        plan: {
          type: 'object',
          description:
            'Keys exactly: schemaVersion (1), id, incidentIds, target {apiVersion, kind, namespace, name, uid, resourceVersion}, reason, expiresAt, operation. ' +
            'operation is one of: {type:"patch-image", containers [{name, initContainer (boolean)}], before (the exact image every listed container runs now), after (registry/repo:tag@sha256:digest)} on a Deployment, StatefulSet, DaemonSet or batch/v1 CronJob (its job template containers; the only change allowed in backups); ' +
            '{type:"restart", restartedAt}; {type:"scale", before, after}; {type:"delete-job"} (target a finished batch/v1 Job); ' +
            '{type:"delete-storage", reclaimConfirmed:true} on a PV, PVC or Longhorn volume (apiVersion "longhorn.io/v1beta2", kind "Volume", namespace "longhorn-system"); ' +
            '{type:"helm-values", file ("kubernetes/helm-charts/<release>-values.yaml" in k8s.jegor.nl), chart {repo: "https://..." or "oci://..."} (needed until the host has verified it once), set [{path (dotted values path, e.g. "image.tag"), before (the value in the file now, or null to add an absent key), after}] (1-8 string/number/boolean edits; image, tag and digest values must pin a same-repository sha256 digest)} with target {apiVersion:"v1", kind:"Secret", namespace, name (the Helm release), uid:"-", resourceVersion:"-"}: the file must equal the live release values, then the host runs helm upgrade and commits the values only if the release comes up healthy and matches any open Helm drift; ' +
            '{type:"helm-sync-values"} with the same release target writes the live values to that file and pushes, no cluster change; ' +
            '{type:"pod-exec", container, command [argv]} with target {apiVersion:"v1", kind:"Pod", namespace, name, uid, resourceVersion}: the host runs the argv from an in-cluster Job and returns the last 2 KB of output; ' +
            '{type:"manifest-edit", file ("kubernetes/<path>.yaml" in k8s.jegor.nl), set [{path (dotted, numeric list indices, e.g. "spec.template.spec.containers.0.image"), before, after}]} with target the object in that file (any apiVersion/kind, uid:"-", resourceVersion:"-"): the object must equal live, then the host applies it server-side and pushes; ' +
            '{type:"manifest-sync", file} with the same target writes the live object to the file and pushes, no cluster change; ' +
            '{type:"build-image", dockerfile, context (k8s.jegor.nl paths, dockerfile inside context), image ("registry.prophet.jopdorp.nl/<name>:<tag>")} with target {apiVersion:"batch/v1", kind:"Job", namespace:"security", name (the build Job to create), uid:"-", resourceVersion:"-"}: the host builds with kaniko, pushes and replies with the digest; ' +
            'Changes no operation covers (probes, config outside a values file, CRs) are not plans: send Jegor the exact commands.',
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
