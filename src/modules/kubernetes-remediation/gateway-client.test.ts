import { randomUUID } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';

import {
  cleanupRemediationOrphans,
  GatewayRemediationExecutor,
  type KubernetesJsonClient,
  type RolloutObserver,
} from './gateway-client.js';
import { validateRemediationPlan } from './policy.js';

function plan(namespace: 'vaultwarden' | 'kube-system' | 'gitea') {
  return {
    schemaVersion: 1,
    id: randomUUID(),
    incidentIds: ['falco:one'],
    target: {
      apiVersion: 'apps/v1',
      kind: 'Deployment',
      namespace,
      name: namespace === 'vaultwarden' ? 'vaultwarden' : namespace === 'gitea' ? 'gitea' : 'coredns',
      uid: 'uid-1',
      resourceVersion: '42',
    },
    reason: 'review fixture',
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    operation:
      namespace === 'vaultwarden'
        ? {
            type: 'patch-image',
            container: 'vaultwarden',
            initContainer: false,
            before: 'docker.io/vaultwarden/server:latest',
            after: `docker.io/vaultwarden/server@sha256:${'a'.repeat(64)}`,
          }
        : namespace === 'gitea'
          ? { type: 'scale', before: 1, after: 1 }
          : { type: 'lane-c-escalation', requestedChange: 'upgrade coredns manually' },
  };
}

describe('gateway remediation executor', () => {
  it('removes stale annotations and temporary bindings before startup', async () => {
    const request = vi.fn(async (path: string, options?: { method?: string }) => {
      if (options) return {};
      if (path.endsWith('/clusterrolebindings')) {
        return { items: [{ metadata: { name: 'nanoclaw-remediation-123e4567-e89b-42d3-a456-426614174000' } }] };
      }
      if (path.endsWith('/deployments')) {
        return {
          items: [
            {
              metadata: {
                name: 'gitea',
                namespace: 'gitea',
                resourceVersion: '55',
                annotations: { 'remediation.nanoclaw.io/approval-id': '123e4567-e89b-42d3-a456-426614174000' },
              },
            },
          ],
        };
      }
      return { items: [] };
    });
    const client: KubernetesJsonClient = { request, watch: vi.fn() };

    await expect(cleanupRemediationOrphans(client)).resolves.toBe(2);
    expect(request).toHaveBeenCalledWith(
      '/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/nanoclaw-remediation-123e4567-e89b-42d3-a456-426614174000',
      { method: 'DELETE' },
    );
    expect(request).toHaveBeenCalledWith(
      '/apis/apps/v1/namespaces/gitea/deployments/gitea',
      expect.objectContaining({ method: 'PATCH' }),
    );
  });

  it('uses only the annotator identity for the approval annotation and clears it', async () => {
    const validated = validateRemediationPlan(plan('gitea'));
    const executorCalls: Array<{ path: string; options?: Record<string, unknown> }> = [];
    const annotatorCalls: Array<{ path: string; options?: Record<string, unknown> }> = [];
    const executor: KubernetesJsonClient = {
      request: vi.fn(async (path, options) => {
        executorCalls.push({ path, options });
        return options ? {} : { metadata: { uid: 'uid-1', resourceVersion: '42' } };
      }),
      watch: vi.fn(),
    };
    let annotatorGet = 0;
    const annotator: KubernetesJsonClient = {
      request: vi.fn(async (path, options) => {
        annotatorCalls.push({ path, options });
        if (!options) return { metadata: { uid: 'uid-1', resourceVersion: String(43 + annotatorGet++) } };
        return {};
      }),
      watch: vi.fn(),
    };
    const observer: RolloutObserver = { ready: vi.fn(async () => true) };
    await new GatewayRemediationExecutor(executor, annotator, observer).execute(validated, {
      approvalRowId: 'row-1',
      approverUserId: 'matrix:@owner:example',
      planId: validated.plan.id,
      planDigest: validated.digest,
    });

    expect(executorCalls).toHaveLength(2);
    expect(JSON.stringify(executorCalls)).not.toContain('remediation.nanoclaw.io/approval-id');
    expect(annotatorCalls.filter((call) => call.options?.method === 'PATCH')).toHaveLength(2);
    expect(JSON.stringify(annotatorCalls)).toContain('remediation.nanoclaw.io/approval-id');
  });

  it('records Lane C approval without touching Kubernetes', async () => {
    const validated = validateRemediationPlan(plan('kube-system'));
    const request = vi.fn();
    const client: KubernetesJsonClient = { request, watch: vi.fn() };
    const result = await new GatewayRemediationExecutor(client, client, { ready: vi.fn() }).execute(validated, {
      approvalRowId: 'row-1',
      approverUserId: 'matrix:@owner:example',
      planId: validated.plan.id,
      planDigest: validated.digest,
    });
    expect(result.applied).toBe(false);
    expect(request).not.toHaveBeenCalled();
  });
});
