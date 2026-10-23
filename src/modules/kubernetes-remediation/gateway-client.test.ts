import { randomUUID } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';

import {
  cleanupRemediationOrphans,
  GatewayRemediationExecutor,
  type KubernetesJsonClient,
  type RolloutObserver,
} from './gateway-client.js';
import { validateRemediationPlan } from './policy.js';

function plan(namespace: 'wireguard-home' | 'kube-system' | 'gitea') {
  return {
    schemaVersion: 1,
    id: randomUUID(),
    incidentIds: ['falco:one'],
    target: {
      apiVersion: 'apps/v1',
      kind: 'Deployment',
      namespace,
      name: namespace === 'wireguard-home' ? 'wireguard' : namespace === 'gitea' ? 'gitea' : 'coredns',
      uid: 'uid-1',
      resourceVersion: '42',
    },
    reason: 'review fixture',
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    operation:
      namespace === 'wireguard-home'
        ? {
            type: 'patch-image',
            containers: [{ name: 'wireguard', initContainer: false }],
            before: 'lscr.io/linuxserver/wireguard:latest',
            after: `lscr.io/linuxserver/wireguard@sha256:${'a'.repeat(64)}`,
          }
        : namespace === 'gitea'
          ? { type: 'scale', before: 1, after: 1 }
          : { type: 'restart', restartedAt: new Date().toISOString() },
  };
}

function attachmentTicketFixture(state = 'Completed') {
  const ticket = 'backup-controller-backup-one';
  const target = {
    ...plan('kube-system').target,
    apiVersion: 'longhorn.io/v1beta2',
    kind: 'VolumeAttachment',
    namespace: 'longhorn-system',
    name: 'vol',
  };
  const validated = validateRemediationPlan({
    ...plan('kube-system'),
    target,
    operation: { type: 'remove-attachment-ticket', ticket },
  });
  const request = vi.fn(async (path: string, options?: unknown) =>
    options
      ? {}
      : path.endsWith('/backups/backup-one')
        ? { metadata: { labels: { 'backup-volume': 'vol' } }, status: { state } }
        : {
            metadata: { uid: 'uid-1', resourceVersion: '42' },
            spec: { attachmentTickets: { [ticket]: { id: ticket, type: 'backup-controller' } } },
          },
  );
  const client = { request, watch: vi.fn() };
  const executor = new GatewayRemediationExecutor(client, client, { ready: vi.fn() }, undefined, { client });
  const grant = {
    approvalRowId: '',
    approverUserId: 'standing',
    planId: validated.plan.id,
    planDigest: validated.digest,
  };
  return { executor, grant, request, ticket, validated };
}

function cronJobRunFixture() {
  const jobTemplate = {
    metadata: { labels: { existing: 'yes' } },
    spec: { template: { spec: { containers: [{ name: 'backup', image: 'alpine' }] } } },
  };
  const target = {
    ...plan('gitea').target,
    apiVersion: 'batch/v1',
    kind: 'CronJob',
    namespace: 'backups',
    name: 'backup',
  };
  const validated = validateRemediationPlan({ ...plan('gitea'), target, operation: { type: 'run-cronjob' } });
  const request = vi.fn(async (path: string, options?: unknown) =>
    options
      ? {}
      : path.includes('/pods?')
        ? { items: [{ status: { startTime: 'now' } }] }
        : { metadata: { uid: 'uid-1', resourceVersion: '42' }, spec: { jobTemplate } },
  );
  const client = { request, watch: vi.fn() };
  const grant = {
    approvalRowId: '',
    approverUserId: 'auto:low-risk',
    planId: validated.plan.id,
    planDigest: validated.digest,
  };
  return {
    executor: new GatewayRemediationExecutor(client, client, { ready: vi.fn() }),
    grant,
    jobTemplate,
    request,
    validated,
  };
}

describe('gateway remediation executor', () => {
  it('removes exactly a completed Backup attachment ticket through break-glass', async () => {
    const { executor, grant, request, ticket, validated } = attachmentTicketFixture();
    await executor.execute(validated, grant);
    expect(request).toHaveBeenLastCalledWith(
      expect.stringContaining('/volumeattachments/vol'),
      expect.objectContaining({
        contentType: 'application/json-patch+json',
        body: expect.arrayContaining([{ op: 'remove', path: `/spec/attachmentTickets/${ticket}` }]),
      }),
    );
  });

  it('refuses a backup attachment ticket until its Backup is completed', async () => {
    const { executor, grant, request, validated } = attachmentTicketFixture('InProgress');
    await expect(executor.execute(validated, grant)).rejects.toThrow('is not completed');
    expect(request.mock.calls.some(([, options]) => options)).toBe(false);
  });

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
    const validated = validateRemediationPlan(plan('wireguard-home'));
    const executorCalls: Array<{ path: string; options?: Record<string, unknown> }> = [];
    const annotatorCalls: Array<{ path: string; options?: Record<string, unknown> }> = [];
    const executor: KubernetesJsonClient = {
      request: vi.fn(async (path, options) => {
        executorCalls.push({ path, options });
        const containers = [{ name: 'wireguard', image: 'lscr.io/linuxserver/wireguard:latest' }];
        return options
          ? {}
          : { metadata: { uid: 'uid-1', resourceVersion: '42' }, spec: { template: { spec: { containers } } } };
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

  it('deletes a Job only once it has finished', async () => {
    const validated = validateRemediationPlan({
      ...plan('gitea'),
      target: { ...plan('gitea').target, apiVersion: 'batch/v1', kind: 'Job' },
      operation: { type: 'delete-job' },
    });
    const grant = {
      approvalRowId: '',
      approverUserId: 'auto:low-risk',
      planId: validated.plan.id,
      planDigest: validated.digest,
    };
    const job = (status: Record<string, unknown>) => {
      const request = vi.fn(async (_path: string, options?: unknown) =>
        options ? {} : { metadata: { uid: 'uid-1', resourceVersion: '42' }, status },
      );
      return {
        request,
        executor: new GatewayRemediationExecutor(
          { request, watch: vi.fn() },
          { request: vi.fn(), watch: vi.fn() },
          { ready: vi.fn() },
        ),
      };
    };

    const running = job({ active: 1, conditions: [{ type: 'Complete', status: 'False' }] });
    await expect(running.executor.execute(validated, grant)).rejects.toThrow('Job is still running');
    expect(running.request).toHaveBeenCalledTimes(1);

    const done = job({ conditions: [{ type: 'Failed', status: 'True' }] });
    await expect(done.executor.execute(validated, grant)).resolves.toMatchObject({ applied: true });
    expect(done.request).toHaveBeenLastCalledWith('/apis/batch/v1/namespaces/gitea/jobs/gitea', {
      method: 'DELETE',
      body: expect.objectContaining({
        propagationPolicy: 'Background',
        preconditions: { uid: 'uid-1', resourceVersion: '42' },
      }),
    });
  });

  it('patches a CronJob job template without an annotation or rollout wait', async () => {
    const validated = validateRemediationPlan({
      ...plan('gitea'),
      target: { ...plan('gitea').target, apiVersion: 'batch/v1', kind: 'CronJob', namespace: 'openclaw-private' },
      operation: {
        type: 'patch-image',
        containers: [{ name: 'build', initContainer: false }],
        before: 'node:20-alpine',
        after: `docker.io/library/node:20-alpine@sha256:${'a'.repeat(64)}`,
      },
    });
    const containers = [{ name: 'build', image: 'node:20-alpine' }];
    const request = vi.fn(async (_path: string, options?: unknown) =>
      options
        ? {}
        : {
            metadata: { uid: 'uid-1', resourceVersion: '42' },
            spec: { jobTemplate: { spec: { template: { spec: { containers } } } } },
          },
    );
    const annotator = { request: vi.fn(), watch: vi.fn() };
    const observer = { ready: vi.fn() };
    await new GatewayRemediationExecutor({ request, watch: vi.fn() }, annotator, observer).execute(validated, {
      approvalRowId: '',
      approverUserId: 'auto:low-risk',
      planId: validated.plan.id,
      planDigest: validated.digest,
    });
    expect(request).toHaveBeenLastCalledWith('/apis/batch/v1/namespaces/openclaw-private/cronjobs/gitea', {
      method: 'PATCH',
      body: {
        metadata: { resourceVersion: '42' },
        spec: {
          jobTemplate: {
            spec: {
              template: {
                spec: {
                  containers: [
                    {
                      name: 'build',
                      image: validated.plan.operation.type === 'patch-image' && validated.plan.operation.after,
                    },
                  ],
                },
              },
            },
          },
        },
      },
      contentType: 'application/strategic-merge-patch+json',
    });
    expect(annotator.request).not.toHaveBeenCalled();
    expect(observer.ready).not.toHaveBeenCalled();
  });

  it('copies a CronJob job template into a labeled Job', async () => {
    const { executor, grant, jobTemplate, request, validated } = cronJobRunFixture();
    await executor.execute(validated, grant);
    const body = request.mock.calls.find(([, options]) => options)?.[1] as { body: Record<string, unknown> };
    expect(body.body).toMatchObject({
      metadata: { labels: { existing: 'yes', 'nanoclaw.dev/run-of': 'backup' } },
      spec: jobTemplate.spec,
    });
  });

  it('applies an approved Lane C plan only through the break-glass identity', async () => {
    const validated = validateRemediationPlan(plan('kube-system'));
    const grant = {
      approvalRowId: 'row-1',
      approverUserId: 'matrix:@owner:example',
      planId: validated.plan.id,
      planDigest: validated.digest,
    };
    const writer = { request: vi.fn(), watch: vi.fn() };
    const observer = { ready: vi.fn(async () => true) };
    await expect(new GatewayRemediationExecutor(writer, writer, observer).execute(validated, grant)).rejects.toThrow(
      'break-glass identity is not configured',
    );
    const request = vi.fn(async (_path: string, options?: unknown) =>
      options ? {} : { metadata: { uid: 'uid-1', resourceVersion: '42' } },
    );
    const result = await new GatewayRemediationExecutor(writer, writer, observer, undefined, {
      client: { request, watch: vi.fn() },
    }).execute(validated, grant);
    expect(result.applied).toBe(true);
    expect(request).toHaveBeenLastCalledWith(
      '/apis/apps/v1/namespaces/kube-system/deployments/coredns',
      expect.objectContaining({ method: 'PATCH' }),
    );
    expect(writer.request).not.toHaveBeenCalled();
  });
});
