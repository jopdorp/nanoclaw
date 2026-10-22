import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import { validateRemediationPlan } from './policy.js';

const now = Date.parse('2026-10-21T12:00:00.000Z');

function base(namespace = 'gitea') {
  return {
    schemaVersion: 1,
    id: randomUUID(),
    incidentIds: ['trivy:one:2'],
    target: {
      apiVersion: 'apps/v1',
      kind: 'Deployment',
      namespace,
      name: namespace === 'vaultwarden' ? 'vaultwarden' : 'gitea',
      uid: 'uid-1',
      resourceVersion: '42',
    },
    reason: 'critical image finding; rollback to the recorded prior digest',
    expiresAt: '2026-10-21T12:10:00.000Z',
  };
}

describe('Kubernetes remediation policy', () => {
  it('accepts a Lane A same-repository digest update with the two-write recovery cap', () => {
    const validated = validateRemediationPlan(
      {
        ...base(),
        operation: {
          type: 'patch-image',
          container: 'gitea',
          initContainer: false,
          before: `docker.io/gitea/gitea@sha256:${'c'.repeat(64)}`,
          after: `docker.io/gitea/gitea@sha256:${'a'.repeat(64)}`,
        },
      },
      now,
    );
    expect(validated.lane).toBe('A');
    expect(validated.automaticWriteCap).toBe(2);
    expect(validated.digest).toMatch(/^[0-9a-f]{64}$/);
  });

  it('keeps Vaultwarden always-ask with no automatic recovery', () => {
    const validated = validateRemediationPlan(
      {
        ...base('vaultwarden'),
        operation: {
          type: 'patch-image',
          container: 'vaultwarden',
          initContainer: false,
          before: 'docker.io/vaultwarden/server:latest',
          after: `docker.io/vaultwarden/server@sha256:${'b'.repeat(64)}`,
        },
      },
      now,
    );
    expect(validated.lane).toBe('always-ask');
    expect(validated.automaticWriteCap).toBe(0);
  });

  it('allows only a manual escalation plan in Lane C', () => {
    const laneC = {
      ...base('kube-system'),
      operation: { type: 'lane-c-escalation', requestedChange: 'upgrade coredns' },
    };
    expect(validateRemediationPlan(laneC, now).automaticWriteCap).toBe(0);
    expect(() =>
      validateRemediationPlan({ ...base('kube-system'), operation: { type: 'scale', before: 1, after: 1 } }, now),
    ).toThrow('Lane C is read/propose only');
  });

  it('rejects tag updates, target drift fields, backup deletion, and stale plans', () => {
    expect(() =>
      validateRemediationPlan(
        {
          ...base(),
          operation: {
            type: 'patch-image',
            container: 'gitea',
            initContainer: false,
            before: 'gitea/gitea:old',
            after: 'gitea/gitea:new',
          },
        },
        now,
      ),
    ).toThrow('approved digest');
    expect(() =>
      validateRemediationPlan(
        { ...base(), surprise: true, operation: { type: 'restart', restartedAt: new Date(now).toISOString() } },
        now,
      ),
    ).toThrow('surprise is not allowed');
    expect(() =>
      validateRemediationPlan(
        {
          ...base('backups'),
          target: { ...base('backups').target, apiVersion: 'v1', kind: 'PersistentVolumeClaim' },
          operation: { type: 'delete-storage', reclaimConfirmed: true },
        },
        now,
      ),
    ).toThrow('backup storage is immutable');
    expect(() =>
      validateRemediationPlan(
        { ...base(), expiresAt: '2026-10-21T11:59:00Z', operation: { type: 'scale', before: 1, after: 1 } },
        now,
      ),
    ).toThrow('within the next 15 minutes');
  });
});
