import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';

import { checkImageUpdate, isAutoApproved, standingGrant, validateRemediationPlan } from './policy.js';

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
      name: 'gitea',
      uid: 'uid-1',
      resourceVersion: '42',
    },
    reason: 'critical image finding; rollback to the recorded prior digest',
    expiresAt: '2026-10-21T12:10:00.000Z',
  };
}

function chartBump(version: string) {
  const target = { ...base().target, apiVersion: 'v1', kind: 'Secret' };
  const operation = {
    type: 'helm-values',
    file: 'kubernetes/helm-charts/gitea-values.yaml',
    chart: { version },
    set: [],
  };
  const plan = validateRemediationPlan({ ...base(), target, operation }, now);
  return isAutoApproved(plan, new Set(), {
    chart: { before: '1.2.3', after: version },
    images: {},
    statefulRepositories: [],
    hasStatefulSet: false,
  });
}

describe('Kubernetes remediation policy', () => {
  it('only accepts backup-controller attachment tickets', () => {
    const target = { ...base('longhorn-system').target, apiVersion: 'longhorn.io/v1beta2', kind: 'VolumeAttachment' };
    const proposed = (ticket: string) => ({
      ...base('longhorn-system'),
      target,
      operation: { type: 'remove-attachment-ticket', ticket },
    });
    expect(validateRemediationPlan(proposed('backup-controller-backup-one'), now).lane).toBe('C');
    expect(() => validateRemediationPlan(proposed('csi-one'), now)).toThrow('only backup-controller-*');
  });

  it('accepts a Lane A same-repository digest update with the two-write recovery cap', () => {
    const validated = validateRemediationPlan(
      {
        ...base(),
        operation: {
          type: 'patch-image',
          containers: [{ name: 'gitea', initContainer: false }],
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

  it('allows repository changes only to trusted registries', () => {
    const digest = `@sha256:${'a'.repeat(64)}`;
    expect(() => checkImageUpdate('alpine:3', `gitea.claw.jopdorp.nl/cluster/binder${digest}`)).not.toThrow();
    expect(() => checkImageUpdate('alpine:3', `evil.example/cluster/binder${digest}`)).toThrow();
  });

  it('keeps wireguard-home always-ask with no automatic recovery', () => {
    const validated = validateRemediationPlan(
      {
        ...base('wireguard-home'),
        operation: {
          type: 'patch-image',
          containers: [{ name: 'wireguard', initContainer: false }],
          before: 'lscr.io/linuxserver/wireguard:latest',
          after: `lscr.io/linuxserver/wireguard@sha256:${'b'.repeat(64)}`,
        },
      },
      now,
    );
    expect(validated.lane).toBe('always-ask');
    expect(validated.automaticWriteCap).toBe(0);
  });

  it('auto-approves within the major version, T1 within the minor, and holds the rest', () => {
    const t1 = new Set(['nextcloud']);
    const auto = (namespace: string, operation: Record<string, unknown>, kind = 'Deployment') =>
      isAutoApproved(
        validateRemediationPlan({ ...base(namespace), target: { ...base(namespace).target, kind }, operation }, now),
        t1,
      );
    const image = (before: string, after: string) => ({
      type: 'patch-image',
      containers: [{ name: 'app', initContainer: false }],
      before,
      after: `${after}@sha256:${'a'.repeat(64)}`,
    });
    expect(auto('duckdns', image('ghcr.io/x/app:v1.2.3', 'ghcr.io/x/app:v1.9.0'))).toBe(true);
    expect(auto('duckdns', image('ghcr.io/x/app:1.2.3', 'ghcr.io/x/app:2.0.0'))).toBe(false);
    expect(auto('nextcloud', image('nextcloud:31.0.1', 'docker.io/library/nextcloud'))).toBe(false);
    expect(auto('duckdns', image('matrixdotorg/synapse:latest', 'docker.io/matrixdotorg/synapse:v1.140.0'))).toBe(true);
    expect(auto('nextcloud', image('nextcloud:31.0.1', 'docker.io/library/nextcloud:31.0.9-apache'))).toBe(true);
    expect(auto('nextcloud', image('nextcloud:31.0.1', 'docker.io/library/nextcloud:31.1.0'))).toBe(false);
    expect(auto('nextcloud', image('nextcloud:latest', 'docker.io/library/nextcloud:31.1.0'))).toBe(false);
    expect(auto('prophet', image('qdrant/qdrant:v1.13.0', 'docker.io/qdrant/qdrant:v1.14.0'), 'StatefulSet')).toBe(
      false,
    );
    expect(auto('prophet', { type: 'scale', before: 1, after: 0 })).toBe(true);
    expect(auto('prophet', { type: 'scale', before: 1, after: 0 }, 'StatefulSet')).toBe(false);
    const restart = { type: 'restart', restartedAt: new Date(now).toISOString() };
    const laneC = validateRemediationPlan({ ...base('longhorn-system'), operation: restart }, now);
    expect([laneC.lane, laneC.automaticWriteCap, isAutoApproved(laneC, t1)]).toEqual(['C', 0, false]);
    const lane = (namespace: string) => validateRemediationPlan({ ...base(namespace), operation: restart }, now).lane;
    expect(['security', 'vaultwarden', 'nanoclaw-remediator', 'wireguard-home', 'kube-system'].map(lane)).toEqual([
      'A',
      'A',
      'A',
      'always-ask',
      'C',
    ]);
  });

  it('auto-applies pod-exec in an ordinary namespace and holds it where exec needs approval', () => {
    const exec = (namespace: string) =>
      isAutoApproved(
        validateRemediationPlan(
          {
            ...base(namespace),
            target: { ...base(namespace).target, apiVersion: 'v1', kind: 'Pod', name: 'app-0' },
            operation: { type: 'pod-exec', container: 'app', command: ['rm', '/tmp/x'] },
          },
          now,
        ),
        new Set(),
      );
    expect(['vaultwarden', 'wireguard-home', 'kube-system'].map(exec)).toEqual([true, false, false]);
  });

  it('auto-approves minor chart bumps and holds majors', () => {
    expect([chartBump('1.3.0'), chartBump('2.0.0')]).toEqual([true, false]);
  });

  it('never deletes anything in backups', () => {
    const target = (kind: string) => ({ ...base('backups').target, apiVersion: 'batch/v1', kind });
    const cron = validateRemediationPlan(
      {
        ...base('backups'),
        target: target('CronJob'),
        operation: {
          type: 'patch-image',
          containers: [{ name: 'backup', initContainer: false }],
          before: 'alpine:3.19',
          after: `docker.io/library/alpine:3.22@sha256:${'a'.repeat(64)}`,
        },
      },
      now,
    );
    expect([cron.automaticWriteCap, isAutoApproved(cron, new Set())]).toEqual([0, true]);
    expect(() =>
      validateRemediationPlan({ ...base('backups'), target: target('Job'), operation: { type: 'delete-job' } }, now),
    ).toThrow('nothing in backups is ever deleted');
  });

  it('rejects tag updates, target drift fields, backup deletion, and stale plans', () => {
    expect(() =>
      validateRemediationPlan(
        {
          ...base(),
          operation: {
            type: 'patch-image',
            containers: [{ name: 'gitea', initContainer: false }],
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
    ).toThrow('nothing in backups is ever deleted');
    expect(() =>
      validateRemediationPlan(
        { ...base(), expiresAt: '2026-10-21T11:59:00Z', operation: { type: 'scale', before: 1, after: 1 } },
        now,
      ),
    ).toThrow('within the next 15 minutes');
  });

  it('keeps helm-values to the release values file', () => {
    const helmValues = (namespace: string, file: string) => ({
      ...base(namespace),
      target: { apiVersion: 'v1', kind: 'Secret', namespace, name: namespace, uid: '-', resourceVersion: '-' },
      operation: { type: 'helm-values', file, set: [{ path: 'replicaCount', before: 1, after: 2 }] },
    });
    expect(() => validateRemediationPlan(helmValues('gitea', 'ansible/inventory-values.yaml'), now)).toThrow(
      'kubernetes/helm-charts/*.yaml',
    );
  });

  it('a standing yes for all except wireguard-home never covers wireguard-home', () => {
    const grant = {
      scope: 'all' as const,
      except: [{ namespace: 'wireguard-home' }],
      grantedBy: 'j',
      grantedAt: '2026-10-22',
      note: '',
    };
    const scale = (namespace: string) =>
      validateRemediationPlan({ ...base(namespace), operation: { type: 'scale', before: 1, after: 2 } }, now);
    expect(standingGrant(scale('nextcloud'), [grant])).toBe(grant);
    expect(standingGrant(scale('wireguard-home'), [grant])).toBeUndefined();
  });

  it('a plain image tag is pinned by a sibling digest edit in the same plan', () => {
    const plan = (set: unknown[]) => ({
      ...base(),
      target: { apiVersion: 'v1', kind: 'Secret', namespace: 'gitea', name: 'gitea', uid: '-', resourceVersion: '-' },
      operation: { type: 'helm-values', file: 'kubernetes/helm-charts/gitea-values.yaml', set },
    });
    const tag = { path: 'image.tag', before: '1.27.0', after: '1.27.3' };
    const digest = { path: 'image.digest', before: `sha256:${'b'.repeat(64)}`, after: `sha256:${'a'.repeat(64)}` };
    expect(validateRemediationPlan(plan([tag, digest]), now).lane).toBe('A');
    expect(() => validateRemediationPlan(plan([tag]), now)).toThrow('must pin a sha256 digest');
  });

  it('repo-write refuses inline credentials but passes Secret references', () => {
    const write = (content: string, file = 'kubernetes/a.yaml') => ({
      ...base(),
      target: {
        apiVersion: 'v1',
        kind: 'File',
        namespace: null,
        name: file,
        uid: '-',
        resourceVersion: '-',
      },
      operation: { type: 'repo-write', path: file, content },
    });
    const references =
      'server:\n  ingress:\n    tls:\n      - secretName: victoria-logs-tls\n  existingSecret: grafana-admin\n';
    expect(validateRemediationPlan(write(references), now).lane).toBe('A');
    expect(() => validateRemediationPlan(write('grafana:\n  adminPassword: hunter2\n'), now)).toThrow(
      'secret-looking values at grafana.adminPassword',
    );
    expect(validateRemediationPlan(write('name: apply', '.gitea/workflows/apply.yaml'), now).plan.commitOnly).toBe(
      true,
    );
    expect(
      validateRemediationPlan(write('not: yaml: at all', 'kubernetes/security/images/x/Dockerfile'), now).plan
        .commitOnly,
    ).toBe(true);
    expect(() => validateRemediationPlan(write('hi', 'README.md'), now)).toThrow('kubernetes/**');
  });
});
