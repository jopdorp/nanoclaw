import { createHash } from 'node:crypto';

import type { RemediationLane, RemediationPlan, TargetRef, ValidatedPlan } from './types.js';

export const LANE_A_NAMESPACES = new Set([
  'nextcloud',
  'mail',
  'gitea',
  'monitoring',
  'wiki-js',
  'logging',
  'excalidraw',
  'excalidraw-room',
  'openclaw',
  'openclaw-private',
  'duckdns',
  'hermes',
  'mpcpi',
  'prophet',
  'schipperswoning',
  'trivy-operator',
]);

export const LANE_C_NAMESPACES = new Set([
  'kube-system',
  'kube-node-lease',
  'kube-public',
  'longhorn-system',
  'cert-manager',
  'falco',
  'system-upgrade',
]);

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DIGEST_IMAGE_RE =
  /^(docker\.io|docker\.gitea\.com|cr\.fluentbit\.io|ghcr\.io|quay\.io|registry\.k8s\.io)\/[a-z0-9]+(?:[._/-][a-z0-9]+)*@sha256:[0-9a-f]{64}$/;
const VAULTWARDEN_RE = /^docker\.io\/vaultwarden\/server@sha256:[0-9a-f]{64}$/;
const WIREGUARD_RE = /^lscr\.io\/linuxserver\/wireguard@sha256:[0-9a-f]{64}$/;

function record(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value))
    throw new Error(`${label} must be an object`);
  return value as Record<string, unknown>;
}

function string(value: unknown, label: string, max = 1024): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > max) {
    throw new Error(`${label} must be a non-empty string no longer than ${max} characters`);
  }
  return value;
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[], label: string): void {
  const allowed = new Set(keys);
  const extra = Object.keys(value).find((key) => !allowed.has(key));
  if (extra) throw new Error(`${label}.${extra} is not allowed`);
}

function targetFrom(value: unknown): TargetRef {
  const input = record(value, 'target');
  exactKeys(input, ['apiVersion', 'kind', 'namespace', 'name', 'uid', 'resourceVersion'], 'target');
  const kind = string(input.kind, 'target.kind');
  if (!['Deployment', 'StatefulSet', 'DaemonSet', 'PersistentVolume', 'PersistentVolumeClaim'].includes(kind)) {
    throw new Error('target.kind is unsupported');
  }
  const apiVersion = string(input.apiVersion, 'target.apiVersion');
  if (
    (kind.startsWith('Persistent') && apiVersion !== 'v1') ||
    (!kind.startsWith('Persistent') && apiVersion !== 'apps/v1')
  ) {
    throw new Error('target.apiVersion does not match target.kind');
  }
  const namespace = input.namespace === null ? null : string(input.namespace, 'target.namespace', 63);
  if ((kind === 'PersistentVolume') !== (namespace === null)) {
    throw new Error('only PersistentVolume targets may omit namespace');
  }
  return {
    apiVersion: apiVersion as TargetRef['apiVersion'],
    kind: kind as TargetRef['kind'],
    namespace,
    name: string(input.name, 'target.name', 253),
    uid: string(input.uid, 'target.uid', 128),
    resourceVersion: string(input.resourceVersion, 'target.resourceVersion', 128),
  };
}

export function parseRemediationPlan(value: unknown): RemediationPlan {
  const input = record(value, 'plan');
  exactKeys(input, ['schemaVersion', 'id', 'incidentIds', 'target', 'reason', 'expiresAt', 'operation'], 'plan');
  if (input.schemaVersion !== 1) throw new Error('plan.schemaVersion must be 1');
  const id = string(input.id, 'plan.id', 36);
  if (!UUID_RE.test(id)) throw new Error('plan.id must be a lowercase UUID');
  if (!Array.isArray(input.incidentIds) || input.incidentIds.length === 0 || input.incidentIds.length > 32) {
    throw new Error('plan.incidentIds must contain 1 through 32 IDs');
  }
  const incidentIds = input.incidentIds.map((entry, index) => string(entry, `plan.incidentIds[${index}]`, 256));
  if (new Set(incidentIds).size !== incidentIds.length) throw new Error('plan.incidentIds must be unique');
  const base = {
    schemaVersion: 1 as const,
    id,
    incidentIds,
    target: targetFrom(input.target),
    reason: string(input.reason, 'plan.reason', 2000),
    expiresAt: string(input.expiresAt, 'plan.expiresAt', 64),
  };
  const operation = record(input.operation, 'plan.operation');
  const type = string(operation.type, 'plan.operation.type');
  if (type === 'patch-image') {
    exactKeys(operation, ['type', 'container', 'initContainer', 'before', 'after'], 'plan.operation');
    if (typeof operation.initContainer !== 'boolean') throw new Error('plan.operation.initContainer must be boolean');
    return {
      ...base,
      operation: {
        type,
        container: string(operation.container, 'plan.operation.container', 253),
        initContainer: operation.initContainer,
        before: string(operation.before, 'plan.operation.before', 1000),
        after: string(operation.after, 'plan.operation.after', 1000),
      },
    };
  }
  if (type === 'restart') {
    exactKeys(operation, ['type', 'restartedAt'], 'plan.operation');
    return {
      ...base,
      operation: { type, restartedAt: string(operation.restartedAt, 'plan.operation.restartedAt', 64) },
    };
  }
  if (type === 'scale') {
    exactKeys(operation, ['type', 'before', 'after'], 'plan.operation');
    if (!Number.isInteger(operation.before) || !Number.isInteger(operation.after)) {
      throw new Error('plan.operation scale values must be integers');
    }
    return { ...base, operation: { type, before: operation.before as number, after: operation.after as number } };
  }
  if (type === 'delete-storage') {
    exactKeys(operation, ['type', 'reclaimConfirmed'], 'plan.operation');
    if (operation.reclaimConfirmed !== true) throw new Error('storage deletion requires reclaimConfirmed=true');
    return { ...base, operation: { type, reclaimConfirmed: true } };
  }
  if (type === 'lane-c-escalation') {
    exactKeys(operation, ['type', 'requestedChange'], 'plan.operation');
    return {
      ...base,
      operation: { type, requestedChange: string(operation.requestedChange, 'plan.operation.requestedChange', 2000) },
    };
  }
  throw new Error(
    'plan.operation.type is unsupported; use patch-image, restart, scale, delete-storage or lane-c-escalation',
  );
}

export function classifyTarget(target: TargetRef): RemediationLane {
  if (target.kind === 'PersistentVolume' || target.kind === 'PersistentVolumeClaim') return 'always-ask';
  if (target.namespace === 'vaultwarden' || target.namespace === 'wireguard-home') return 'always-ask';
  if (target.namespace && LANE_A_NAMESPACES.has(target.namespace)) return 'A';
  if (target.namespace && LANE_C_NAMESPACES.has(target.namespace)) return 'C';
  throw new Error('target is outside the remediation lanes');
}

function repository(image: string): string {
  const withoutDigest = image.split('@', 1)[0];
  const first = withoutDigest.split('/')[0];
  const normalized = first.includes('.') ? withoutDigest : `docker.io/${withoutDigest}`;
  const lastSlash = normalized.lastIndexOf('/');
  const colon = normalized.lastIndexOf(':');
  return colon > lastSlash ? normalized.slice(0, colon) : normalized;
}

function stable(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([k, v]) => [k, stable(v)]),
    );
  }
  return value;
}

export function canonicalPlan(plan: RemediationPlan): string {
  return JSON.stringify(stable(plan));
}

export function validateRemediationPlan(value: unknown, now = Date.now()): ValidatedPlan {
  const plan = parseRemediationPlan(value);
  const expiry = Date.parse(plan.expiresAt);
  if (!Number.isFinite(expiry) || expiry <= now || expiry > now + 15 * 60_000) {
    throw new Error('plan.expiresAt must be within the next 15 minutes');
  }
  const lane = classifyTarget(plan.target);
  let automaticWriteCap: 0 | 1 | 2 = 0;

  if (lane === 'C') {
    if (plan.operation.type !== 'lane-c-escalation') throw new Error('Lane C is read/propose only');
  } else if (plan.operation.type === 'lane-c-escalation') {
    throw new Error('lane-c-escalation is valid only for Lane C');
  }

  if (plan.operation.type === 'patch-image') {
    if (!['Deployment', 'StatefulSet', 'DaemonSet'].includes(plan.target.kind)) {
      throw new Error('patch-image requires a workload target');
    }
    const expected =
      plan.target.namespace === 'vaultwarden'
        ? VAULTWARDEN_RE
        : plan.target.namespace === 'wireguard-home'
          ? WIREGUARD_RE
          : DIGEST_IMAGE_RE;
    if (!expected.test(plan.operation.after)) throw new Error('new image is not an approved digest reference');
    if (repository(plan.operation.before) !== repository(plan.operation.after)) {
      throw new Error('image repository may not change');
    }
    // The base admission policy rejects a rollback to a mutable tag. Such a
    // rollout gets the restart attempt only; a digest-pinned prior image may
    // also use the second, rollback write.
    automaticWriteCap = lane === 'A' ? (DIGEST_IMAGE_RE.test(plan.operation.before) ? 2 : 1) : 0;
  } else if (plan.operation.type === 'restart') {
    if (lane !== 'A') throw new Error('restart is permitted only in Lane A');
    if (!Number.isFinite(Date.parse(plan.operation.restartedAt)))
      throw new Error('restartedAt must be an ISO timestamp');
    automaticWriteCap = 1;
  } else if (plan.operation.type === 'scale') {
    if (lane !== 'A' || !['Deployment', 'StatefulSet'].includes(plan.target.kind)) {
      throw new Error('scale requires a Lane A Deployment or StatefulSet');
    }
    if (
      plan.operation.before < 0 ||
      plan.operation.before > 10 ||
      plan.operation.after < 0 ||
      plan.operation.after > 10
    ) {
      throw new Error('replicas must be between 0 and 10');
    }
    automaticWriteCap = 1;
  } else if (plan.operation.type === 'delete-storage') {
    if (!plan.target.kind.startsWith('Persistent')) throw new Error('delete-storage requires PV or PVC');
    if (plan.target.namespace === 'backups') throw new Error('backup storage is immutable');
  }

  const canonical = canonicalPlan(plan);
  return {
    plan,
    lane,
    canonical,
    digest: createHash('sha256').update(canonical).digest('hex'),
    automaticWriteCap,
  };
}
