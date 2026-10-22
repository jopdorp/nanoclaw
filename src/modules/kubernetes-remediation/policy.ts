import { createHash } from 'node:crypto';

import type { RemediationLane, RemediationPlan, TargetRef, ValidatedPlan, ValuesScalar } from './types.js';

/** Every write here needs approval and runs as the break-glass identity. */
export const LANE_C_NAMESPACES = new Set(['kube-system', 'kube-node-lease', 'kube-public', 'longhorn-system']);

const API_VERSIONS: Record<TargetRef['kind'], TargetRef['apiVersion']> = {
  Deployment: 'apps/v1',
  StatefulSet: 'apps/v1',
  DaemonSet: 'apps/v1',
  CronJob: 'batch/v1',
  Job: 'batch/v1',
  PersistentVolume: 'v1',
  PersistentVolumeClaim: 'v1',
  Secret: 'v1',
};
const WORKLOAD_KINDS = ['Deployment', 'StatefulSet', 'DaemonSet'];
const IMAGE_KINDS = [...WORKLOAD_KINDS, 'CronJob'];

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DIGEST_IMAGE_RE =
  /^(docker\.io|docker\.gitea\.com|cr\.fluentbit\.io|ghcr\.io|quay\.io|registry\.k8s\.io|mirror\.gcr\.io|lscr\.io|registry\.prophet\.jopdorp\.nl)\/[a-z0-9]+(?:[._/-][a-z0-9]+)*@sha256:[0-9a-f]{64}$/;
const TAG_RE = /^\w[\w.-]{0,127}$/;
const VALUES_FILE_RE = /^kubernetes\/helm-charts\/[a-z0-9]+(?:-[a-z0-9]+)*-values\.yaml$/;
const VALUES_PATH_RE = /^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*$/;
const IMAGE_KEY_RE = /(?:^|\.)(image|repository|registry|tag|digest)$/;
// Only the chart's own top-level key; nested ones usually size a subchart's database StatefulSet.
const REPLICA_KEY_RE = /^(replicas|replicaCount)$/;
const PINNED_RE = /^(?:\w[\w.-]{0,127}@)?sha256:[0-9a-f]{64}$/;
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

function scalar(value: unknown, label: string): ValuesScalar {
  if (typeof value === 'boolean' || (typeof value === 'number' && Number.isFinite(value))) return value;
  return string(value, label, 1000);
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[], label: string): void {
  const allowed = new Set(keys);
  const extra = Object.keys(value).find((key) => !allowed.has(key));
  if (extra) throw new Error(`${label}.${extra} is not allowed`);
}

function targetFrom(value: unknown): TargetRef {
  const input = record(value, 'target');
  exactKeys(input, ['apiVersion', 'kind', 'namespace', 'name', 'uid', 'resourceVersion'], 'target');
  const kind = string(input.kind, 'target.kind') as TargetRef['kind'];
  if (!Object.hasOwn(API_VERSIONS, kind)) throw new Error('target.kind is unsupported');
  const apiVersion = string(input.apiVersion, 'target.apiVersion');
  if (apiVersion !== API_VERSIONS[kind]) throw new Error('target.apiVersion does not match target.kind');
  const namespace = input.namespace === null ? null : string(input.namespace, 'target.namespace', 63);
  if ((kind === 'PersistentVolume') !== (namespace === null)) {
    throw new Error('only PersistentVolume targets may omit namespace');
  }
  return {
    apiVersion: API_VERSIONS[kind],
    kind,
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
    exactKeys(operation, ['type', 'containers', 'before', 'after'], 'plan.operation');
    if (!Array.isArray(operation.containers) || operation.containers.length === 0 || operation.containers.length > 16) {
      throw new Error('plan.operation.containers must contain 1 through 16 entries');
    }
    const containers = operation.containers.map((entry, index) => {
      const container = record(entry, `plan.operation.containers[${index}]`);
      exactKeys(container, ['name', 'initContainer'], `plan.operation.containers[${index}]`);
      if (typeof container.initContainer !== 'boolean') {
        throw new Error(`plan.operation.containers[${index}].initContainer must be boolean`);
      }
      return {
        name: string(container.name, `plan.operation.containers[${index}].name`, 253),
        initContainer: container.initContainer,
      };
    });
    if (new Set(containers.map((c) => `${c.initContainer}/${c.name}`)).size !== containers.length) {
      throw new Error('plan.operation.containers must be unique');
    }
    return {
      ...base,
      operation: {
        type,
        containers,
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
  if (type === 'delete-job') {
    exactKeys(operation, ['type'], 'plan.operation');
    return { ...base, operation: { type } };
  }
  if (type === 'delete-storage') {
    exactKeys(operation, ['type', 'reclaimConfirmed'], 'plan.operation');
    if (operation.reclaimConfirmed !== true) throw new Error('storage deletion requires reclaimConfirmed=true');
    return { ...base, operation: { type, reclaimConfirmed: true } };
  }
  if (type === 'helm-values') {
    exactKeys(operation, ['type', 'file', 'set'], 'plan.operation');
    const file = string(operation.file, 'plan.operation.file', 256);
    if (!VALUES_FILE_RE.test(file))
      throw new Error('plan.operation.file must be kubernetes/helm-charts/<name>-values.yaml');
    if (!Array.isArray(operation.set) || operation.set.length === 0 || operation.set.length > 8) {
      throw new Error('plan.operation.set must contain 1 through 8 edits');
    }
    const set = operation.set.map((entry, index) => {
      const edit = record(entry, `plan.operation.set[${index}]`);
      exactKeys(edit, ['path', 'before', 'after'], `plan.operation.set[${index}]`);
      const path = string(edit.path, `plan.operation.set[${index}].path`, 256);
      if (!VALUES_PATH_RE.test(path)) throw new Error(`plan.operation.set[${index}].path must be a dotted values path`);
      return {
        path,
        before: edit.before === null ? null : scalar(edit.before, `plan.operation.set[${index}].before`),
        after: scalar(edit.after, `plan.operation.set[${index}].after`),
      };
    });
    if (new Set(set.map((edit) => edit.path)).size !== set.length)
      throw new Error('plan.operation.set paths must be unique');
    return { ...base, operation: { type, file, set } };
  }
  throw new Error(
    'plan.operation.type is unsupported; use patch-image, restart, scale, delete-job, delete-storage or helm-values',
  );
}

export function classifyTarget(target: TargetRef): RemediationLane {
  if (target.kind === 'PersistentVolume' || target.kind === 'PersistentVolumeClaim') return 'always-ask';
  if (target.namespace === 'vaultwarden' || target.namespace === 'wireguard-home') return 'always-ask';
  if (target.namespace && LANE_C_NAMESPACES.has(target.namespace)) return 'C';
  if (target.namespace === 'nanoclaw-remediator') throw new Error('Orfie never changes its own namespace');
  return 'A';
}

function parseImage(image: string) {
  const at = image.indexOf('@');
  const name = at < 0 ? image : image.slice(0, at);
  const digest = at < 0 ? undefined : image.slice(at + 1);
  const colon = name.lastIndexOf(':');
  const tag = colon > name.lastIndexOf('/') ? name.slice(colon + 1) : undefined;
  const path = tag === undefined ? name : name.slice(0, colon);
  const first = path.split('/')[0];
  const explicit = path.includes('/') && (first.includes('.') || first.includes(':') || first === 'localhost');
  const registry = !explicit || first === 'index.docker.io' ? 'docker.io' : first;
  const rest = explicit ? path.slice(first.length + 1) : path;
  const repository = registry === 'docker.io' && !rest.includes('/') ? `library/${rest}` : rest;
  return { registry, repository, tag, digest };
}

function checkImageUpdate(beforeImage: string, afterImage: string, expected: RegExp): void {
  const before = parseImage(beforeImage);
  const after = parseImage(afterImage);
  if (
    !expected.test(`${after.registry}/${after.repository}@${after.digest}`) ||
    (after.tag !== undefined && !TAG_RE.test(after.tag))
  ) {
    throw new Error('new image is not an approved digest reference');
  }
  if (`${before.registry}/${before.repository}` !== `${after.registry}/${after.repository}`) {
    throw new Error('image repository may not change');
  }
}

export function canonicalImage(image: string): string {
  const { registry, repository, tag, digest } = parseImage(image);
  return `${registry}/${repository}${tag === undefined ? '' : `:${tag}`}${digest === undefined ? '' : `@${digest}`}`;
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
  if (plan.target.namespace === 'backups' && !(plan.operation.type === 'patch-image' && plan.target.kind === 'CronJob'))
    throw new Error('backups is immutable except CronJob images');

  if (plan.operation.type === 'patch-image') {
    if (!IMAGE_KINDS.includes(plan.target.kind) || (lane === 'C' && plan.target.kind === 'CronJob')) {
      throw new Error('patch-image requires a workload target, or a CronJob outside Lane C');
    }
    const expected =
      plan.target.namespace === 'vaultwarden'
        ? VAULTWARDEN_RE
        : plan.target.namespace === 'wireguard-home'
          ? WIREGUARD_RE
          : DIGEST_IMAGE_RE;
    checkImageUpdate(plan.operation.before, plan.operation.after, expected);
    // The base admission policy rejects a rollback to a mutable tag unless the
    // pinned image was derived from exactly that tag. Any other rollout gets the
    // restart attempt only; a digest-pinned or exact-tag prior image may also
    // use the second, rollback write.
    const exactTag = plan.operation.after.startsWith(`${plan.operation.before}@sha256:`);
    if (lane === 'A' && plan.target.kind !== 'CronJob')
      automaticWriteCap = DIGEST_IMAGE_RE.test(plan.operation.before) || exactTag ? 2 : 1;
  } else if (plan.operation.type === 'restart') {
    if (lane === 'always-ask' || !WORKLOAD_KINDS.includes(plan.target.kind)) {
      throw new Error('restart requires a Lane A or Lane C workload');
    }
    if (!Number.isFinite(Date.parse(plan.operation.restartedAt)))
      throw new Error('restartedAt must be an ISO timestamp');
    if (lane === 'A') automaticWriteCap = 1;
  } else if (plan.operation.type === 'scale') {
    if (lane === 'always-ask' || !['Deployment', 'StatefulSet'].includes(plan.target.kind)) {
      throw new Error('scale requires a Lane A or Lane C Deployment or StatefulSet');
    }
    if (
      plan.operation.before < 0 ||
      plan.operation.before > 10 ||
      plan.operation.after < 0 ||
      plan.operation.after > 10
    ) {
      throw new Error('replicas must be between 0 and 10');
    }
    if (lane === 'A') automaticWriteCap = 1;
  } else if (plan.operation.type === 'delete-job') {
    if (lane !== 'A' || plan.target.kind !== 'Job') throw new Error('delete-job requires a Lane A Job');
  } else if (plan.operation.type === 'helm-values') {
    if (lane === 'always-ask' || plan.target.kind !== 'Secret')
      throw new Error('helm-values requires a Lane A or Lane C Helm release');
    for (const { path, before, after } of plan.operation.set) {
      const key = IMAGE_KEY_RE.exec(path)?.[1];
      if (!key) continue;
      if (key === 'repository' || key === 'registry') throw new Error(`${path}: image repository may not change`);
      if (typeof after !== 'string' || (key === 'image' ? typeof before !== 'string' : !PINNED_RE.test(after))) {
        throw new Error(`${path} must pin a sha256 digest of the same image repository`);
      }
      if (key === 'image') checkImageUpdate(before as string, after, DIGEST_IMAGE_RE);
    }
  } else if (plan.operation.type === 'delete-storage') {
    if (!plan.target.kind.startsWith('Persistent')) throw new Error('delete-storage requires PV or PVC');
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

function tagVersion(tag = ''): [number, number] | undefined {
  const match = /^v?(\d+)(?:\.(\d+)(?:[.+_-].*)?|[+_-].*)?$/.exec(tag.split('@')[0]);
  return match ? [Number(match[1]), Number(match[2] ?? 0)] : undefined;
}

/** Same major, and for T1 also the same minor; only an unversioned before (latest) may skip that outside T1, and a bare digest never passes. */
function sameVersionLine(before: string | undefined, after: string | undefined, t1: boolean): boolean {
  if (after === undefined || after.startsWith('sha256:')) return false;
  const [from, to] = [tagVersion(before), tagVersion(after)];
  if (!from || !to) return !t1 && !from;
  return from[0] === to[0] && (!t1 || from[1] === to[1]);
}

/**
 * Plans the host applies without a Matrix card; the approver still hears what ran.
 * `t1` holds `namespace` or `namespace/name` entries; every StatefulSet is T1 too.
 */
export function isAutoApproved({ lane, plan }: ValidatedPlan, t1: ReadonlySet<string>): boolean {
  if (lane !== 'A') return false;
  const { target, operation } = plan;
  const critical =
    target.kind === 'StatefulSet' || t1.has(target.namespace ?? '') || t1.has(`${target.namespace}/${target.name}`);
  if (operation.type === 'restart' || operation.type === 'delete-job') return true;
  if (operation.type === 'scale') return target.kind === 'Deployment';
  if (operation.type === 'patch-image')
    return sameVersionLine(parseImage(operation.before).tag, parseImage(operation.after).tag, critical);
  if (operation.type !== 'helm-values') return false;
  return operation.set.every(({ path, before, after }) => {
    if (REPLICA_KEY_RE.test(path)) return !critical;
    const key = IMAGE_KEY_RE.exec(path)?.[1];
    // A subchart image (postgresql.image.tag) usually runs a StatefulSet.
    const strict = critical || !/^(?:image\.)?[^.]+$/.test(path);
    if (key === 'digest') return operation.set.some((edit) => edit.path === path.replace(/digest$/, 'tag'));
    if (key === 'tag') return sameVersionLine(String(before ?? ''), String(after), strict);
    if (key === 'image') return sameVersionLine(parseImage(String(before)).tag, parseImage(String(after)).tag, strict);
    return false;
  });
}
