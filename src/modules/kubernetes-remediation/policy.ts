import { createHash } from 'node:crypto';
import { parseAllDocuments } from 'yaml';

import type {
  HelmBinding,
  KnownKind,
  RemediationLane,
  RemediationPlan,
  TargetRef,
  ValidatedPlan,
  ValuesEdit,
  ValuesScalar,
  ValuesValue,
} from './types.js';

/** Every write here needs approval and runs as the break-glass identity. */
export const LANE_C_NAMESPACES = new Set(['kube-system', 'longhorn-system']);
/** Every change here needs approval ("ask first"). Every other namespace is Lane A. */
const ALWAYS_ASK_NAMESPACES = new Set(['wireguard-home']);

const API_VERSIONS: Record<KnownKind, string> = {
  Deployment: 'apps/v1',
  StatefulSet: 'apps/v1',
  DaemonSet: 'apps/v1',
  CronJob: 'batch/v1',
  Job: 'batch/v1',
  PersistentVolume: 'v1',
  PersistentVolumeClaim: 'v1',
  Secret: 'v1',
  Pod: 'v1',
  Volume: 'longhorn.io/v1beta2',
  VolumeAttachment: 'longhorn.io/v1beta2',
  Snapshot: 'longhorn.io/v1beta2',
};
const WORKLOAD_KINDS = ['Deployment', 'StatefulSet', 'DaemonSet'];
const IMAGE_KINDS = [...WORKLOAD_KINDS, 'CronJob'];

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DIGEST_IMAGE_RE =
  /^(docker\.io|docker\.gitea\.com|cr\.fluentbit\.io|ghcr\.io|quay\.io|registry\.k8s\.io|mirror\.gcr\.io|lscr\.io|registry\.prophet\.jopdorp\.nl|gitea\.claw\.jopdorp\.nl)\/[a-z0-9]+(?:[._/-][a-z0-9]+)*@sha256:[0-9a-f]{64}$/;
const TAG_RE = /^\w[\w.-]{0,127}$/;
const CHART_REPO_RE = /^(?:https|oci):\/\/[A-Za-z0-9.-]+(?::\d+)?(?:\/[\w.~%-]+)*\/?$/;
const VALUES_PATH_RE = /^(?:[\w-]|\\\.)+(?:\.(?:[\w-]|\\\.)+)*$/;
const IMAGE_KEY_RE = /(?:^|(?<!\\)\.)(image|repository|registry|tag|digest|sha)$/;
// Only the chart's own top-level key; nested ones usually size a subchart's database StatefulSet.
const REPLICA_KEY_RE = /^(replicas|replicaCount)$/;
const PINNED_RE = /^(?:\w[\w.-]{0,127}@)?sha256:[0-9a-f]{64}$/;
const MANIFEST_FILE_RE = /^kubernetes\/(?:[\w-][\w.-]*\/)*[\w-][\w.-]*\.ya?ml$/;
const REPO_MANIFEST_RE = /^kubernetes\/(?:[\w-][\w.-]*\/)*[\w-][\w.-]*\.(?:ya?ml|json)$/;
const REPO_FILE_RE = /^(?:(?:kubernetes|\.gitea)\/[\w.-]+(?:\/[\w.-]+)*|(?:renovate|\.renovaterc)\.json)$/;
const VALUES_FILE_RE = /^kubernetes\/helm-charts\/[\w-][\w.-]*\.ya?ml$/;
const CHART_RE = /^[a-z0-9][a-z0-9_.-]{0,62}$/;
const CHART_VERSION_RE = /^v?\d+\.\d+\.\d+[\w.+-]*$/;
// Values under such keys may be credentials, but a key that names or points at a Secret holds none.
export const SECRET_KEY_RE = /password|passwd|token|secret|apikey|api_key|credential|private_?key/i;
const SECRET_REFERENCE_RE = /(?:name|ref|file|path)$|^existingsecret/i;
const REPO_PATH_RE = /^[\w-][\w.-]*(?:\/[\w-][\w.-]*)*$/;
const BUILD_IMAGE_RE =
  /^(?:registry\.prophet\.jopdorp\.nl|gitea\.claw\.jopdorp\.nl)\/[a-z0-9]+(?:[._/-][a-z0-9]+)*:\w[\w.-]{0,127}$/;
const DNS_LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,50}[a-z0-9])?$/;
const RELEASE_NAME_RE = /^[a-z0-9](?:[a-z0-9-]{0,51}[a-z0-9])?$/;
const API_VERSION_RE = /^(?:[a-z0-9.-]+\/)?v\d+(?:(?:alpha|beta)\d+)?$/;

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

const VALUE_MAX = 65536;

function scalar(value: unknown, label: string): ValuesScalar {
  if (typeof value === 'boolean' || (typeof value === 'number' && Number.isFinite(value))) return value;
  return string(value, label, VALUE_MAX);
}

function valuesValue(value: unknown, label: string): ValuesValue {
  if (value === null || typeof value !== 'object') return scalar(value, label);
  const serialized = JSON.stringify(value);
  if (!serialized || serialized.length > VALUE_MAX)
    throw new Error(`${label} must be a YAML value no longer than ${VALUE_MAX} characters`);
  return value as ValuesValue;
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[], label: string): void {
  const allowed = new Set(keys);
  const extra = Object.keys(value).find((key) => !allowed.has(key));
  if (extra) throw new Error(`${label}.${extra} is not allowed`);
}

/** A manifest target may be any kind, cluster-scoped ones included. */
function targetFrom(value: unknown, manifest: boolean): TargetRef {
  const input = record(value, 'target');
  exactKeys(input, ['apiVersion', 'kind', 'namespace', 'name', 'uid', 'resourceVersion'], 'target');
  const kind = string(input.kind, 'target.kind', 63);
  const apiVersion = string(input.apiVersion, 'target.apiVersion', 128);
  const namespace = input.namespace === null ? null : string(input.namespace, 'target.namespace', 63);
  if (manifest) {
    if (!/^[A-Z][A-Za-z0-9]*$/.test(kind) || !API_VERSION_RE.test(apiVersion))
      throw new Error('target.kind and target.apiVersion must name a Kubernetes kind');
  } else {
    if (!Object.hasOwn(API_VERSIONS, kind)) throw new Error('target.kind is unsupported');
    if (apiVersion !== API_VERSIONS[kind as KnownKind]) throw new Error('target.apiVersion does not match target.kind');
    if ((kind === 'PersistentVolume') !== (namespace === null))
      throw new Error('only PersistentVolume targets may omit namespace');
  }
  return {
    apiVersion,
    kind,
    namespace,
    name: string(input.name, 'target.name', 253),
    uid: string(input.uid, 'target.uid', 128),
    resourceVersion: string(input.resourceVersion, 'target.resourceVersion', 128),
  };
}

export function parseRemediationPlan(value: unknown): RemediationPlan {
  const input = record(value, 'plan');
  exactKeys(
    input,
    ['schemaVersion', 'id', 'incidentIds', 'target', 'reason', 'expiresAt', 'operation', 'commitOnly'],
    'plan',
  );
  if (input.schemaVersion !== 1) throw new Error('plan.schemaVersion must be 1');
  const id = string(input.id, 'plan.id', 36);
  if (!UUID_RE.test(id)) throw new Error('plan.id must be a lowercase UUID');
  if (!Array.isArray(input.incidentIds) || input.incidentIds.length === 0 || input.incidentIds.length > 32) {
    throw new Error('plan.incidentIds must contain 1 through 32 IDs');
  }
  const incidentIds = input.incidentIds.map((entry, index) => string(entry, `plan.incidentIds[${index}]`, 256));
  if (new Set(incidentIds).size !== incidentIds.length) throw new Error('plan.incidentIds must be unique');
  const operation = record(input.operation, 'plan.operation');
  const type = string(operation.type, 'plan.operation.type');
  const gitOps = ['helm-values', 'helm-sync-values', 'manifest-edit', 'manifest-sync', 'repo-write'];
  if (input.commitOnly !== undefined && (input.commitOnly !== true || !gitOps.includes(type)))
    throw new Error(`plan.commitOnly must be true and only on ${gitOps.join(', ')}`);
  const base = {
    schemaVersion: 1 as const,
    id,
    incidentIds,
    target: targetFrom(input.target, ['manifest-edit', 'manifest-sync', 'repo-write'].includes(type)),
    reason: string(input.reason, 'plan.reason', 2000),
    expiresAt: string(input.expiresAt, 'plan.expiresAt', 64),
    ...(input.commitOnly ? { commitOnly: true as const } : {}),
  };
  const runningDigest = () => {
    if (operation.runningDigest === undefined) return {};
    const digest = string(operation.runningDigest, 'plan.operation.runningDigest', 71);
    if (!/^sha256:[0-9a-f]{64}$/.test(digest)) throw new Error('plan.operation.runningDigest must be a sha256 digest');
    return { runningDigest: digest };
  };
  if (type === 'patch-image') {
    exactKeys(operation, ['type', 'containers', 'before', 'after', 'runningDigest'], 'plan.operation');
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
        before: string(operation.before, 'plan.operation.before', VALUE_MAX),
        after: string(operation.after, 'plan.operation.after', VALUE_MAX),
        ...runningDigest(),
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
  const valuesFile = () => {
    const file =
      operation.file === undefined
        ? `kubernetes/helm-charts/${base.target.name}-values.yaml`
        : string(operation.file, 'plan.operation.file', 256);
    if (!VALUES_FILE_RE.test(file)) throw new Error('plan.operation.file must be a kubernetes/helm-charts/*.yaml file');
    return file;
  };
  if (type === 'helm-sync-values') {
    exactKeys(operation, ['type', 'file'], 'plan.operation');
    return { ...base, operation: { type, file: valuesFile() } };
  }
  if (type === 'write-secret') {
    exactKeys(operation, ['type', 'secretType', 'stringData'], 'plan.operation');
    const stringData = record(operation.stringData, 'plan.operation.stringData');
    const entries = Object.entries(stringData);
    if (
      !entries.length ||
      entries.length > 64 ||
      entries.some(
        ([key, value]) => !/^[-._a-zA-Z0-9]{1,253}$/.test(key) || typeof value !== 'string' || value.length > 65536,
      )
    )
      throw new Error('plan.operation.stringData must map 1 through 64 Secret keys to strings');
    const secretType =
      operation.secretType === undefined ? 'Opaque' : string(operation.secretType, 'plan.operation.secretType', 128);
    if (secretType === 'kubernetes.io/service-account-token')
      throw new Error('ServiceAccount tokens are minted by Kubernetes, not written');
    return { ...base, operation: { type, secretType, stringData: stringData as Record<string, string> } };
  }
  if (type === 'delete-snapshot') {
    exactKeys(operation, ['type', 'volume'], 'plan.operation');
    return { ...base, operation: { type, volume: string(operation.volume, 'plan.operation.volume', 253) } };
  }
  if (type === 'remove-attachment-ticket') {
    exactKeys(operation, ['type', 'ticket'], 'plan.operation');
    const ticket = string(operation.ticket, 'plan.operation.ticket', 253);
    if (!ticket.startsWith('backup-controller-'))
      throw new Error('only backup-controller-* attachment tickets with a completed Backup may be removed');
    return { ...base, operation: { type, ticket } };
  }
  if (type === 'helm-uninstall') {
    exactKeys(operation, ['type'], 'plan.operation');
    return { ...base, operation: { type } };
  }
  if (type === 'helm-install') {
    exactKeys(operation, ['type', 'chart', 'repo', 'version', 'file'], 'plan.operation');
    const [chart, repo, version] = [
      string(operation.chart, 'plan.operation.chart', 63),
      string(operation.repo, 'plan.operation.repo', 512),
      string(operation.version, 'plan.operation.version', 64),
    ];
    if (!CHART_RE.test(chart) || !CHART_REPO_RE.test(repo) || !CHART_VERSION_RE.test(version))
      throw new Error('plan.operation needs a chart name, an https:// or oci:// repo and an exact chart version');
    return { ...base, operation: { type, chart, repo, version, file: valuesFile() } };
  }
  if (type === 'repo-write') {
    exactKeys(operation, ['type', 'path', 'content'], 'plan.operation');
    const file = string(operation.path, 'plan.operation.path', 256);
    if (!REPO_FILE_RE.test(file) || file.split('/').includes('..') || base.target.name !== file)
      throw new Error(
        'plan.operation.path must be under kubernetes/** or .gitea/**, or be a Renovate config; .git/** is refused, and target.name must match',
      );
    return {
      ...base,
      ...(!REPO_MANIFEST_RE.test(file) ? { commitOnly: true as const } : {}),
      operation: { type, path: file, content: string(operation.content, 'plan.operation.content', 256 * 1024) },
    };
  }
  if (type === 'helm-values') {
    exactKeys(operation, ['type', 'file', 'chart', 'set'], 'plan.operation');
    const file = valuesFile();
    let chart: { repo: string } | undefined;
    if (operation.chart !== undefined) {
      const input = record(operation.chart, 'plan.operation.chart');
      exactKeys(input, ['repo'], 'plan.operation.chart');
      const repo = string(input.repo, 'plan.operation.chart.repo', 512);
      if (!CHART_REPO_RE.test(repo)) throw new Error('plan.operation.chart.repo must be an https:// or oci:// URL');
      chart = { repo };
    }
    return { ...base, operation: { type, file, ...(chart ? { chart } : {}), set: editsFrom(operation.set) } };
  }
  if (type === 'manifest-edit' || type === 'manifest-sync') {
    exactKeys(
      operation,
      type === 'manifest-edit' ? ['type', 'file', 'set', 'runningDigest'] : ['type', 'file'],
      'plan.operation',
    );
    const file = string(operation.file, 'plan.operation.file', 256);
    if (!MANIFEST_FILE_RE.test(file) || file.split('/').includes('..'))
      throw new Error('plan.operation.file must be a kubernetes/**.yaml path in k8s.jegor.nl');
    return type === 'manifest-edit'
      ? { ...base, operation: { type, file, set: editsFrom(operation.set), ...runningDigest() } }
      : { ...base, operation: { type, file } };
  }
  if (type === 'pod-exec') {
    exactKeys(operation, ['type', 'container', 'command'], 'plan.operation');
    if (!Array.isArray(operation.command) || operation.command.length === 0 || operation.command.length > 64)
      throw new Error('plan.operation.command must be an argv of 1 through 64 strings');
    const command = operation.command.map((arg, index) => string(arg, `plan.operation.command[${index}]`, 4096));
    const container = string(operation.container, 'plan.operation.container', 63);
    return { ...base, operation: { type, container, command } };
  }
  if (type === 'build-image') {
    exactKeys(operation, ['type', 'dockerfile', 'context', 'image'], 'plan.operation');
    const dockerfile = string(operation.dockerfile, 'plan.operation.dockerfile', 256);
    const context = string(operation.context, 'plan.operation.context', 256);
    const clean = (p: string) => REPO_PATH_RE.test(p) && !p.split('/').includes('..');
    if (!clean(dockerfile) || !clean(context) || !dockerfile.startsWith(`${context}/`))
      throw new Error('plan.operation.dockerfile must be a k8s.jegor.nl path inside plan.operation.context');
    const image = string(operation.image, 'plan.operation.image', 256);
    if (!BUILD_IMAGE_RE.test(image))
      throw new Error(
        'plan.operation.image must be <registry.prophet.jopdorp.nl or gitea.claw.jopdorp.nl>/<name>:<tag>',
      );
    return { ...base, operation: { type, dockerfile, context, image } };
  }
  throw new Error(
    'plan.operation.type is unsupported; use patch-image, restart, scale, delete-job, delete-storage, helm-values, helm-sync-values, helm-install, helm-uninstall, delete-snapshot, remove-attachment-ticket, write-secret, pod-exec, manifest-edit, manifest-sync, repo-write or build-image',
  );
}

function editsFrom(value: unknown): ValuesEdit[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > 8) {
    throw new Error('plan.operation.set must contain 1 through 8 edits');
  }
  const set = value.map((entry, index) => {
    const edit = record(entry, `plan.operation.set[${index}]`);
    exactKeys(edit, ['path', 'before', 'after'], `plan.operation.set[${index}]`);
    const path = string(edit.path, `plan.operation.set[${index}].path`, 256);
    if (!VALUES_PATH_RE.test(path)) throw new Error(`plan.operation.set[${index}].path must be a dotted values path`);
    return {
      path,
      before: edit.before === null ? null : valuesValue(edit.before, `plan.operation.set[${index}].before`),
      after: edit.after === null ? null : valuesValue(edit.after, `plan.operation.set[${index}].after`),
    };
  });
  if (new Set(set.map((edit) => edit.path)).size !== set.length)
    throw new Error('plan.operation.set paths must be unique');
  return set;
}

/** Helm --set paths, where `\.` is a literal dot inside a key. */
export const valuesKeys = (path: string) =>
  path.split(/(?<!\\)\./).map((key) => (/^\d+$/.test(key) ? Number(key) : key.replaceAll('\\.', '.')));

export function secretKeys(value: unknown, prefix = ''): string[] {
  if (!value || typeof value !== 'object') return [];
  return Object.entries(value).flatMap(([key, child]) => {
    if (SECRET_REFERENCE_RE.test(key)) return [];
    const at = prefix ? `${prefix}.${key}` : key;
    // A key named `key` (tolerations, matchExpressions, secretKeyRef) is a credential only under a secret-looking parent.
    const secretKey = SECRET_KEY_RE.test(key) || (/^key$/i.test(key) && SECRET_KEY_RE.test(prefix));
    const own = secretKey && typeof child === 'string' && child !== '';
    return [...(own ? [at] : []), ...secretKeys(child, at)];
  });
}

/** env entries that carry a secret-looking value inline. */
export function inlineSecrets(value: unknown, at = ''): string[] {
  if (!value || typeof value !== 'object') return [];
  const node = value as Record<string, unknown>;
  const own =
    typeof node.name === 'string' && typeof node.value === 'string' && SECRET_KEY_RE.test(node.name) ? [at] : [];
  return [...own, ...Object.entries(node).flatMap(([k, v]) => inlineSecrets(v, at ? `${at}.${k}` : k))];
}

/** The Kubernetes objects of a repo-write file, after the public-repo secret checks. */
export function repoObjects(
  content: string,
): Array<{ apiVersion: string; kind: string; metadata?: { name?: string; namespace?: string } }> {
  const docs = parseAllDocuments(content);
  const values = (Array.isArray(docs) ? docs : [docs]).map((doc) => {
    if (doc.errors.length) throw new Error(`content does not parse: ${doc.errors[0].message}`);
    return doc.toJS() as unknown;
  });
  const secrets = values.flatMap((value) => [...secretKeys(value), ...inlineSecrets(value)]);
  if (secrets.length)
    throw new Error(`secret-looking values at ${secrets.join(', ')}; reference a Secret by name instead`);
  const objects = values.filter(
    (value): value is { apiVersion: string; kind: string } =>
      !!value && typeof value === 'object' && 'apiVersion' in value && 'kind' in value,
  );
  if (objects.some((object) => object.kind === 'Secret'))
    throw new Error('Secrets never go into the public k8s.jegor.nl repo');
  return objects;
}

export function classifyTarget(target: TargetRef): RemediationLane {
  if (target.kind === 'PersistentVolume' || target.kind === 'PersistentVolumeClaim') return 'always-ask';
  if (target.namespace && ALWAYS_ASK_NAMESPACES.has(target.namespace)) return 'always-ask';
  if (target.namespace && LANE_C_NAMESPACES.has(target.namespace)) return 'C';
  return 'A';
}

export function parseImage(image: string) {
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

export function checkImageUpdate(_beforeImage: string, afterImage: string): void {
  const after = parseImage(afterImage);
  if (
    !DIGEST_IMAGE_RE.test(`${after.registry}/${after.repository}@${after.digest}`) ||
    (after.tag !== undefined && !TAG_RE.test(after.tag))
  ) {
    throw new Error('new image is not an approved digest reference');
  }
}

/** The same bits: the digest `before` pins, or for a tag-only `before` the digest its pods run. */
function sameDigest(before: string, after: string, runningDigest?: string): boolean {
  const digest = parseImage(before).digest ?? runningDigest;
  return !!digest && digest === parseImage(after).digest;
}

export function imageRepository(image: string): string {
  const { registry, repository } = parseImage(image);
  return `${registry}/${repository}`;
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
  let lane = classifyTarget(plan.target);
  let automaticWriteCap: 0 | 1 | 2 = 0;
  const { namespace, name } = plan.target;
  if (
    namespace === 'backups' &&
    (plan.operation.type.startsWith('delete-') || plan.operation.type === 'helm-uninstall')
  )
    throw new Error('nothing in backups is ever deleted');

  if (plan.operation.type === 'patch-image') {
    if (!IMAGE_KINDS.includes(plan.target.kind)) throw new Error('patch-image requires a workload or CronJob target');
    checkImageUpdate(plan.operation.before, plan.operation.after);
    // The base admission policy rejects a rollback to a mutable tag unless the
    // pinned image was derived from exactly that tag. Any other rollout gets the
    // restart attempt only; a digest-pinned or exact-tag prior image may also
    // use the second, rollback write.
    const exactTag = plan.operation.after.startsWith(`${plan.operation.before}@sha256:`);
    if (lane === 'A' && plan.target.kind !== 'CronJob')
      automaticWriteCap = DIGEST_IMAGE_RE.test(plan.operation.before) || exactTag ? 2 : 1;
  } else if (plan.operation.type === 'restart') {
    if (!WORKLOAD_KINDS.includes(plan.target.kind)) throw new Error('restart requires a workload');
    if (!Number.isFinite(Date.parse(plan.operation.restartedAt)))
      throw new Error('restartedAt must be an ISO timestamp');
    if (lane === 'A') automaticWriteCap = 1;
  } else if (plan.operation.type === 'scale') {
    if (!['Deployment', 'StatefulSet'].includes(plan.target.kind))
      throw new Error('scale requires a Deployment or StatefulSet');
    if (plan.operation.before < 0 || plan.operation.after < 0) throw new Error('replicas must not be negative');
    if (lane === 'A') automaticWriteCap = 1;
  } else if (plan.operation.type === 'delete-job') {
    if (plan.target.kind !== 'Job') throw new Error('delete-job requires a Job');
  } else if (plan.operation.type === 'helm-values') {
    if (plan.target.kind !== 'Secret') throw new Error('helm-values requires a Helm release');
    // Charts pin in different shapes: tag@sha256, a sibling digest or sha key, or repository@sha256. The host
    // then checks the image the chart renders: pinned, and the same repository or the same digest.
    const planned = new Map(plan.operation.set.map((edit) => [edit.path, edit.after]));
    for (const { path, before, after } of plan.operation.set) {
      const key = IMAGE_KEY_RE.exec(path)?.[1];
      if (!key || key === 'registry' || key === 'repository') continue;
      const parent = path.slice(0, -key.length);
      const siblingPin = ['digest', 'sha'].some((k) => PINNED_RE.test(String(planned.get(`${parent}${k}`) ?? '')));
      const repositoryPin = /@sha256:[0-9a-f]{64}$/.test(String(planned.get(`${parent}repository`) ?? ''));
      if (key === 'image') {
        if (typeof before !== 'string' || typeof after !== 'string')
          throw new Error(`${path} must be an image reference`);
        checkImageUpdate(before, after);
      } else if (
        typeof after !== 'string' ||
        !(PINNED_RE.test(after) || (key === 'tag' && (siblingPin || repositoryPin)))
      )
        throw new Error(`${path} must pin a sha256 digest, in the tag or a sibling digest key`);
    }
  } else if (['helm-sync-values', 'helm-install', 'helm-uninstall'].includes(plan.operation.type)) {
    if (plan.target.kind !== 'Secret' || !namespace || !RELEASE_NAME_RE.test(name))
      throw new Error(`${plan.operation.type} requires a Helm release target`);
  } else if (plan.operation.type === 'repo-write') {
    const lanes = plan.commitOnly
      ? []
      : repoObjects(plan.operation.content).map((object) =>
          classifyTarget({ ...plan.target, kind: object.kind, namespace: object.metadata?.namespace ?? null }),
        );
    lane = lanes.includes('C') ? 'C' : lanes.includes('always-ask') ? 'always-ask' : 'A';
  } else if (plan.operation.type === 'delete-storage') {
    if (!['PersistentVolume', 'PersistentVolumeClaim', 'Volume'].includes(plan.target.kind))
      throw new Error('delete-storage requires a PV, PVC or Longhorn volume');
    if (plan.target.kind === 'Volume' && namespace !== 'longhorn-system')
      throw new Error('Longhorn volumes live in longhorn-system');
  } else if (plan.operation.type === 'write-secret') {
    if (plan.target.kind !== 'Secret' || !namespace) throw new Error('write-secret targets a namespaced v1 Secret');
  } else if (plan.operation.type === 'delete-snapshot') {
    if (plan.target.kind !== 'Snapshot' || namespace !== 'longhorn-system')
      throw new Error('delete-snapshot targets a Longhorn Snapshot in longhorn-system');
  } else if (plan.operation.type === 'remove-attachment-ticket') {
    if (plan.target.kind !== 'VolumeAttachment' || namespace !== 'longhorn-system')
      throw new Error('remove-attachment-ticket targets a Longhorn VolumeAttachment in longhorn-system');
  } else if (plan.operation.type === 'pod-exec') {
    if (plan.target.kind !== 'Pod') throw new Error('pod-exec requires a Pod');
  } else if (plan.operation.type === 'build-image') {
    if (plan.target.kind !== 'Job' || namespace !== 'security' || !DNS_LABEL_RE.test(name))
      throw new Error('build-image targets the build Job to create in security, named as a DNS label');
  } else {
    if (plan.target.kind === 'Secret') throw new Error('Secrets never go into the public k8s.jegor.nl repo');
    if (plan.operation.type === 'manifest-edit') {
      for (const { path, before, after } of plan.operation.set) {
        if (/(?:^|(?<!\\)\.)image$/.test(path)) {
          if (typeof before !== 'string' || typeof after !== 'string')
            throw new Error(`${path} must be an image reference`);
          checkImageUpdate(before, after);
        }
      }
    }
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

/** Same major, and for T1 also the same minor; a tag without a version (latest) or no tag at all passes only outside T1. */
function sameVersionLine(before: string | undefined, after: string | undefined, t1: boolean): boolean {
  const [from, to] = [tagVersion(before), tagVersion(after)];
  if (!from || !to) return !t1;
  return from[0] === to[0] && (!t1 || from[1] === to[1]);
}

/** The owner's standing yes: Traefik's own configuration applies without asking, in kube-system through break-glass. */
function traefikConfig({ apiVersion, kind, name, namespace }: Omit<TargetRef, 'uid' | 'resourceVersion'>): boolean {
  return (
    namespace === 'kube-system' &&
    (/^traefik\.(?:io|containo\.us)\//.test(apiVersion) ||
      (apiVersion === 'helm.cattle.io/v1' && kind === 'HelmChartConfig' && name === 'traefik'))
  );
}

export interface GrantEntry {
  op?: string;
  namespace?: string;
  target?: string;
}

/** The approver's standing yes, recorded by the host from his own message. */
export interface StandingGrant {
  scope: 'all' | GrantEntry[];
  except?: GrantEntry[];
  grantedBy: string;
  grantedAt: string;
  note: string;
}

/** The grant that covers this approval-class plan; never-rules were already enforced by validation. */
export function standingGrant({ plan }: ValidatedPlan, grants: StandingGrant[]): StandingGrant | undefined {
  const namespaces =
    plan.operation.type === 'repo-write' && !plan.commitOnly
      ? repoObjects(plan.operation.content).map((object) => object.metadata?.namespace ?? null)
      : [plan.target.namespace];
  const fits = (e: GrantEntry, namespace: string | null) =>
    (!e.op || e.op === plan.operation.type) &&
    (!e.target || e.target === plan.target.name) &&
    (!e.namespace || e.namespace === namespace);
  return grants.find(
    (grant) =>
      (grant.scope === 'all' || grant.scope.some((e) => namespaces.every((ns) => fits(e, ns)))) &&
      !(grant.except ?? []).some((e) => namespaces.some((ns) => fits(e, ns))),
  );
}

/**
 * Plans the host applies without a Matrix card; the approver still hears what ran.
 * `t1` holds `namespace` or `namespace/name` entries; every StatefulSet is T1 too.
 */
export function isAutoApproved(
  { lane, plan }: ValidatedPlan,
  t1: ReadonlySet<string>,
  helm?: Pick<HelmBinding, 'images' | 'statefulRepositories' | 'hasStatefulSet'>,
): boolean {
  const { target, operation } = plan;
  if (operation.type === 'helm-sync-values' || operation.type === 'manifest-sync') return true;
  if (lane === 'C') {
    const objects =
      operation.type === 'repo-write'
        ? repoObjects(operation.content).map(({ apiVersion, kind, metadata }) => ({
            apiVersion,
            kind,
            name: metadata?.name ?? '',
            namespace: metadata?.namespace ?? null,
          }))
        : operation.type === 'manifest-edit'
          ? [target]
          : [];
    return objects.length > 0 && objects.every(traefikConfig);
  }
  if (lane !== 'A') return false;
  const critical =
    target.kind === 'StatefulSet' || t1.has(target.namespace ?? '') || t1.has(`${target.namespace}/${target.name}`);
  if (
    ['restart', 'delete-job', 'pod-exec', 'build-image', 'helm-install', 'repo-write', 'write-secret'].includes(
      operation.type,
    )
  )
    return true;
  if (operation.type === 'manifest-edit') {
    return operation.set.every(({ path, before, after }) =>
      /(?:^|(?<!\\)\.)image$/.test(path)
        ? sameDigest(String(before), String(after), operation.runningDigest) ||
          sameVersionLine(parseImage(String(before)).tag, parseImage(String(after)).tag, critical)
        : path !== 'spec.replicas' || target.kind !== 'StatefulSet',
    );
  }
  if (operation.type === 'scale') return target.kind === 'Deployment';
  if (operation.type === 'patch-image')
    return (
      sameDigest(operation.before, operation.after, operation.runningDigest) ||
      sameVersionLine(parseImage(operation.before).tag, parseImage(operation.after).tag, critical)
    );
  if (operation.type !== 'helm-values' || !helm) return false;
  // Which workload a replica key sizes is chart-specific, so a release with a StatefulSet asks.
  const edits = operation.set.every(({ path }) =>
    REPLICA_KEY_RE.test(path) ? !critical && !helm.hasStatefulSet : IMAGE_KEY_RE.test(path),
  );
  return (
    edits &&
    Object.values(helm.images).every(({ before, after }) => {
      const strict = critical || helm.statefulRepositories.includes(imageRepository(after ?? ''));
      return (
        !!after &&
        !!before &&
        (sameDigest(before, after) || sameVersionLine(parseImage(before).tag, parseImage(after).tag, strict))
      );
    })
  );
}
