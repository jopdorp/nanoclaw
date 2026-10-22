import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';

import type { HelmReleaseExecutor } from './helm-release.js';
import { canonicalImage } from './policy.js';
import type { RegistryFetch } from './registry.js';
import type {
  ApprovalGrant,
  BuildImagePlan,
  ExecutionResult,
  HelmInstallPlan,
  HelmSyncPlan,
  HelmUninstallPlan,
  HelmValuesPlan,
  ManifestEditPlan,
  ManifestSyncPlan,
  PodExecPlan,
  RemediationPlan,
  RepoWritePlan,
  SnapshotDeletePlan,
  ValidatedPlan,
} from './types.js';

const APPROVAL_ANNOTATION = 'remediation.nanoclaw.io/approval-id';
// The gateway cannot carry the API's exec WebSocket, so exec runs in-cluster as a Job under the writer's account.
export const KUBECTL_IMAGE =
  'registry.k8s.io/kubectl:v1.35.9@sha256:436cbaa8a019152063d638f412cf9d73ec29e56061529d28cbc231c6ab1b37a4';
export const KANIKO_IMAGE =
  'gcr.io/kaniko-project/executor:v1.23.2@sha256:9e69fd4330ec887829c780f5126dd80edc663df6def362cd22e79bcdf00ac53f';
const OUTPUT_LIMIT = 2048;
const TEMPORARY_BINDING_RE = /^nanoclaw-remediation-[0-9a-f-]{36}$/;

export interface KubernetesJsonClient {
  /** `text` returns the raw body (pod logs) instead of parsed JSON. */
  request(
    path: string,
    options?: { method?: string; body?: unknown; contentType?: string; signal?: AbortSignal; text?: boolean },
  ): Promise<unknown>;
  watch(path: string, resourceVersion: string, signal: AbortSignal): AsyncIterable<unknown>;
}

interface CommandResult {
  stdout: string;
  stderr: string;
  code: number;
}

function run(
  executable: string,
  args: string[],
  options: { input?: string; signal?: AbortSignal } = {},
): Promise<CommandResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, { stdio: ['pipe', 'pipe', 'pipe'], signal: options.signal });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    child.stdout.on('data', (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on('data', (chunk: Buffer) => stderr.push(chunk));
    child.once('error', reject);
    child.once('close', (code) =>
      resolve({
        stdout: Buffer.concat(stdout).toString('utf8'),
        stderr: Buffer.concat(stderr).toString('utf8'),
        code: code ?? 1,
      }),
    );
    child.stdin.end(options.input);
  });
}

/**
 * Kubernetes requests travel through `onecli run`; the kubeconfig contains no
 * credential. OneCLI injects the assigned ServiceAccount bearer token at the
 * exact API authority, so neither this process nor the agent receives it.
 */
export class OneCliKubernetesClient implements KubernetesJsonClient {
  constructor(
    private readonly agent: string,
    private readonly apiServer: string,
    private readonly onecli = 'onecli',
  ) {}

  async request(
    path: string,
    options: { method?: string; body?: unknown; contentType?: string; signal?: AbortSignal; text?: boolean } = {},
  ): Promise<unknown> {
    const method = options.method ?? 'GET';
    const args = [
      'run',
      '--agent',
      this.agent,
      '--',
      'curl',
      '--silent',
      '--show-error',
      '--fail-with-body',
      '--request',
      method,
      '--header',
      'Accept: application/json',
    ];
    let input: string | undefined;
    if (options.body !== undefined) {
      input = JSON.stringify(options.body);
      args.push('--header', `Content-Type: ${options.contentType ?? 'application/json'}`, '--data-binary', '@-');
    }
    args.push(new URL(path, this.apiServer).toString());
    const result = await run(this.onecli, args, { input, signal: options.signal });
    if (result.code !== 0) {
      // curl --fail-with-body leaves the API Status, and with it the reason, on stdout.
      const status = result.stdout.trim().slice(-500);
      throw new Error(`Kubernetes gateway request failed: ${result.stderr.trim() || result.code} ${status}`.trim());
    }
    if (options.text) return result.stdout;
    return result.stdout.trim() ? JSON.parse(result.stdout) : null;
  }

  async *watch(path: string, resourceVersion: string, signal: AbortSignal): AsyncIterable<unknown> {
    const url = new URL(path, this.apiServer);
    url.searchParams.set('watch', '1');
    url.searchParams.set('allowWatchBookmarks', 'true');
    url.searchParams.set('resourceVersion', resourceVersion);
    const child = spawn(
      this.onecli,
      [
        'run',
        '--agent',
        this.agent,
        '--',
        'curl',
        '--silent',
        '--show-error',
        '--fail-with-body',
        '--no-buffer',
        '--header',
        'Accept: application/json',
        url.toString(),
      ],
      { stdio: ['ignore', 'pipe', 'pipe'], signal },
    );
    const completion = new Promise<number>((resolve, reject) => {
      child.once('error', reject);
      child.once('close', (value) => resolve(value ?? 1));
    });
    let stderr = '';
    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (chunk: string) => (stderr += chunk));
    for await (const line of createInterface({ input: child.stdout })) {
      if (line.trim()) yield JSON.parse(line);
    }
    const code = await completion;
    if (code !== 0 && !signal.aborted) throw new Error(`Kubernetes gateway watch failed: ${stderr.trim() || code}`);
  }
}

/** Registry reads through the gateway; the identity's only token is scoped to the API server, so nothing is injected. */
export function registryThroughOneCli(agent: string, onecli = 'onecli'): RegistryFetch {
  return async (url, headers) => {
    const args = ['run', '--agent', agent, '--', 'curl', '--silent', '--show-error', '--location'];
    args.push('--max-time', '20', '--suppress-connect-headers', '--dump-header', '-');
    for (const [name, value] of Object.entries(headers)) args.push('--header', `${name}: ${value}`);
    const { stdout, code, stderr } = await run(onecli, [...args, url]);
    if (code !== 0) throw new Error(`registry request failed: ${stderr.trim() || code}`);
    // One header block per redirect; the last one belongs to the body.
    let rest = stdout;
    let block = '';
    while (/^HTTP\/\S+ \d{3}/.test(rest)) {
      const end = rest.search(/\r?\n\r?\n/);
      block = end < 0 ? rest : rest.slice(0, end);
      rest = end < 0 ? '' : rest.slice(end).replace(/^\r?\n\r?\n/, '');
    }
    const [statusLine, ...lines] = block.split(/\r?\n/);
    return {
      status: Number(statusLine?.split(' ')[1] ?? 0),
      headers: Object.fromEntries(
        lines.map((line) => [
          line.slice(0, line.indexOf(':')).trim().toLowerCase(),
          line.slice(line.indexOf(':') + 1).trim(),
        ]),
      ),
      body: rest,
    };
  };
}

const WORKLOAD_COLLECTIONS: Partial<Record<RemediationPlan['target']['kind'], [string, string]>> = {
  Deployment: ['apps/v1', 'deployments'],
  StatefulSet: ['apps/v1', 'statefulsets'],
  DaemonSet: ['apps/v1', 'daemonsets'],
  CronJob: ['batch/v1', 'cronjobs'],
};

function workloadPath(plan: RemediationPlan): string {
  const collection = WORKLOAD_COLLECTIONS[plan.target.kind];
  if (!collection) throw new Error('target is not a workload');
  const [groupVersion, plural] = collection;
  return `/apis/${groupVersion}/namespaces/${encodeURIComponent(plan.target.namespace ?? '')}/${plural}/${encodeURIComponent(plan.target.name)}`;
}

function jobPath(plan: RemediationPlan): string {
  return `/apis/batch/v1/namespaces/${encodeURIComponent(plan.target.namespace ?? '')}/jobs/${encodeURIComponent(plan.target.name)}`;
}

function storagePath(plan: RemediationPlan): string {
  const name = encodeURIComponent(plan.target.name);
  const namespace = encodeURIComponent(plan.target.namespace ?? '');
  if (plan.target.kind === 'PersistentVolume') return `/api/v1/persistentvolumes/${name}`;
  if (plan.target.kind === 'Volume') return `/apis/longhorn.io/v1beta2/namespaces/${namespace}/volumes/${name}`;
  return `/api/v1/namespaces/${namespace}/persistentvolumeclaims/${name}`;
}

function runnerJob(plan: PodExecPlan, serviceAccount: string): Record<string, unknown> {
  const { container, command } = plan.operation;
  return {
    apiVersion: 'batch/v1',
    kind: 'Job',
    metadata: { name: `orfie-exec-${plan.id.slice(0, 8)}`, namespace: 'nanoclaw-remediator' },
    spec: {
      backoffLimit: 0,
      activeDeadlineSeconds: 600,
      ttlSecondsAfterFinished: 3600,
      template: {
        spec: {
          restartPolicy: 'Never',
          serviceAccountName: serviceAccount,
          automountServiceAccountToken: true,
          securityContext: { runAsNonRoot: true, runAsUser: 65532, seccompProfile: { type: 'RuntimeDefault' } },
          containers: [
            {
              name: 'exec',
              image: KUBECTL_IMAGE,
              args: ['exec', '-n', plan.target.namespace, plan.target.name, '-c', container, '--', ...command],
              env: [{ name: 'HOME', value: '/tmp' }],
              volumeMounts: [{ name: 'tmp', mountPath: '/tmp' }],
              securityContext: {
                allowPrivilegeEscalation: false,
                readOnlyRootFilesystem: true,
                capabilities: { drop: ['ALL'] },
              },
            },
          ],
          volumes: [{ name: 'tmp', emptyDir: {} }],
        },
      },
    },
  };
}

function kanikoJob(plan: BuildImagePlan, pushSecret: string): Record<string, unknown> {
  const { dockerfile, context, image } = plan.operation;
  return {
    apiVersion: 'batch/v1',
    kind: 'Job',
    metadata: { name: plan.target.name, namespace: 'security' },
    spec: {
      backoffLimit: 0,
      activeDeadlineSeconds: 1800,
      ttlSecondsAfterFinished: 86400,
      template: {
        spec: {
          restartPolicy: 'Never',
          automountServiceAccountToken: false,
          containers: [
            {
              name: 'kaniko',
              image: KANIKO_IMAGE,
              args: [
                '--context=git://github.com/jopdorp/k8s.jegor.nl.git#refs/heads/master',
                `--context-sub-path=${context}`,
                `--dockerfile=${dockerfile.slice(context.length + 1)}`,
                `--destination=${image}`,
                '--digest-file=/dev/termination-log',
              ],
              volumeMounts: [{ name: 'docker', mountPath: '/kaniko/.docker' }],
            },
          ],
          volumes: [
            {
              name: 'docker',
              secret: { secretName: pushSecret, items: [{ key: '.dockerconfigjson', path: 'config.json' }] },
            },
          ],
        },
      },
    },
  };
}

function mergePatch(plan: RemediationPlan): Record<string, unknown> {
  const resourceVersion = plan.target.resourceVersion;
  if (plan.operation.type === 'patch-image') {
    const { containers, after } = plan.operation;
    const images = (init: boolean) =>
      containers.filter((c) => c.initContainer === init).map(({ name }) => ({ name, image: after }));
    const spec = { containers: images(false), initContainers: images(true) };
    const template = { spec: Object.fromEntries(Object.entries(spec).filter(([, list]) => list.length)) };
    return {
      metadata: { resourceVersion },
      spec: plan.target.kind === 'CronJob' ? { jobTemplate: { spec: { template } } } : { template },
    };
  }
  if (plan.operation.type === 'restart') {
    return {
      metadata: { resourceVersion },
      spec: {
        template: { metadata: { annotations: { 'kubectl.kubernetes.io/restartedAt': plan.operation.restartedAt } } },
      },
    };
  }
  if (plan.operation.type === 'scale')
    return { metadata: { resourceVersion }, spec: { replicas: plan.operation.after } };
  throw new Error('operation has no workload patch');
}

function approvalAnnotationPatch(plan: RemediationPlan, value: string | null): Record<string, unknown> {
  return {
    metadata: {
      resourceVersion: plan.target.resourceVersion,
      annotations: { [APPROVAL_ANNOTATION]: value },
    },
  };
}

interface PodTemplateHolder {
  template?: { spec?: Partial<Record<'containers' | 'initContainers', Array<{ name?: string; image?: string }>>> };
}

interface LiveObject {
  metadata?: { uid?: string; resourceVersion?: string };
  spec?: PodTemplateHolder & { jobTemplate?: { spec?: PodTemplateHolder }; claimRef?: { namespace?: string } };
  status?: {
    active?: number;
    conditions?: Array<{ type?: string; status?: string }>;
    kubernetesStatus?: { namespace?: string };
  };
}

interface ListedObject {
  metadata?: {
    annotations?: Record<string, string>;
    name?: string;
    namespace?: string;
    resourceVersion?: string;
  };
}

async function listed(client: KubernetesJsonClient, path: string): Promise<ListedObject[]> {
  const value = (await client.request(path)) as { items?: unknown[] };
  return Array.isArray(value.items) ? (value.items as ListedObject[]) : [];
}

/** Remove capabilities left by a host crash before accepting new work. */
export async function cleanupRemediationOrphans(annotator: KubernetesJsonClient): Promise<number> {
  const cleanups: Promise<unknown>[] = [];
  for (const [collection, namespaced] of [
    ['/apis/rbac.authorization.k8s.io/v1/clusterrolebindings', false],
    ['/apis/rbac.authorization.k8s.io/v1/rolebindings', true],
  ] as const) {
    for (const item of await listed(annotator, collection)) {
      const { name, namespace } = item.metadata ?? {};
      if (!name || !TEMPORARY_BINDING_RE.test(name) || (namespaced && !namespace)) continue;
      const path = namespaced
        ? `/apis/rbac.authorization.k8s.io/v1/namespaces/${encodeURIComponent(namespace!)}/rolebindings/${encodeURIComponent(name)}`
        : `${collection}/${encodeURIComponent(name)}`;
      cleanups.push(annotator.request(path, { method: 'DELETE' }));
    }
  }
  for (const [collection, namespaced] of [
    ['/apis/apps/v1/deployments', true],
    ['/apis/apps/v1/statefulsets', true],
    ['/apis/apps/v1/daemonsets', true],
    ['/apis/batch/v1/cronjobs', true],
    ['/apis/batch/v1/jobs', true],
    ['/api/v1/persistentvolumeclaims', true],
    ['/api/v1/persistentvolumes', false],
  ] as const) {
    for (const item of await listed(annotator, collection)) {
      const { annotations, name, namespace, resourceVersion } = item.metadata ?? {};
      if (!annotations?.[APPROVAL_ANNOTATION] || !name || !resourceVersion || (namespaced && !namespace)) continue;
      const path = namespaced
        ? `${collection.replace(/\/[^/]+$/, '')}/namespaces/${encodeURIComponent(namespace!)}/${collection.split('/').at(-1)}/${encodeURIComponent(name)}`
        : `${collection}/${encodeURIComponent(name)}`;
      cleanups.push(
        annotator.request(path, {
          method: 'PATCH',
          body: { metadata: { resourceVersion, annotations: { [APPROVAL_ANNOTATION]: null } } },
          contentType: 'application/merge-patch+json',
        }),
      );
    }
  }
  const results = await Promise.allSettled(cleanups);
  const failed = results.filter((result): result is PromiseRejectedResult => result.status === 'rejected');
  if (failed.length)
    throw new AggregateError(
      failed.map(({ reason }) => reason),
      'orphan cleanup failed',
    );
  return cleanups.length;
}

function binding(plan: RemediationPlan): { collection: string; path: string; body: Record<string, unknown> } {
  const name = `nanoclaw-remediation-${plan.id}`;
  const cluster = plan.target.kind === 'PersistentVolume';
  const collection = cluster
    ? '/apis/rbac.authorization.k8s.io/v1/clusterrolebindings'
    : `/apis/rbac.authorization.k8s.io/v1/namespaces/${encodeURIComponent(plan.target.namespace ?? '')}/rolebindings`;
  return {
    collection,
    path: `${collection}/${name}`,
    body: {
      apiVersion: 'rbac.authorization.k8s.io/v1',
      kind: cluster ? 'ClusterRoleBinding' : 'RoleBinding',
      metadata: { name, ...(cluster ? {} : { namespace: plan.target.namespace }) },
      roleRef: {
        apiGroup: 'rbac.authorization.k8s.io',
        kind: 'ClusterRole',
        name: cluster
          ? 'nanoclaw-remediator-human-approved-pv-delete'
          : 'nanoclaw-remediator-human-approved-pvc-delete',
      },
      subjects: [{ kind: 'ServiceAccount', name: 'nanoclaw-remediator', namespace: 'nanoclaw-remediator' }],
    },
  };
}

export interface RolloutObserver {
  ready(plan: RemediationPlan, deadline: number): Promise<boolean>;
}

function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

export class KubernetesRolloutObserver implements RolloutObserver {
  constructor(private readonly client: KubernetesJsonClient) {}
  async ready(plan: RemediationPlan, deadline: number): Promise<boolean> {
    const path = workloadPath(plan);
    while (Date.now() < deadline) {
      const object = (await this.client.request(path)) as {
        metadata?: { generation?: number };
        spec?: { replicas?: number };
        status?: Record<string, unknown>;
      };
      const generation = object.metadata?.generation ?? 0;
      const observed = Number(object.status?.observedGeneration ?? 0);
      const desired =
        plan.target.kind === 'DaemonSet'
          ? Number(object.status?.desiredNumberScheduled ?? 0)
          : (object.spec?.replicas ?? 1);
      const ready =
        plan.target.kind === 'DaemonSet'
          ? Number(object.status?.numberReady ?? 0)
          : Number(object.status?.readyReplicas ?? 0);
      const revisionReady =
        plan.target.kind !== 'StatefulSet' || object.status?.currentRevision === object.status?.updateRevision;
      if (observed >= generation && ready === desired && revisionReady) return true;
      await sleep(Math.min(5_000, Math.max(0, deadline - Date.now())));
    }
    return false;
  }
}

/** Host-only executor. The agent is never given any of these OneCLI identities. */
export class GatewayRemediationExecutor {
  constructor(
    private readonly writer: KubernetesJsonClient,
    private readonly annotator: KubernetesJsonClient,
    private readonly observer: RolloutObserver,
    private readonly helm?: HelmReleaseExecutor,
    private readonly breakGlass?: { client: KubernetesJsonClient; helm?: HelmReleaseExecutor },
    private readonly build = { registry: 'registry.prophet.jopdorp.nl', pushSecret: 'registry-prophet' },
  ) {}

  async execute(validated: ValidatedPlan, grant: ApprovalGrant) {
    const { plan, lane } = validated;
    if (grant.planId !== plan.id || grant.planDigest !== validated.digest)
      throw new Error('approval does not bind this plan');
    if (Date.parse(plan.expiresAt) <= Date.now()) throw new Error('approved plan expired');
    const executor = lane === 'C' ? this.breakGlass?.client : this.writer;
    if (!executor) throw new Error('the break-glass identity is not configured');
    const repo = lane === 'C' ? this.breakGlass?.helm : this.helm;
    switch (plan.operation.type) {
      case 'helm-values':
      case 'helm-sync-values':
      case 'manifest-edit':
      case 'manifest-sync':
      case 'helm-install':
      case 'helm-uninstall':
      case 'repo-write':
        if (!repo) throw new Error('the Helm and manifest path is not configured');
        if (plan.operation.type === 'helm-install') return repo.install(plan as HelmInstallPlan);
        if (plan.operation.type === 'helm-uninstall') return repo.uninstall(plan as HelmUninstallPlan);
        if (plan.operation.type === 'repo-write') return repo.writeFile(plan as RepoWritePlan);
        if (plan.operation.type === 'helm-values') return repo.apply(plan as HelmValuesPlan);
        if (plan.operation.type === 'helm-sync-values') return repo.syncValues(plan as HelmSyncPlan);
        if (plan.operation.type === 'manifest-edit') return repo.applyManifest(plan as ManifestEditPlan);
        return repo.syncManifest(plan as ManifestSyncPlan);
      case 'pod-exec':
        return this.podExec(plan as PodExecPlan, lane === 'C' ? 'nanoclaw-breakglass' : 'nanoclaw-remediator');
      case 'build-image':
        return this.buildImage(plan as BuildImagePlan);
      case 'delete-snapshot':
        return this.deleteSnapshot(plan as SnapshotDeletePlan, executor);
    }

    const path =
      plan.operation.type === 'delete-storage'
        ? storagePath(plan)
        : plan.operation.type === 'delete-job'
          ? jobPath(plan)
          : workloadPath(plan);
    const live = (await executor.request(path)) as LiveObject;
    if (live.metadata?.uid !== plan.target.uid || live.metadata?.resourceVersion !== plan.target.resourceVersion) {
      throw new Error('target UID or resourceVersion changed after proposal');
    }
    if (live.spec?.claimRef?.namespace === 'backups' || live.status?.kubernetesStatus?.namespace === 'backups')
      throw new Error('volumes claimed from backups are never deleted');
    if (plan.operation.type === 'delete-job') {
      const finished = live.status?.conditions?.some(
        (c) => (c.type === 'Complete' || c.type === 'Failed') && c.status === 'True',
      );
      if (!finished || live.status?.active) throw new Error('Job is still running');
      await executor.request(path, {
        method: 'DELETE',
        body: {
          apiVersion: 'v1',
          kind: 'DeleteOptions',
          propagationPolicy: 'Background',
          preconditions: { uid: plan.target.uid, resourceVersion: plan.target.resourceVersion },
        },
      });
      return { applied: true, message: `Deleted finished Job for plan ${plan.id}.`, automaticWrites: 0 };
    }
    if (plan.operation.type === 'patch-image') {
      const pod = (plan.target.kind === 'CronJob' ? live.spec?.jobTemplate?.spec : live.spec)?.template?.spec;
      for (const { name, initContainer } of plan.operation.containers) {
        const image = (initContainer ? pod?.initContainers : pod?.containers)?.find((c) => c.name === name)?.image;
        if (!image || canonicalImage(image) !== canonicalImage(plan.operation.before))
          throw new Error(`container ${name} does not run the before image`);
      }
    }

    let currentPlan = plan;
    let annotationInstalled = false;
    let temporaryBindingPath = '';
    let storageDeleted = false;
    let result: ExecutionResult | undefined;
    let executionError: unknown;
    try {
      result = await (async () => {
        // Only the always-ask admission rules read the annotation.
        if (lane === 'always-ask') {
          annotationInstalled = true;
          await this.annotator.request(path, {
            method: 'PATCH',
            body: approvalAnnotationPatch(plan, plan.id),
            contentType: 'application/merge-patch+json',
          });
          const annotated = (await this.annotator.request(path)) as {
            metadata?: { uid?: string; resourceVersion?: string };
          };
          if (annotated.metadata?.uid !== plan.target.uid || !annotated.metadata.resourceVersion) {
            throw new Error('annotated target identity changed');
          }
          currentPlan = { ...plan, target: { ...plan.target, resourceVersion: annotated.metadata.resourceVersion } };
        }

        if (plan.operation.type === 'delete-storage') {
          // Lane C (Longhorn volumes) deletes as break-glass; PVs and PVCs get a one-off binding for the writer.
          if (lane !== 'C') {
            const candidate = binding(currentPlan);
            temporaryBindingPath = candidate.path;
            await this.annotator.request(candidate.collection, { method: 'POST', body: candidate.body });
          }
          await executor.request(path, {
            method: 'DELETE',
            body: {
              apiVersion: 'v1',
              kind: 'DeleteOptions',
              preconditions: { uid: currentPlan.target.uid, resourceVersion: currentPlan.target.resourceVersion },
            },
          });
          storageDeleted = true;
        } else {
          await executor.request(path, {
            method: 'PATCH',
            body: mergePatch(currentPlan),
            contentType: 'application/strategic-merge-patch+json',
          });
        }
        if (plan.operation.type === 'delete-storage' || plan.target.kind === 'CronJob') {
          return { applied: true, message: `Applied approved plan ${plan.id}.`, automaticWrites: 0 };
        }
        const deadline = Math.min(Date.parse(plan.expiresAt), Date.now() + 10 * 60_000);
        if (await this.observer.ready(currentPlan, Math.min(deadline, Date.now() + 3 * 60_000))) {
          return { applied: true, message: `Applied approved plan ${plan.id}.`, automaticWrites: 0 };
        }
        if (lane !== 'A' || validated.automaticWriteCap === 0) {
          return {
            applied: true,
            message: `Plan ${plan.id} applied but did not become ready; escalate.`,
            automaticWrites: 0,
          };
        }
        const automaticWrites = await this.recover(currentPlan, deadline, validated.automaticWriteCap);
        return {
          applied: true,
          message: `Plan ${plan.id} applied; capped same-workload recovery used ${automaticWrites} write(s).`,
          automaticWrites,
        };
      })();
      // eslint-disable-next-line no-catch-all/no-catch-all -- cleanup must run after every execution failure
    } catch (error) {
      executionError = error;
    }

    const cleanups: Promise<unknown>[] = [];
    if (temporaryBindingPath) cleanups.push(this.annotator.request(temporaryBindingPath, { method: 'DELETE' }));
    if (annotationInstalled && (!storageDeleted || plan.operation.type !== 'delete-storage')) {
      cleanups.push(
        this.annotator.request(path).then((value) => {
          const current = value as { metadata?: { resourceVersion?: string } };
          const cleanup = {
            ...plan,
            target: { ...plan.target, resourceVersion: current.metadata?.resourceVersion ?? '' },
          };
          return this.annotator.request(path, {
            method: 'PATCH',
            body: approvalAnnotationPatch(cleanup, null),
            contentType: 'application/merge-patch+json',
          });
        }),
      );
    }
    const failed = (await Promise.allSettled(cleanups)).filter(
      (cleanup): cleanup is PromiseRejectedResult => cleanup.status === 'rejected',
    );
    if (executionError !== undefined || failed.length) {
      const errors = [...(executionError === undefined ? [] : [executionError]), ...failed.map(({ reason }) => reason)];
      if (errors.length === 1) throw errors[0];
      throw new AggregateError(errors, 'remediation execution or cleanup failed');
    }
    if (!result) throw new Error('remediation execution produced no result');
    if (this.helm && (plan.operation.type === 'patch-image' || plan.operation.type === 'scale')) {
      const note = await this.helm
        .recordPatch(plan, await executor.request(path))
        .catch(
          (error: unknown) => `Helm drift was not recorded: ${error instanceof Error ? error.message : String(error)}`,
        );
      if (note) return { ...result, message: `${result.message} ${note}` };
    }
    return result;
  }

  /** Runs the plan's argv in its pod from an in-cluster Job, as the writer or, in Lane C, the break-glass account. */
  private async podExec(plan: PodExecPlan, serviceAccount: string): Promise<ExecutionResult> {
    const ns = encodeURIComponent(plan.target.namespace ?? '');
    const pod = (await this.writer.request(
      `/api/v1/namespaces/${ns}/pods/${encodeURIComponent(plan.target.name)}`,
    )) as LiveObject;
    if (pod.metadata?.uid !== plan.target.uid) throw new Error('target pod changed after proposal');
    const { exitCode, output } = await this.runJob(runnerJob(plan, serviceAccount), 10 * 60_000);
    return {
      applied: exitCode === 0,
      message: `exec in ${plan.target.namespace}/${plan.target.name} exited ${exitCode ?? 'without finishing'}:\n${output}`,
      automaticWrites: 0,
    };
  }

  private async deleteSnapshot(plan: SnapshotDeletePlan, client: KubernetesJsonClient): Promise<ExecutionResult> {
    const base = '/apis/longhorn.io/v1beta2/namespaces/longhorn-system';
    const { uid, resourceVersion, name } = plan.target;
    const path = `${base}/snapshots/${encodeURIComponent(name)}`;
    const live = (await client.request(path)) as LiveObject & { spec?: { volume?: string } };
    if (live.metadata?.uid !== uid || live.metadata?.resourceVersion !== resourceVersion)
      throw new Error('target UID or resourceVersion changed after proposal');
    if (live.spec?.volume !== plan.operation.volume)
      throw new Error(`snapshot ${name} is not of volume ${plan.operation.volume}`);
    const volume = (await client.request(`${base}/volumes/${encodeURIComponent(plan.operation.volume)}`)) as LiveObject;
    if (volume.status?.kubernetesStatus?.namespace === 'backups')
      throw new Error('snapshots of volumes claimed from backups are never deleted');
    const backups = (await client.request(`${base}/backups`)) as {
      items?: Array<{ spec?: { snapshotName?: string }; status?: { snapshotName?: string } }>;
    };
    if (backups.items?.some((b) => b.spec?.snapshotName === name || b.status?.snapshotName === name))
      throw new Error(`a Longhorn backup references snapshot ${name}; it is never deleted`);
    await client.request(path, {
      method: 'DELETE',
      body: { apiVersion: 'v1', kind: 'DeleteOptions', preconditions: { uid, resourceVersion } },
    });
    return {
      applied: true,
      message: `Deleted Longhorn snapshot ${name} of volume ${plan.operation.volume}.`,
      automaticWrites: 0,
    };
  }

  private async buildImage(plan: BuildImagePlan): Promise<ExecutionResult> {
    if (!plan.operation.image.startsWith(`${this.build.registry}/`))
      throw new Error(`build-image pushes to ${this.build.registry}`);
    const { exitCode, message, output } = await this.runJob(kanikoJob(plan, this.build.pushSecret), 30 * 60_000);
    const digest = /sha256:[0-9a-f]{64}/.exec(message)?.[0];
    return exitCode === 0 && digest
      ? { applied: true, message: `built ${plan.operation.image}@${digest}`, automaticWrites: 0 }
      : { applied: false, message: `build of ${plan.operation.image} failed:\n${output}`, automaticWrites: 0 };
  }

  /** Creates the Job, waits for it, and returns its container's exit code, termination message and last 2 KB of output. */
  private async runJob(job: Record<string, unknown>, timeout: number) {
    const { name, namespace } = job.metadata as { name: string; namespace: string };
    const jobs = `/apis/batch/v1/namespaces/${namespace}/jobs`;
    await this.writer.request(jobs, { method: 'POST', body: job });
    const deadline = Date.now() + timeout;
    let done = false;
    while (!done && Date.now() < deadline) {
      await sleep(3_000);
      const status = ((await this.writer.request(`${jobs}/${name}`)) as { status?: Record<string, number> }).status;
      done = Boolean(status?.succeeded || status?.failed);
    }
    const pods = (await this.writer.request(
      `/api/v1/namespaces/${namespace}/pods?labelSelector=${encodeURIComponent(`job-name=${name}`)}`,
    )) as {
      items?: Array<{
        metadata?: { name?: string };
        status?: { containerStatuses?: Array<{ state?: { terminated?: { exitCode?: number; message?: string } } }> };
      }>;
    };
    const pod = pods.items?.[0];
    const terminated = pod?.status?.containerStatuses?.[0]?.state?.terminated;
    const log = pod?.metadata?.name
      ? String(
          await this.writer.request(
            `/api/v1/namespaces/${namespace}/pods/${pod.metadata.name}/log?limitBytes=1048576`,
            { text: true },
          ),
        )
      : '';
    return { exitCode: terminated?.exitCode, message: terminated?.message ?? '', output: log.slice(-OUTPUT_LIMIT) };
  }

  private async recover(plan: RemediationPlan, deadline: number, cap: 1 | 2): Promise<number> {
    const path = workloadPath(plan);
    let writes = 0;
    const apply = async (candidate: RemediationPlan): Promise<boolean> => {
      if (Date.now() >= deadline) return false;
      const live = (await this.writer.request(path)) as { metadata?: { uid?: string; resourceVersion?: string } };
      if (live.metadata?.uid !== plan.target.uid || !live.metadata.resourceVersion)
        throw new Error('recovery target drifted');
      const fresh = { ...candidate, target: { ...candidate.target, resourceVersion: live.metadata.resourceVersion } };
      await this.writer.request(path, {
        method: 'PATCH',
        body: mergePatch(fresh),
        contentType: 'application/strategic-merge-patch+json',
      });
      writes++;
      return this.observer.ready(fresh, Math.min(deadline, Date.now() + 3 * 60_000));
    };

    if (plan.operation.type === 'patch-image') {
      const restarted: RemediationPlan = {
        ...plan,
        operation: { type: 'restart', restartedAt: new Date().toISOString() },
      };
      if (await apply(restarted)) return writes;
      if (writes < cap) await apply({ ...plan, operation: { ...plan.operation, after: plan.operation.before } });
    } else if (plan.operation.type === 'scale') {
      await apply({ ...plan, operation: { ...plan.operation, after: plan.operation.before } });
    } else if (plan.operation.type === 'restart') {
      await apply({ ...plan, operation: { ...plan.operation, restartedAt: new Date().toISOString() } });
    }
    return writes;
  }
}
