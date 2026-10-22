import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';

import { canonicalImage } from './policy.js';
import type { ApprovalGrant, ExecutionResult, RemediationPlan, ValidatedPlan } from './types.js';

const APPROVAL_ANNOTATION = 'remediation.nanoclaw.io/approval-id';
const TEMPORARY_BINDING_RE = /^nanoclaw-remediation-[0-9a-f-]{36}$/;

export interface KubernetesJsonClient {
  request(
    path: string,
    options?: { method?: string; body?: unknown; contentType?: string; signal?: AbortSignal },
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
    options: { method?: string; body?: unknown; contentType?: string; signal?: AbortSignal } = {},
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
    if (result.code !== 0) throw new Error(`Kubernetes gateway request failed: ${result.stderr.trim() || result.code}`);
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

function workloadPath(plan: RemediationPlan): string {
  const namespace = encodeURIComponent(plan.target.namespace ?? '');
  const name = encodeURIComponent(plan.target.name);
  const plural =
    plan.target.kind === 'Deployment'
      ? 'deployments'
      : plan.target.kind === 'StatefulSet'
        ? 'statefulsets'
        : plan.target.kind === 'DaemonSet'
          ? 'daemonsets'
          : null;
  if (!plural) throw new Error('target is not a workload');
  return `/apis/apps/v1/namespaces/${namespace}/${plural}/${name}`;
}

function jobPath(plan: RemediationPlan): string {
  return `/apis/batch/v1/namespaces/${encodeURIComponent(plan.target.namespace ?? '')}/jobs/${encodeURIComponent(plan.target.name)}`;
}

function storagePath(plan: RemediationPlan): string {
  const name = encodeURIComponent(plan.target.name);
  return plan.target.kind === 'PersistentVolume'
    ? `/api/v1/persistentvolumes/${name}`
    : `/api/v1/namespaces/${encodeURIComponent(plan.target.namespace ?? '')}/persistentvolumeclaims/${name}`;
}

function mergePatch(plan: RemediationPlan): Record<string, unknown> {
  const resourceVersion = plan.target.resourceVersion;
  if (plan.operation.type === 'patch-image') {
    const { containers, after } = plan.operation;
    const images = (init: boolean) =>
      containers.filter((c) => c.initContainer === init).map(({ name }) => ({ name, image: after }));
    const spec = { containers: images(false), initContainers: images(true) };
    return {
      metadata: { resourceVersion },
      spec: { template: { spec: Object.fromEntries(Object.entries(spec).filter(([, list]) => list.length)) } },
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

interface LiveObject {
  metadata?: { uid?: string; resourceVersion?: string };
  spec?: {
    template?: { spec?: Partial<Record<'containers' | 'initContainers', Array<{ name?: string; image?: string }>>> };
  };
  status?: { active?: number; conditions?: Array<{ type?: string; status?: string }> };
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

/** Host-only executor. The agent is never given either OneCLI identity. */
export class GatewayRemediationExecutor {
  constructor(
    private readonly executor: KubernetesJsonClient,
    private readonly annotator: KubernetesJsonClient,
    private readonly observer: RolloutObserver,
  ) {}

  async execute(validated: ValidatedPlan, grant: ApprovalGrant) {
    const { plan, lane } = validated;
    if (grant.planId !== plan.id || grant.planDigest !== validated.digest)
      throw new Error('approval does not bind this plan');
    if (Date.parse(plan.expiresAt) <= Date.now()) throw new Error('approved plan expired');
    if (lane === 'C')
      return {
        applied: false,
        message: 'Lane C stays read-only; approval recorded for manual escalation.',
        automaticWrites: 0,
      };

    const path =
      plan.operation.type === 'delete-storage'
        ? storagePath(plan)
        : plan.operation.type === 'delete-job'
          ? jobPath(plan)
          : workloadPath(plan);
    const live = (await this.executor.request(path)) as LiveObject;
    if (live.metadata?.uid !== plan.target.uid || live.metadata?.resourceVersion !== plan.target.resourceVersion) {
      throw new Error('target UID or resourceVersion changed after proposal');
    }
    if (plan.operation.type === 'delete-job') {
      const finished = live.status?.conditions?.some(
        (c) => (c.type === 'Complete' || c.type === 'Failed') && c.status === 'True',
      );
      if (!finished || live.status?.active) throw new Error('Job is still running');
      await this.executor.request(path, {
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
      const pod = live.spec?.template?.spec;
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

        if (plan.operation.type === 'delete-storage') {
          const candidate = binding(currentPlan);
          temporaryBindingPath = candidate.path;
          await this.annotator.request(candidate.collection, { method: 'POST', body: candidate.body });
          await this.executor.request(path, {
            method: 'DELETE',
            body: {
              apiVersion: 'v1',
              kind: 'DeleteOptions',
              preconditions: { uid: currentPlan.target.uid, resourceVersion: currentPlan.target.resourceVersion },
            },
          });
          storageDeleted = true;
        } else {
          await this.executor.request(path, {
            method: 'PATCH',
            body: mergePatch(currentPlan),
            contentType: 'application/strategic-merge-patch+json',
          });
        }
        if (plan.operation.type === 'delete-storage') {
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
    return result;
  }

  private async recover(plan: RemediationPlan, deadline: number, cap: 1 | 2): Promise<number> {
    const path = workloadPath(plan);
    let writes = 0;
    const apply = async (candidate: RemediationPlan): Promise<boolean> => {
      if (Date.now() >= deadline) return false;
      const live = (await this.executor.request(path)) as { metadata?: { uid?: string; resourceVersion?: string } };
      if (live.metadata?.uid !== plan.target.uid || !live.metadata.resourceVersion)
        throw new Error('recovery target drifted');
      const fresh = { ...candidate, target: { ...candidate.target, resourceVersion: live.metadata.resourceVersion } };
      await this.executor.request(path, {
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
