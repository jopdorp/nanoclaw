/**
 * The Helm path, for any release. A helm-values plan edits the release's values
 * file in a k8s.jegor.nl checkout, runs `helm upgrade` with it, and commits and
 * pushes only once the release is healthy and still matches any direct patch
 * recorded as Helm drift. The file must equal the release's live user-supplied
 * values before the edit; helm-sync-values writes them there first. The chart
 * source comes from the plan or an earlier verified hint, and must serve the
 * installed chart version. A direct image or replica patch on a Helm-managed
 * workload is recorded as a drift item in the group's memory/open-items, so it
 * always comes back to Helm.
 */
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { isDeepStrictEqual, promisify } from 'node:util';
import { isMap, isScalar, parseAllDocuments, parseDocument, stringify } from 'yaml';

import type { KubernetesJsonClient } from './gateway-client.js';
import { canonicalImage, imageRepository } from './policy.js';
import type { ExecutionResult, HelmBinding, HelmSyncPlan, HelmValuesPlan, RemediationPlan } from './types.js';

const exec = promisify(execFile);
const DAY = 24 * 60 * 60_000;
// Only these leaves are echoed back on a before mismatch; anything else may be a credential.
const ECHOED_KEY_RE = /(?:^|\.)(image|repository|registry|tag|digest|replicas|replicaCount|enabled)$/;
const RELEASE_RE = /^[a-z0-9][a-z0-9.-]{0,52}$/;
// Values under such keys are never shown, and never written to the public values repo.
const SECRET_KEY_RE = /password|token|secret|key/i;
const ENTRY_RE =
  /^- (\S+) plan (\S+) (Deployment|StatefulSet|DaemonSet)\/(\S+) (container:\S+|init:\S+|replicas) (\S+)$/;

export interface HelmChart {
  chart: string;
  repo: string;
  file: string;
}

export interface HelmReleaseOptions {
  client: KubernetesJsonClient;
  /** Verified chart sources keyed `<namespace>/<release>`; hints only, every plan re-verifies. */
  charts: Record<string, HelmChart>;
  remember: (key: string, chart: HelmChart) => void;
  checkout: string;
  memoryDir: string;
  helm: (args: string[]) => Promise<string>;
  git: (args: string[]) => Promise<string>;
  remote: string;
}

interface Workload {
  metadata?: { labels?: Record<string, string>; annotations?: Record<string, string> };
  spec?: {
    replicas?: number;
    template?: { spec?: Partial<Record<'containers' | 'initContainers', Array<{ name?: string; image?: string }>>> };
  };
}

/** A digest pins the image whatever tag the chart renders next to it. */
function pinnedImage(image = ''): string {
  return canonicalImage(image).replace(/:[^/:@]+@/, '@');
}

type Values = Record<string, unknown>;

function parseValues(text: string): Values {
  const doc = parseDocument(text);
  if (doc.errors.length) throw new Error(`values do not parse: ${doc.errors[0].code}`);
  const value: unknown = doc.toJS();
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as Values) : {};
}

function leaves(value: unknown, prefix = '', out = new Map<string, unknown>()): Map<string, unknown> {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    for (const [key, child] of Object.entries(value)) leaves(child, prefix ? `${prefix}.${key}` : key, out);
  } else if (prefix) out.set(prefix, value);
  return out;
}

/** One line per differing leaf, `path: live -> file`, with secret-looking and structured values hidden. */
function valuesDiff(live: Values, file: Values): string[] {
  const [a, b] = [leaves(live), leaves(file)];
  const show = (path: string, value: unknown) =>
    value === undefined
      ? 'absent'
      : SECRET_KEY_RE.test(path) || (value !== null && typeof value === 'object')
        ? 'set'
        : JSON.stringify(value);
  return [...new Set([...a.keys(), ...b.keys()])]
    .sort()
    .filter((path) => !isDeepStrictEqual(a.get(path), b.get(path)))
    .map((path) => `${path}: ${show(path, a.get(path))} -> ${show(path, b.get(path))}`);
}

function secretKeys(value: unknown, prefix = ''): string[] {
  if (!value || typeof value !== 'object') return [];
  return Object.entries(value).flatMap(([key, child]) => {
    const at = prefix ? `${prefix}.${key}` : key;
    return [...(SECRET_KEY_RE.test(key) ? [at] : []), ...secretKeys(child, at)];
  });
}

function valueAt(values: Values, dotted: string): unknown {
  return dotted.split('.').reduce<unknown>((node, key) => (node as Values | undefined)?.[key], values);
}

/** Full image references for each image-key edit, assembled from the edit and its repository/registry/tag/digest siblings. */
function imageEdits(values: Values, set: HelmValuesPlan['operation']['set']): HelmBinding['images'] {
  const images: HelmBinding['images'] = {};
  const planned = new Map(set.map((edit) => [edit.path, edit.after]));
  for (const { path: dotted, before, after } of set) {
    const key = /(?:^|\.)(image|tag|digest)$/.exec(dotted)?.[1];
    if (key === 'image') {
      images[dotted] = { before: before === null ? undefined : String(before), after: String(after) };
      continue;
    }
    if (!key) continue;
    const parent = dotted.slice(0, -key.length);
    const repository = valueAt(values, `${parent}repository`);
    if (typeof repository !== 'string') continue;
    const registry = valueAt(values, `${parent}registry`);
    const ref = (side: 'before' | 'after') => {
      const pick = (leaf: string) => {
        const value =
          side === 'after' && planned.has(`${parent}${leaf}`)
            ? planned.get(`${parent}${leaf}`)
            : valueAt(values, `${parent}${leaf}`);
        return value === undefined || value === null || value === '' ? '' : String(value);
      };
      const [tag, digest] = [pick('tag'), pick('digest').replace(/^@/, '')];
      return `${typeof registry === 'string' && registry ? `${registry}/` : ''}${repository}${tag ? `:${tag}` : ''}${digest && !tag.includes('@') ? `@${digest}` : ''}`;
    };
    images[dotted] = { before: ref('before'), after: ref('after') };
  }
  return images;
}

function reason(error: unknown): string {
  return (error instanceof Error ? error.message : String(error)).trim().split('\n').slice(-3).join(' ');
}

/**
 * Splices each edit into the source text instead of re-rendering the document,
 * which reformats most of the values files. A `before` of null adds the key,
 * and any missing parents, as the first entry of the nearest block map.
 */
export function editValues(text: string, set: HelmValuesPlan['operation']['set']): string {
  let result = text;
  for (const { path: dotted, before, after } of set) {
    const doc = parseDocument(result);
    if (doc.errors.length) throw new Error(`values file does not parse: ${doc.errors[0].code}`);
    const keys = dotted.split('.');
    const node = doc.getIn(keys, true);
    if (before === null) {
      let depth = keys.length - 1;
      while (depth > 0 && !doc.hasIn(keys.slice(0, depth))) depth--;
      const parent = depth ? doc.getIn(keys.slice(0, depth), true) : doc.contents;
      const first = isMap(parent) && !parent.flow ? parent.items[0]?.key : undefined;
      if (node !== undefined || !isScalar(first) || !first.range) {
        throw new Error(`repo drift: ${dotted} ${node === undefined ? 'has no block map to join' : 'already exists'}`);
      }
      const lineStart = result.lastIndexOf('\n', first.range[0]) + 1;
      const indent = first.range[0] - lineStart;
      const lines = keys
        .slice(depth)
        .map(
          (key, i, added) =>
            `${' '.repeat(indent + 2 * i)}${key}:${i === added.length - 1 ? ` ${JSON.stringify(after)}` : ''}\n`,
        );
      result = result.slice(0, lineStart) + lines.join('') + result.slice(lineStart);
      continue;
    }
    if (!isScalar(node) || !node.range || node.value !== before) {
      const actual = isScalar(node) ? JSON.stringify(node.value) : 'not a scalar';
      throw new Error(
        `repo drift: ${dotted} is ${ECHOED_KEY_RE.test(dotted) ? actual : 'different'}, not ${JSON.stringify(before)}`,
      );
    }
    const literal =
      typeof after !== 'string'
        ? String(after)
        : node.type === 'QUOTE_SINGLE'
          ? `'${after.replaceAll("'", "''")}'`
          : node.type === 'PLAIN' && parseDocument(after).contents?.toJSON() === after
            ? after
            : JSON.stringify(after);
    result = result.slice(0, node.range[0]) + literal + result.slice(node.range[1]);
  }
  const expected = parseDocument(text);
  for (const { path: dotted, after } of set) expected.setIn(dotted.split('.'), expected.createNode(after));
  if (!isDeepStrictEqual(parseDocument(result).toJS(), expected.toJS()))
    throw new Error('the edit changes more than the given scalar paths');
  return result;
}

export function gitWithDeployKey(checkout: string, sshDir: string): (args: string[]) => Promise<string> {
  const env = {
    ...process.env,
    GIT_SSH_COMMAND: `ssh -i ${path.join(sshDir, 'id_ed25519')} -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=${path.join(sshDir, 'known_hosts')}`,
  };
  return async (args) => (await exec('git', args, { cwd: checkout, env })).stdout;
}

export function helmThroughOneCli(agent: string, apiServer: string, home: string): (args: string[]) => Promise<string> {
  const env = {
    ...process.env,
    HELM_CACHE_HOME: `${home}/cache`,
    HELM_CONFIG_HOME: `${home}/config`,
    HELM_DATA_HOME: `${home}/data`,
  };
  return async (args) =>
    (
      await exec('onecli', ['run', '--agent', agent, '--', 'helm', ...args, '--kube-apiserver', apiServer], {
        env,
        maxBuffer: 16 * 1024 * 1024,
      })
    ).stdout;
}

export class HelmReleaseExecutor {
  // bind and apply share one checkout and must not overlap a running upgrade.
  private queue: Promise<unknown> = Promise.resolve();

  constructor(private readonly options: HelmReleaseOptions) {}

  bind(plan: HelmValuesPlan): Promise<HelmBinding> {
    return this.serial(() => this.bindNow(plan));
  }

  apply(plan: HelmValuesPlan): Promise<ExecutionResult> {
    return this.serial(() => this.applyNow(plan));
  }

  syncValues(plan: HelmSyncPlan): Promise<ExecutionResult> {
    return this.serial(() => this.syncNow(plan));
  }

  /** Binds the plan to the release's latest revision Secret, its verified chart and its live values. */
  private async bindNow(plan: HelmValuesPlan): Promise<HelmBinding> {
    const { name: release, namespace } = plan.target;
    const ns = namespace ?? '';
    await this.resolveChart(plan);
    const anchor = await this.latestRelease(plan);
    await this.sync();
    const text = await this.unchangedFromLive(plan);
    const live = parseValues(text);
    const stateful = parseAllDocuments(await this.options.helm(['get', 'manifest', release, '-n', ns]))
      .map((doc) => doc.toJS() as { kind?: string; spec?: Workload['spec'] } | null)
      .filter((object): object is { kind: string; spec?: Workload['spec'] } => object?.kind === 'StatefulSet');
    return {
      plan: { ...plan, target: { ...plan.target, ...anchor } },
      diff: valuesDiff(live, parseValues(editValues(text, plan.operation.set))),
      images: imageEdits(live, plan.operation.set),
      statefulRepositories: stateful.flatMap(({ spec }) =>
        [...(spec?.template?.spec?.containers ?? []), ...(spec?.template?.spec?.initContainers ?? [])].map((c) =>
          imageRepository(c.image ?? ''),
        ),
      ),
      hasStatefulSet: stateful.length > 0,
    };
  }

  private async applyNow(plan: HelmValuesPlan): Promise<ExecutionResult> {
    const { name: release, namespace } = plan.target;
    const ns = namespace ?? '';
    const anchor = await this.latestRelease(plan);
    if (anchor.uid !== plan.target.uid || anchor.resourceVersion !== plan.target.resourceVersion) {
      throw new Error('Helm release changed after proposal');
    }
    const { chart, metadata } = await this.resolveChart(plan);
    await this.sync();
    const file = path.join(this.options.checkout, plan.operation.file);
    fs.writeFileSync(file, editValues(await this.unchangedFromLive(plan), plan.operation.set));

    const upgrade = ['upgrade', release, ...this.chartRef(chart), '--version', metadata.version];
    try {
      await this.options.helm([...upgrade, '-n', ns, '-f', file, '--wait', '--timeout', '10m']);
      // eslint-disable-next-line no-catch-all/no-catch-all -- every upgrade failure rolls back
    } catch (error) {
      const rolledBack = await this.rollback(release, ns, metadata.revision);
      return {
        applied: false,
        message: `helm upgrade failed (${reason(error)}); ${rolledBack}; nothing pushed.`,
        automaticWrites: 0,
      };
    }

    const diff = await this.driftDiff(release, ns).catch((error: unknown) => [`drift check failed: ${reason(error)}`]);
    if (diff.length) {
      return {
        applied: false,
        message: `helm result differs from patch: ${diff.join('; ')}; ${await this.rollback(release, ns, metadata.revision)}; nothing pushed, the drift item stays open.`,
        automaticWrites: 0,
      };
    }

    const result = await this.commit(
      plan.operation.file,
      `Orfie: ${plan.reason.split('\n', 1)[0]}`,
      'helm matches live',
    );
    if (result.message.includes('pushed ')) this.resolveDrift(ns, release, plan.id);
    return result;
  }

  private async commit(file: string, message: string, done: string): Promise<ExecutionResult> {
    try {
      await this.options.git(['add', '--', file]);
      await this.options.git([
        '-c',
        'user.name=Orfie',
        '-c',
        'user.email=orfie@claw.jopdorp.nl',
        'commit',
        '-m',
        message,
        '--',
        file,
      ]);
      await this.options.git(['push', 'origin', 'HEAD:master']);
      // eslint-disable-next-line no-catch-all/no-catch-all -- the change is live either way; the approver hears the push failed
    } catch (error) {
      return {
        applied: true,
        message: `${done}, but the values commit was not pushed: ${reason(error)}`,
        automaticWrites: 0,
      };
    }
    const sha = (await this.options.git(['rev-parse', '--short', 'HEAD'])).trim();
    return { applied: true, message: `${done}; pushed ${sha} to k8s.jegor.nl.`, automaticWrites: 0 };
  }

  /** Records a direct patch on a Helm-managed workload; returns the Matrix note, or '' when Helm does not own it. */
  async recordPatch(plan: RemediationPlan, object: unknown): Promise<string> {
    const live = object as Workload;
    const release = live.metadata?.annotations?.['meta.helm.sh/release-name'];
    if (live.metadata?.labels?.['app.kubernetes.io/managed-by'] !== 'Helm' || !release || !RELEASE_RE.test(release))
      return '';
    const stamp = `- ${new Date().toISOString()} plan ${plan.id} ${plan.target.kind}/${plan.target.name}`;
    const pod = live.spec?.template?.spec;
    const op = plan.operation;
    const lines: string[] = [];
    if (op.type === 'patch-image') {
      for (const { name, initContainer } of op.containers) {
        const image = (initContainer ? pod?.initContainers : pod?.containers)?.find((c) => c.name === name)?.image;
        if (image === op.after) lines.push(`${stamp} ${initContainer ? 'init' : 'container'}:${name} ${op.after}`);
      }
    } else if (op.type === 'scale' && live.spec?.replicas === op.after) {
      lines.push(`${stamp} replicas ${op.after}`);
    }
    if (!lines.length) return '';
    const file = this.driftFile(plan.target.namespace ?? '', release);
    const current = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';
    const head = [
      '---',
      'type: helm-drift',
      `description: direct patch on Helm release ${plan.target.namespace}/${release}, pending a helm-values plan`,
      'tags: [helm, drift]',
      '---',
      '',
      `# Helm drift: ${plan.target.namespace}/${release}`,
      '',
      'Temporary direct patch. Propose the matching helm-values plan next; delete this file once the host appends a resolved line.',
      '',
    ].join('\n');
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, `${current && !current.includes('\n- resolved ') ? current : head}${lines.join('\n')}\n`);
    const index = path.join(path.dirname(file), 'index.md');
    const link = `(${path.basename(file)})`;
    const listed = fs.existsSync(index) ? fs.readFileSync(index, 'utf8') : '# Open items\n';
    if (!listed.includes(link)) {
      fs.writeFileSync(
        index,
        `${listed.trimEnd()}\n- [Helm drift ${plan.target.namespace}/${release}]${link} - direct patch, reconcile with helm-values\n`,
      );
    }
    return `temporary; Helm reconciliation pending (memory/open-items/${path.basename(file)}).`;
  }

  /** One reminder line per unresolved drift item older than a day, or '' when there is none. */
  staleDrift(now = Date.now()): string {
    const dir = path.join(this.options.memoryDir, 'open-items');
    if (!fs.existsSync(dir)) return '';
    return fs
      .readdirSync(dir)
      .filter((name) => name.startsWith('helm-drift-'))
      .flatMap((name) => {
        const text = fs.readFileSync(path.join(dir, name), 'utf8');
        const since = Date.parse(ENTRY_RE.exec(text.split('\n').find((line) => ENTRY_RE.test(line)) ?? '')?.[1] ?? '');
        return !text.includes('\n- resolved ') && since < now - DAY
          ? [`${name} open since ${new Date(since).toISOString()}`]
          : [];
      })
      .join('\n');
  }

  private chartRef({ chart, repo }: HelmChart): string[] {
    return repo.startsWith('oci://') ? [`${repo.replace(/\/$/, '')}/${chart}`] : [chart, '--repo', repo];
  }

  /** The installed chart and version, from a source that is verified to serve exactly that version. */
  private async resolveChart(plan: HelmValuesPlan) {
    const { name: release, namespace } = plan.target;
    const ns = namespace ?? '';
    const key = `${ns}/${release}`;
    const metadata = JSON.parse(await this.options.helm(['get', 'metadata', release, '-n', ns, '-o', 'json'])) as {
      chart?: string;
      version?: string;
      revision?: number;
    };
    if (!metadata.chart || !metadata.version || !metadata.revision) throw new Error(`no Helm release ${key}`);
    const repo = plan.operation.chart?.repo ?? this.options.charts[key]?.repo;
    if (!repo) throw new Error(`${key}: the host knows no source for chart ${metadata.chart}; add chart: { repo }`);
    const chart = { chart: metadata.chart, repo, file: plan.operation.file };
    const shown = parseValues(
      await this.options.helm(['show', 'chart', ...this.chartRef(chart), '--version', metadata.version]),
    );
    if (shown.name !== metadata.chart || shown.version !== metadata.version) {
      throw new Error(`${repo} does not serve ${metadata.chart} ${metadata.version}`);
    }
    if (!isDeepStrictEqual(this.options.charts[key], chart)) this.options.remember(key, chart);
    return { chart, metadata: { version: metadata.version, revision: metadata.revision } };
  }

  /** The values file, which must hold exactly the release's live user-supplied values. */
  private async unchangedFromLive(plan: HelmValuesPlan): Promise<string> {
    const { name: release, namespace } = plan.target;
    const live = parseValues(await this.options.helm(['get', 'values', release, '-n', namespace ?? '', '-o', 'yaml']));
    const file = path.join(this.options.checkout, plan.operation.file);
    if (!fs.existsSync(file))
      throw new Error(`repo values drift; submit helm-sync-values first: ${plan.operation.file} does not exist`);
    const text = this.read(plan.operation.file);
    const drift = valuesDiff(live, parseValues(text));
    if (drift.length) throw new Error(`repo values drift; submit helm-sync-values first: ${drift.join('; ')}`);
    return text;
  }

  private async syncNow(plan: HelmSyncPlan): Promise<ExecutionResult> {
    const { name: release, namespace } = plan.target;
    const live = parseValues(await this.options.helm(['get', 'values', release, '-n', namespace ?? '', '-o', 'yaml']));
    const secrets = secretKeys(live);
    if (secrets.length) {
      return {
        applied: false,
        message: `live values of ${namespace}/${release} hold secret-looking keys (${secrets.join(', ')}); nothing written to the public values repo.`,
        automaticWrites: 0,
      };
    }
    await this.sync();
    const relative = `kubernetes/helm-charts/${release}-values.yaml`;
    const file = path.join(this.options.checkout, relative);
    if (fs.existsSync(file) && !valuesDiff(live, parseValues(this.read(relative))).length) {
      return { applied: true, message: `${relative} already matches live.`, automaticWrites: 0 };
    }
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, stringify(live));
    return this.commit(relative, `Sync ${release} values from live`, 'wrote the live values');
  }

  private async latestRelease(plan: HelmValuesPlan): Promise<{ uid: string; resourceVersion: string }> {
    const selector = encodeURIComponent(`owner=helm,name=${plan.target.name}`);
    const list = (await this.options.client.request(
      `/api/v1/namespaces/${encodeURIComponent(plan.target.namespace ?? '')}/secrets?labelSelector=${selector}`,
    )) as { items?: Array<{ metadata?: { uid?: string; resourceVersion?: string; labels?: Record<string, string> } }> };
    const latest = (list.items ?? []).sort(
      (a, b) => Number(b.metadata?.labels?.version) - Number(a.metadata?.labels?.version),
    )[0];
    if (!latest?.metadata?.uid || !latest.metadata.resourceVersion)
      throw new Error(`no Helm release ${plan.target.name}`);
    return { uid: latest.metadata.uid, resourceVersion: latest.metadata.resourceVersion };
  }

  private async sync(): Promise<void> {
    if (!fs.existsSync(path.join(this.options.checkout, '.git'))) {
      fs.mkdirSync(this.options.checkout, { recursive: true });
      await this.options.git(['init', '-q']);
      await this.options.git(['remote', 'add', 'origin', this.options.remote]);
    }
    await this.options.git(['fetch', '-q', '--depth', '1', 'origin', 'master']);
    await this.options.git(['reset', '-q', '--hard', 'FETCH_HEAD']);
  }

  private serial<T>(run: () => Promise<T>): Promise<T> {
    const next = this.queue.then(run, run);
    this.queue = next.catch(() => undefined);
    return next;
  }

  private read(relative: string): string {
    const file = path.join(fs.realpathSync(this.options.checkout), relative);
    if (fs.realpathSync(file) !== file) throw new Error(`${relative} is a symlink`);
    return fs.readFileSync(file, 'utf8');
  }

  private async rollback(release: string, ns: string, revision: number): Promise<string> {
    try {
      await this.options.helm(['rollback', release, String(revision), '-n', ns, '--wait', '--timeout', '10m']);
      return `rolled back to revision ${revision}`;
      // eslint-disable-next-line no-catch-all/no-catch-all -- a failed rollback is reported, not thrown over the upgrade error
    } catch (error) {
      return `rollback to revision ${revision} failed: ${reason(error)}`;
    }
  }

  private driftFile(ns: string, release: string): string {
    return path.join(this.options.memoryDir, 'open-items', `helm-drift-${ns}--${release}.md`);
  }

  private async driftDiff(release: string, ns: string): Promise<string[]> {
    const file = this.driftFile(ns, release);
    const text = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';
    if (text.includes('\n- resolved ')) return [];
    const expected = new Map<string, { kind: string; name: string; field: string; value: string }>();
    for (const line of text.split('\n')) {
      const [, , , kind, name, field, value] = ENTRY_RE.exec(line) ?? [];
      if (kind) expected.set(`${kind}/${name} ${field}`, { kind, name, field, value });
    }
    const diff: string[] = [];
    for (const [key, { kind, name, field, value }] of expected) {
      const live = (await this.options.client.request(
        `/apis/apps/v1/namespaces/${encodeURIComponent(ns)}/${kind.toLowerCase()}s/${encodeURIComponent(name)}`,
      )) as Workload;
      const [type, container] = field.split(':');
      const actual =
        field === 'replicas'
          ? String(live.spec?.replicas)
          : (type === 'init' ? live.spec?.template?.spec?.initContainers : live.spec?.template?.spec?.containers)?.find(
              (c) => c.name === container,
            )?.image;
      if (field === 'replicas' ? actual !== value : pinnedImage(actual) !== pinnedImage(value))
        diff.push(`${key} live ${actual}, patch ${value}`);
    }
    return diff;
  }

  private resolveDrift(ns: string, release: string, planId: string): void {
    const file = this.driftFile(ns, release);
    if (fs.existsSync(file))
      fs.appendFileSync(file, `- resolved ${new Date().toISOString()} by helm-values plan ${planId}\n`);
  }
}
