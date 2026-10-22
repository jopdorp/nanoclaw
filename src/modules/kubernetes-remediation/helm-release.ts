/**
 * The Helm path. A helm-values plan edits a values file in a k8s.jegor.nl
 * checkout, runs `helm upgrade` with it as the nanoclaw-helm identity, and
 * commits and pushes only once the release is healthy and still matches any
 * direct patch recorded as Helm drift. A direct image or replica patch on a
 * Helm-managed workload is recorded as such a drift item in the group's
 * memory/open-items, so it always comes back to Helm.
 */
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';
import { isMap, isScalar, parseDocument } from 'yaml';

import type { KubernetesJsonClient } from './gateway-client.js';
import { canonicalImage } from './policy.js';
import type { ExecutionResult, HelmValuesPlan, RemediationPlan } from './types.js';

const exec = promisify(execFile);
const DAY = 24 * 60 * 60_000;
// Only these leaves are echoed back on a before mismatch; anything else may be a credential.
const ECHOED_KEY_RE = /(?:^|\.)(image|repository|registry|tag|digest|replicas|replicaCount|enabled)$/;
const ENTRY_RE =
  /^- (\S+) plan (\S+) (Deployment|StatefulSet|DaemonSet)\/(\S+) (container:\S+|init:\S+|replicas) (\S+)$/;

export interface HelmChart {
  chart: string;
  repo: string;
  file: string;
}

export interface HelmReleaseOptions {
  client: KubernetesJsonClient;
  charts: Record<string, HelmChart>;
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
    if (doc.errors.length) throw new Error(`values file does not parse: ${doc.errors[0].message}`);
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
  constructor(private readonly options: HelmReleaseOptions) {}

  /** Binds the plan to the release's latest revision Secret and checks every `before` against the repo. */
  async bind(plan: HelmValuesPlan): Promise<HelmValuesPlan> {
    this.chart(plan);
    const anchor = await this.latestRelease(plan);
    await this.sync();
    editValues(this.read(plan), plan.operation.set);
    return { ...plan, target: { ...plan.target, ...anchor } };
  }

  async apply(plan: HelmValuesPlan): Promise<ExecutionResult> {
    const chart = this.chart(plan);
    const { name: release, namespace } = plan.target;
    const ns = namespace ?? '';
    const anchor = await this.latestRelease(plan);
    if (anchor.uid !== plan.target.uid || anchor.resourceVersion !== plan.target.resourceVersion) {
      throw new Error('Helm release changed after proposal');
    }
    const metadata = JSON.parse(await this.options.helm(['get', 'metadata', release, '-n', ns, '-o', 'json'])) as {
      chart?: string;
      version?: string;
      revision?: number;
    };
    if (metadata.chart !== chart.chart || !metadata.version || !metadata.revision) {
      throw new Error(`release ${ns}/${release} runs chart ${metadata.chart}, not ${chart.chart}`);
    }
    await this.sync();
    const file = path.join(this.options.checkout, plan.operation.file);
    fs.writeFileSync(file, editValues(this.read(plan), plan.operation.set));

    const upgrade = ['upgrade', release, chart.chart, '--repo', chart.repo, '--version', metadata.version];
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

    const diff = await this.driftDiff(release, ns);
    if (diff.length) {
      const imageRegressed = diff.some((line) => !line.includes(' replicas '));
      const outcome = imageRegressed ? await this.rollback(release, ns, metadata.revision) : 'kept the upgrade';
      return {
        applied: !imageRegressed,
        message: `helm result differs from patch: ${diff.join('; ')}; ${outcome}; nothing pushed, the drift item stays open.`,
        automaticWrites: 0,
      };
    }

    try {
      await this.options.git([
        '-c',
        'user.name=Orfie',
        '-c',
        'user.email=orfie@claw.jopdorp.nl',
        'commit',
        '-m',
        `Orfie: ${plan.reason.split('\n', 1)[0]}`,
        '--',
        plan.operation.file,
      ]);
      await this.options.git(['push', 'origin', 'HEAD:master']);
      // eslint-disable-next-line no-catch-all/no-catch-all -- the release is live either way; the approver hears the push failed
    } catch (error) {
      return {
        applied: true,
        message: `helm matches live, but the values commit was not pushed: ${reason(error)}`,
        automaticWrites: 0,
      };
    }
    const sha = (await this.options.git(['rev-parse', '--short', 'HEAD'])).trim();
    this.resolveDrift(release, plan.id);
    return { applied: true, message: `helm matches live; pushed ${sha} to k8s.jegor.nl.`, automaticWrites: 0 };
  }

  /** Records a direct patch on a Helm-managed workload; returns the Matrix note, or '' when Helm does not own it. */
  async recordPatch(plan: RemediationPlan, object: unknown): Promise<string> {
    const live = object as Workload;
    const release = live.metadata?.annotations?.['meta.helm.sh/release-name'];
    if (live.metadata?.labels?.['app.kubernetes.io/managed-by'] !== 'Helm' || !release) return '';
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
    const file = this.driftFile(release);
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

  private chart(plan: HelmValuesPlan): HelmChart {
    const chart = this.options.charts[`${plan.target.namespace}/${plan.target.name}`];
    if (!chart || chart.file !== plan.operation.file) {
      throw new Error(
        `${plan.target.namespace}/${plan.target.name} with ${plan.operation.file} is not an allowlisted Helm release`,
      );
    }
    return chart;
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

  private read(plan: HelmValuesPlan): string {
    return fs.readFileSync(path.join(this.options.checkout, plan.operation.file), 'utf8');
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

  private driftFile(release: string): string {
    return path.join(this.options.memoryDir, 'open-items', `helm-drift-${release}.md`);
  }

  private async driftDiff(release: string, ns: string): Promise<string[]> {
    const file = this.driftFile(release);
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

  private resolveDrift(release: string, planId: string): void {
    const file = this.driftFile(release);
    if (fs.existsSync(file))
      fs.appendFileSync(file, `- resolved ${new Date().toISOString()} by helm-values plan ${planId}\n`);
  }
}
