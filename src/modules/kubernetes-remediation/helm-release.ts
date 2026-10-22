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
 *
 * The manifest path shares the checkout: manifest-edit edits one object of a
 * kubernetes/**.yaml file and applies it server-side, after a dry run proves the
 * unedited object equals live; manifest-sync writes the live object there first.
 * repo-write replaces a whole kubernetes/** file and applies the objects in it;
 * helm-install installs a new release from a values file written that way.
 */
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { isDeepStrictEqual, promisify } from 'node:util';
import { isMap, isNode, isScalar, isSeq, parseAllDocuments, parseDocument, stringify } from 'yaml';

import type { KubernetesJsonClient } from './gateway-client.js';
import {
  canonicalImage,
  imageRepository,
  inlineSecrets,
  repoObjects,
  SECRET_KEY_RE,
  secretKeys,
  valuesKeys,
} from './policy.js';
import type {
  ExecutionResult,
  HelmBinding,
  HelmInstallPlan,
  HelmSyncPlan,
  HelmUninstallPlan,
  HelmValuesPlan,
  ManifestEditPlan,
  ManifestSyncPlan,
  RemediationPlan,
  RepoWritePlan,
  SecretWritePlan,
  TargetRef,
} from './types.js';

const exec = promisify(execFile);
const DAY = 24 * 60 * 60_000;
// Only these leaves are echoed back on a before mismatch; anything else may be a credential.
const ECHOED_KEY_RE = /(?:^|(?<!\\)\.)(image|repository|registry|tag|digest|replicas|replicaCount|enabled)$/;
const RELEASE_RE = /^[a-z0-9][a-z0-9.-]{0,52}$/;
const ROLLBACK_ANNOTATION = 'nanoclaw.dev/rollback-to';
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

/** Container images of a rendered or installed manifest, keyed `<kind>/<name>/<container>`. */
function manifestImages(objects: Values[]): Map<string, string> {
  const images = new Map<string, string>();
  for (const object of objects) {
    const spec = object.spec as Workload['spec'] & { jobTemplate?: { spec?: Workload['spec'] } };
    const pod = spec?.template?.spec ?? spec?.jobTemplate?.spec?.template?.spec;
    const name = (object.metadata as { name?: string } | undefined)?.name;
    for (const c of [...(pod?.containers ?? []), ...(pod?.initContainers ?? [])])
      images.set(`${String(object.kind)}/${name}/${c.name}`, c.image ?? '');
  }
  return images;
}

function objects(manifest: string): Values[] {
  return parseAllDocuments(manifest)
    .map((doc) => doc.toJS() as Values | null)
    .filter((object): object is Values => !!object?.kind);
}

/** What the API server owns or derives; never part of a manifest or a drift comparison. */
function declared(object: Values): Values {
  const { status: _status, ...rest } = object;
  const metadata = { ...((rest.metadata as Values | undefined) ?? {}) };
  for (const key of ['managedFields', 'resourceVersion', 'uid', 'creationTimestamp', 'generation', 'selfLink'])
    delete metadata[key];
  const annotations = { ...((metadata.annotations as Values | undefined) ?? {}) };
  delete annotations['kubectl.kubernetes.io/last-applied-configuration'];
  delete annotations['deployment.kubernetes.io/revision'];
  if (Object.keys(annotations).length) metadata.annotations = annotations;
  else delete metadata.annotations;
  return { ...rest, metadata };
}

/** Charts stamp the image tag as a version label; on its own it only moves the record, nothing runs differently. */
function unstamped(object: Values): Values {
  const metadata = object.metadata as Values;
  const { 'app.kubernetes.io/version': _version, ...labels } = (metadata.labels as Values | undefined) ?? {};
  return { ...object, metadata: { ...metadata, labels } };
}

const noted = (recovered: string, result: ExecutionResult): ExecutionResult =>
  recovered ? { ...result, message: `${recovered}; ${result.message}` } : result;

function reason(error: unknown): string {
  return (error instanceof Error ? error.message : String(error)).trim().split('\n').slice(-3).join(' ');
}

/**
 * Splices each edit into the source text instead of re-rendering the document,
 * which reformats most of the values files. A `before` of null adds the key,
 * and any missing parents, as the first entry of the nearest block map; an
 * `after` of null removes the key.
 */
export function editValues(text: string, set: HelmValuesPlan['operation']['set']): string {
  let result = text;
  for (const { path: dotted, before, after } of set) {
    const doc = parseDocument(result);
    if (doc.errors.length) throw new Error(`values file does not parse: ${doc.errors[0].code}`);
    const keys = valuesKeys(dotted);
    const node = doc.getIn(keys, true);
    if (before === null) {
      let depth = keys.length - 1;
      while (depth > 0 && !doc.hasIn(keys.slice(0, depth))) depth--;
      const parent = depth ? doc.getIn(keys.slice(0, depth), true) : doc.contents;
      const last = isSeq(parent) && !parent.flow ? parent.items.at(-1) : undefined;
      if (node === undefined && isSeq(parent) && keys[depth] === parent.items.length && isNode(last) && last.range) {
        const at = result.indexOf('\n', last.range[1] - 1) + 1;
        const dash = ' '.repeat(last.range[0] - result.lastIndexOf('\n', last.range[0]) - 3);
        const rest = keys.slice(depth + 1);
        const added = parseDocument('');
        added.setIn(
          [0, ...rest],
          after !== null && typeof after === 'object'
            ? added.createNode(after)
            : parseDocument(JSON.stringify(after)).contents,
        );
        result =
          result.slice(0, at) +
          String(added)
            .split('\n')
            .slice(0, -1)
            .map((line) => `${dash}${line}\n`)
            .join('') +
          result.slice(at);
        continue;
      }
      const firstPair = isMap(parent) && !parent.flow ? parent.items[0] : undefined;
      const first = firstPair?.key;
      if (node !== undefined || !isScalar(first) || !first.range) {
        throw new Error(`repo drift: ${dotted} ${node === undefined ? 'has no block map to join' : 'already exists'}`);
      }
      const lineStart = result.lastIndexOf('\n', first.range[0]) + 1;
      const indent = first.range[0] - lineStart;
      const added = parseDocument('');
      added.setIn(
        keys.slice(depth),
        after !== null && typeof after === 'object'
          ? added.createNode(after)
          : parseDocument(JSON.stringify(after)).contents,
      );
      const lines = String(added)
        .split('\n')
        .slice(0, -1)
        .map((line) => `${' '.repeat(indent)}${line}\n`);
      const firstValue = firstPair?.value;
      const at = result.slice(lineStart, first.range[0]).includes('- ')
        ? result.indexOf('\n', (isNode(firstValue) && firstValue.range ? firstValue.range[1] : first.range[1]) - 1) + 1
        : lineStart;
      result = result.slice(0, at) + lines.join('') + result.slice(at);
      continue;
    }
    if (!isNode(node) || !node.range || !isDeepStrictEqual(node.toJSON(), before)) {
      const actual = isScalar(node) ? JSON.stringify(node.value) : 'not a scalar';
      throw new Error(
        `repo drift: ${dotted} is ${ECHOED_KEY_RE.test(dotted) ? actual : 'different'}, not ${JSON.stringify(before)}`,
      );
    }
    if (after === null) {
      const parent = doc.getIn(keys.slice(0, -1), true);
      const key = isMap(parent) ? parent.items.find((pair) => pair.value === node)?.key : undefined;
      if (!isScalar(key) || !key.range) throw new Error(`repo drift: ${dotted} is not a block map entry`);
      result = result.slice(0, result.lastIndexOf('\n', key.range[0]) + 1) + result.slice(node.range[2]);
      continue;
    }
    if ((before !== null && typeof before === 'object') || (after !== null && typeof after === 'object')) {
      doc.setIn(keys, doc.createNode(after));
      result = String(doc);
      continue;
    }
    if (!isScalar(node)) throw new Error(`repo drift: ${dotted} is not a scalar`);
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
  for (const { path: dotted, after } of set)
    if (after === null) expected.deleteIn(valuesKeys(dotted));
    else expected.setIn(valuesKeys(dotted), expected.createNode(after));
  if (!isDeepStrictEqual(parseDocument(result).toJS(), expected.toJS()))
    throw new Error('the edit changes more than the given paths');
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

const COMMITTED = 'committed for the applier, not applied';

export class HelmReleaseExecutor {
  // bind and apply share one checkout and must not overlap a running upgrade.
  private queue: Promise<unknown> = Promise.resolve();

  constructor(private readonly options: HelmReleaseOptions) {}

  bind(plan: HelmValuesPlan): Promise<HelmBinding> {
    return this.serial(() => this.bindNow(plan));
  }

  apply(plan: HelmValuesPlan): Promise<ExecutionResult> {
    return this.serial(async () => {
      const recovered = await this.unstick(plan.target.name, plan.target.namespace ?? '');
      return noted(recovered, await this.applyNow(plan, !!recovered));
    });
  }

  syncValues(plan: HelmSyncPlan): Promise<ExecutionResult> {
    return this.serial(() => this.syncNow(plan));
  }

  bindManifest(plan: ManifestEditPlan): Promise<{ plan: ManifestEditPlan; unchanged: boolean }> {
    return this.serial(async () => {
      await this.sync();
      const { live, path: objectPath } = await this.unchangedManifest(plan);
      const edited = editValues(this.document(plan.operation.file, plan.target).text, plan.operation.set);
      const dry = await this.serverSideApply(objectPath, this.object(edited, plan.target), true);
      const { uid = '', resourceVersion = '' } = (live.metadata as { uid?: string; resourceVersion?: string }) ?? {};
      return {
        plan: { ...plan, target: { ...plan.target, uid, resourceVersion } },
        unchanged: !valuesDiff(declared(live), declared(dry)).length,
      };
    });
  }

  applyManifest(plan: ManifestEditPlan): Promise<ExecutionResult> {
    return this.serial(async () => {
      await this.sync();
      const { live, path: objectPath } = await this.unchangedManifest(plan);
      const metadata = live.metadata as { uid?: string; resourceVersion?: string } | undefined;
      if (metadata?.uid !== plan.target.uid || metadata?.resourceVersion !== plan.target.resourceVersion)
        throw new Error('target UID or resourceVersion changed after proposal');
      const { file } = plan.operation;
      const doc = this.document(file, plan.target);
      const edited = editValues(doc.text, plan.operation.set);
      fs.writeFileSync(path.join(this.options.checkout, file), doc.before + edited + doc.after);
      try {
        if (!plan.commitOnly) await this.serverSideApply(objectPath, this.object(edited, plan.target), false);
        // eslint-disable-next-line no-catch-all/no-catch-all -- a refused apply leaves the repo as it was
      } catch (error) {
        await this.options.git(['checkout', '--', file]);
        return {
          applied: false,
          message: `apply failed (${reason(error)}); ${file} reverted, nothing pushed.`,
          automaticWrites: 0,
        };
      }
      return this.commit(file, `Orfie: ${plan.reason.split('\n', 1)[0]}`, plan.commitOnly ? COMMITTED : 'applied');
    });
  }

  syncManifest(plan: ManifestSyncPlan): Promise<ExecutionResult> {
    return this.serial(async () => {
      const objectPath = await this.objectPath(plan.target);
      const live = declared((await this.options.client.request(objectPath)) as Values);
      const secrets = [...secretKeys(live), ...inlineSecrets(live)];
      if (secrets.length) {
        return {
          applied: false,
          message: `${plan.target.kind} ${plan.target.name} holds inline secret-looking values (${secrets.join(', ')}); nothing written to the public repo.`,
          automaticWrites: 0,
        };
      }
      await this.sync();
      const { file } = plan.operation;
      const absolute = path.join(this.options.checkout, file);
      const text = stringify(live);
      if (!fs.existsSync(absolute)) {
        fs.mkdirSync(path.dirname(absolute), { recursive: true });
        fs.writeFileSync(absolute, text);
      } else {
        const doc = this.findDocument(file, plan.target);
        fs.writeFileSync(absolute, doc ? doc.before + text + doc.after : `${this.read(file).trimEnd()}\n---\n${text}`);
      }
      return this.commit(
        file,
        `Sync ${plan.target.kind} ${plan.target.namespace ?? ''}/${plan.target.name} from live`,
        'wrote the live object',
      );
    });
  }

  install(plan: HelmInstallPlan): Promise<ExecutionResult> {
    return this.serial(async () => {
      const { name: release, namespace } = plan.target;
      const ns = namespace ?? '';
      const { chart, repo, version, file } = plan.operation;
      await this.sync();
      if (!fs.existsSync(path.join(this.options.checkout, file)))
        throw new Error(`${file} is not in k8s.jegor.nl; write it with repo-write first`);
      const recovered = await this.unstick(release, ns);
      const status = await this.status(release, ns);
      if (status && status !== 'uninstalled' && status !== 'failed')
        throw new Error(`${ns}/${release} is already installed; change it with helm-values`);
      const source = { chart, repo, file };
      const shown = parseValues(
        await this.options.helm(['show', 'chart', ...this.chartRef(source), '--version', version]),
      );
      if (shown.name !== chart || shown.version !== version)
        throw new Error(`${repo} does not serve ${chart} ${version}`);
      await this.namespaceReady(ns);
      try {
        await this.options.helm([
          'install',
          release,
          ...this.chartRef(source),
          '--version',
          version,
          '-n',
          ns,
          '-f',
          path.join(this.options.checkout, file),
          '--replace',
          '--wait',
          '--timeout',
          '10m',
        ]);
        // eslint-disable-next-line no-catch-all/no-catch-all -- every install failure uninstalls
      } catch (error) {
        const removed = await this.options.helm(['uninstall', release, '-n', ns, '--wait', '--timeout', '10m']).then(
          () => 'uninstalled again',
          (e: unknown) => `uninstall failed: ${reason(e)}`,
        );
        return noted(recovered, {
          applied: false,
          message: `helm install failed (${reason(error)}); ${removed}.`,
          automaticWrites: 0,
        });
      }
      this.options.remember(`${ns}/${release}`, source);
      return noted(recovered, {
        applied: true,
        message: `installed ${chart} ${version} as ${ns}/${release} from ${file}.`,
        automaticWrites: 0,
      });
    });
  }

  uninstall(plan: HelmUninstallPlan): Promise<ExecutionResult> {
    return this.serial(async () => {
      const { name: release, namespace } = plan.target;
      await this.options.helm(['uninstall', release, '-n', namespace ?? '', '--wait', '--timeout', '10m']);
      return {
        applied: true,
        message: `uninstalled ${namespace}/${release}; its values file stays in k8s.jegor.nl.`,
        automaticWrites: 0,
      };
    });
  }

  /** Writes the file, then applies its objects after a dry run of all of them; a failed apply reverts the file. */
  writeFile(plan: RepoWritePlan): Promise<ExecutionResult> {
    return this.serial(async () => {
      const { path: file, content } = plan.operation;
      await this.sync();
      const absolute = path.join(this.options.checkout, file);
      const existed = fs.existsSync(absolute);
      if (existed && this.read(file) === content)
        return { applied: true, message: `${file} already holds that content.`, automaticWrites: 0 };
      const objects: Array<{ path: string; object: Values; namespace: string; newNamespace?: string }> = [];
      for (const object of plan.commitOnly ? [] : repoObjects(content)) {
        const { name = '', namespace = null } = object.metadata ?? {};
        const objectPath = await this.objectPath({ ...plan.target, ...object, name, namespace });
        const checkLive =
          object.kind === 'Namespace' || ['Deployment', 'StatefulSet', 'DaemonSet', 'CronJob'].includes(object.kind);
        const live = checkLive
          ? await this.options.client.request(objectPath).then(
              () => true,
              () => false,
            )
          : false;
        // Existing workloads change through manifest-edit, which holds the owner's version and scale rules.
        if (object.kind !== 'Namespace' && live)
          throw new Error(`${object.kind} ${namespace}/${name} exists; change it with manifest-edit`);
        objects.push({
          path: objectPath,
          object: object as Values,
          namespace: String(namespace ?? ''),
          ...(!live && object.kind === 'Namespace' ? { newNamespace: name } : {}),
        });
      }
      const newNamespaces = new Set(objects.flatMap(({ newNamespace }) => (newNamespace ? [newNamespace] : [])));
      for (const { path: objectPath, object, namespace } of objects)
        if (!newNamespaces.has(namespace)) await this.serverSideApply(objectPath, object, true);
      fs.mkdirSync(path.dirname(absolute), { recursive: true });
      fs.writeFileSync(absolute, content);
      let applied = 0;
      try {
        for (const { path: objectPath, object, newNamespace } of objects.filter(
          ({ object }) => object.kind === 'Namespace',
        )) {
          await this.serverSideApply(objectPath, object, false);
          applied++;
          if (newNamespace) await this.waitForNamespace(newNamespace);
        }
        for (const { path: objectPath, object, namespace } of objects.filter(
          ({ object }) => object.kind !== 'Namespace',
        )) {
          if (newNamespaces.has(namespace)) await this.serverSideApply(objectPath, object, true);
          await this.serverSideApply(objectPath, object, false);
          applied++;
        }
        // eslint-disable-next-line no-catch-all/no-catch-all -- a refused apply leaves the repo as it was
      } catch (error) {
        if (existed) await this.options.git(['checkout', '--', file]);
        else fs.rmSync(absolute);
        return {
          applied: false,
          message: `apply failed after ${applied} of ${objects.length} objects (${reason(error)}); ${file} reverted, nothing pushed.`,
          automaticWrites: 0,
        };
      }
      return this.commit(
        file,
        `Orfie: ${plan.reason.split('\n', 1)[0]}`,
        plan.commitOnly ? COMMITTED : `applied ${objects.length} objects`,
      );
    });
  }

  async writeSecret(plan: SecretWritePlan): Promise<ExecutionResult> {
    const { name, namespace } = plan.target;
    const { secretType, stringData } = plan.operation;
    try {
      await this.serverSideApply(
        `/api/v1/namespaces/${encodeURIComponent(namespace ?? '')}/secrets/${encodeURIComponent(name)}`,
        { apiVersion: 'v1', kind: 'Secret', metadata: { name, namespace }, type: secretType, stringData },
        false,
      );
      // eslint-disable-next-line no-catch-all/no-catch-all -- the API error may quote a value, so it is redacted first
    } catch (error) {
      const redacted = Object.values(stringData)
        .filter(Boolean)
        .reduce((text, value) => text.replaceAll(value, '***'), reason(error));
      return { applied: false, message: `writing Secret ${namespace}/${name} failed: ${redacted}`, automaticWrites: 0 };
    }
    return {
      applied: true,
      message: `wrote Secret ${namespace}/${name} with keys ${Object.keys(stringData).join(', ')}.`,
      automaticWrites: 0,
    };
  }

  /** A text file of the checkout, at most 64 KB, or a directory listing with a trailing / on subdirectories. */
  readRepo(relative: string): Promise<string> {
    return this.serial(async () => {
      if (!/^[\w.-]+(?:\/[\w.-]+)*$|^$/.test(relative) || relative.split('/').includes('..'))
        throw new Error('path must be relative to the k8s.jegor.nl root');
      await this.sync();
      const root = fs.realpathSync(this.options.checkout);
      const absolute = path.join(root, relative);
      if (fs.realpathSync(absolute) !== absolute) throw new Error(`${relative} is a symlink`);
      if (fs.statSync(absolute).isDirectory())
        return fs
          .readdirSync(absolute, { withFileTypes: true })
          .filter((entry) => entry.name !== '.git')
          .map((entry) => `${entry.name}${entry.isDirectory() ? '/' : ''}`)
          .join('\n');
      if (fs.statSync(absolute).size > 64 * 1024) throw new Error(`${relative} is larger than 64 KB`);
      return fs.readFileSync(absolute, 'utf8');
    });
  }

  /** Creates the namespace and waits for namespace-binder to give this identity its rights there. */
  private async namespaceReady(ns: string): Promise<void> {
    const exists = await this.options.client.request(`/api/v1/namespaces/${encodeURIComponent(ns)}`).then(
      () => true,
      () => false,
    );
    if (!exists)
      await this.options.client.request('/api/v1/namespaces', {
        method: 'POST',
        body: { apiVersion: 'v1', kind: 'Namespace', metadata: { name: ns } },
      });
    for (let attempt = 0; ; attempt++) {
      try {
        await this.options.client.request(`/api/v1/namespaces/${encodeURIComponent(ns)}/configmaps?limit=1`);
        return;
      } catch (error) {
        if (attempt >= 30) throw error;
        await new Promise((resolve) => setTimeout(resolve, 1000));
      }
    }
  }

  private findDocument(file: string, target: TargetRef) {
    const text = this.read(file);
    for (const doc of parseAllDocuments(text)) {
      if (!('contents' in doc) || !doc.range) continue;
      const object = (doc.toJS() ?? {}) as {
        apiVersion?: string;
        kind?: string;
        metadata?: { name?: string; namespace?: string };
      };
      if (
        object.apiVersion === target.apiVersion &&
        object.kind === target.kind &&
        object.metadata?.name === target.name &&
        (object.metadata.namespace ?? target.namespace) === target.namespace
      ) {
        const [start, , end] = doc.range;
        return { before: text.slice(0, start), text: text.slice(start, end), after: text.slice(end) };
      }
    }
    return undefined;
  }

  private document(file: string, target: TargetRef) {
    const doc = this.findDocument(file, target);
    if (!doc)
      throw new Error(`repo manifest drift; submit manifest-sync first: ${file} has no ${target.kind} ${target.name}`);
    return doc;
  }

  private object(text: string, target: TargetRef): Values {
    const object = parseValues(text);
    const metadata = (object.metadata as Values | undefined) ?? {};
    return target.namespace ? { ...object, metadata: { ...metadata, namespace: target.namespace } } : object;
  }

  /** The live object, after a server-side dry run proves the unedited manifest would not change it. */
  private async unchangedManifest(plan: ManifestEditPlan) {
    const objectPath = await this.objectPath(plan.target);
    const live = (await this.options.client.request(objectPath)) as Values;
    if (!fs.existsSync(path.join(this.options.checkout, plan.operation.file)))
      throw new Error(`repo manifest drift; submit manifest-sync first: ${plan.operation.file} does not exist`);
    const dry = await this.serverSideApply(
      objectPath,
      this.object(this.document(plan.operation.file, plan.target).text, plan.target),
      true,
    );
    const drift = valuesDiff(declared(live), declared(dry));
    if (drift.length) throw new Error(`repo manifest drift; submit manifest-sync first: ${drift.join('; ')}`);
    return { live, path: objectPath };
  }

  private async serverSideApply(objectPath: string, object: Values, dryRun: boolean): Promise<Values> {
    const query = `?fieldManager=orfie&force=true${dryRun ? '&dryRun=All' : ''}`;
    return (await this.options.client.request(`${objectPath}${query}`, {
      method: 'PATCH',
      body: object,
      contentType: 'application/apply-patch+yaml',
    })) as Values;
  }

  private async waitForNamespace(namespace: string): Promise<void> {
    const deadline = Date.now() + 180_000;
    do {
      const review = (await this.options.client.request('/apis/authorization.k8s.io/v1/selfsubjectaccessreviews', {
        method: 'POST',
        body: {
          apiVersion: 'authorization.k8s.io/v1',
          kind: 'SelfSubjectAccessReview',
          spec: { resourceAttributes: { namespace, verb: 'create', group: '', resource: 'serviceaccounts' } },
        },
      })) as { status?: { allowed?: boolean } };
      if (review.status?.allowed) return;
      await new Promise((resolve) => setTimeout(resolve, 2_000));
    } while (Date.now() < deadline);
    throw new Error(`namespace binder did not grant nanoclaw-helm access to ${namespace}`);
  }

  private async objectPath({ apiVersion, kind, namespace, name }: TargetRef): Promise<string> {
    const base = apiVersion.includes('/') ? `/apis/${apiVersion}` : `/api/${apiVersion}`;
    const list = (await this.options.client.request(base)) as {
      resources?: Array<{ name: string; kind: string; namespaced: boolean }>;
    };
    const resource = list.resources?.find((r) => r.kind === kind && !r.name.includes('/'));
    if (!resource) throw new Error(`the API server does not serve ${apiVersion} ${kind}`);
    const scope = resource.namespaced ? `/namespaces/${encodeURIComponent(namespace ?? 'default')}` : '';
    return `${base}${scope}/${resource.name}/${encodeURIComponent(name)}`;
  }

  /** Binds the plan to the release's latest revision Secret, its verified chart and its live values. */
  private async bindNow(plan: HelmValuesPlan): Promise<HelmBinding> {
    const { name: release, namespace } = plan.target;
    const ns = namespace ?? '';
    const { chart, metadata } = await this.resolveChart(plan);
    const anchor = await this.latestRelease(plan);
    await this.sync();
    const text = await this.unchangedFromLive(plan);
    const live = parseValues(text);
    const edited = editValues(text, plan.operation.set);
    const installed = objects(await this.options.helm(['get', 'manifest', release, '-n', ns]));
    const rendered = await this.render(release, ns, chart, metadata.version, edited);
    const [before, after] = [manifestImages(installed), manifestImages(rendered)];
    const stateful = installed.filter((object) => object.kind === 'StatefulSet') as Array<{ spec?: Workload['spec'] }>;
    return {
      plan: { ...plan, target: { ...plan.target, ...anchor } },
      diff: valuesDiff(live, parseValues(edited)),
      images: Object.fromEntries(
        [...after]
          .filter(([key, image]) => before.get(key) !== image)
          .map(([key, image]) => [key, { before: before.get(key), after: image }]),
      ),
      statefulRepositories: stateful.flatMap(({ spec }) =>
        [...(spec?.template?.spec?.containers ?? []), ...(spec?.template?.spec?.initContainers ?? [])].map((c) =>
          imageRepository(c.image ?? ''),
        ),
      ),
      hasStatefulSet: stateful.length > 0,
      unchanged: await this.matchesLive(rendered, ns),
    };
  }

  /** The release's objects as Helm would apply them with these values. */
  private async render(release: string, ns: string, chart: HelmChart, version: string, values: string) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'orfie-values-'));
    fs.writeFileSync(path.join(dir, 'values.yaml'), values);
    try {
      const { manifest = '' } = JSON.parse(
        await this.options.helm([
          'upgrade',
          release,
          ...this.chartRef(chart),
          '--version',
          version,
          '-n',
          ns,
          '-f',
          path.join(dir, 'values.yaml'),
          '--dry-run=server',
          '-o',
          'json',
        ]),
      ) as { manifest?: string };
      return objects(manifest);
    } catch (error) {
      throw new Error(`helm cannot render the edited values: ${reason(error)}`, { cause: error });
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }

  /** true when applying these objects leaves every live object as it is. */
  private async matchesLive(rendered: Values[], ns: string): Promise<boolean> {
    try {
      for (const object of rendered) {
        const { name = '', namespace = ns } = (object.metadata as { name?: string; namespace?: string }) ?? {};
        const objectPath = await this.objectPath({
          apiVersion: String(object.apiVersion),
          kind: String(object.kind),
          namespace,
          name,
          uid: '',
          resourceVersion: '',
        });
        const live = (await this.options.client.request(objectPath)) as Values;
        const dry = await this.serverSideApply(
          objectPath,
          { ...object, metadata: { ...(object.metadata as Values), namespace } },
          true,
        );
        if (valuesDiff(unstamped(declared(live)), unstamped(declared(dry))).length) return false;
      }
      return rendered.length > 0;
      // eslint-disable-next-line no-catch-all/no-catch-all -- anything it cannot prove unchanged counts as a change
    } catch {
      return false;
    }
  }

  private async status(release: string, ns: string): Promise<string | undefined> {
    return this.options.helm(['status', release, '-n', ns, '-o', 'json']).then(
      (out) => (JSON.parse(out) as { info?: { status?: string } }).info?.status,
      () => undefined,
    );
  }

  /** A release a killed helm left pending, as a host restart mid-operation does, back to its last good state. */
  private async unstick(release: string, ns: string): Promise<string> {
    const status = await this.status(release, ns);
    if (!status?.startsWith('pending-') && status !== 'uninstalling') return '';
    const history = JSON.parse(await this.options.helm(['history', release, '-n', ns, '-o', 'json'])) as Array<{
      revision: number;
      status: string;
    }>;
    const good = history.filter((h) => h.status === 'deployed' || h.status === 'superseded').at(-1);
    if (status === 'pending-install' || status === 'uninstalling' || !good) {
      await this.options.helm(['uninstall', release, '-n', ns, '--keep-history', '--wait', '--timeout', '10m']);
      return `found ${ns}/${release} stuck in ${status} and uninstalled it`;
    }
    return `found ${ns}/${release} stuck in ${status}; ${await this.rollback(release, ns, good.revision)}`;
  }

  private async applyNow(plan: HelmValuesPlan, recovered: boolean): Promise<ExecutionResult> {
    const { name: release, namespace } = plan.target;
    const ns = namespace ?? '';
    const anchor = await this.latestRelease(plan);
    // A recovery rollback is a new revision of the host's own making, not a change behind the plan's back.
    if (!recovered && (anchor.uid !== plan.target.uid || anchor.resourceVersion !== plan.target.resourceVersion)) {
      throw new Error('Helm release changed after proposal');
    }
    const { chart, metadata } = await this.resolveChart(plan);
    await this.sync();
    const file = path.join(this.options.checkout, plan.operation.file);
    fs.writeFileSync(file, editValues(await this.unchangedFromLive(plan), plan.operation.set));
    if (plan.commitOnly) return this.commit(plan.operation.file, `Orfie: ${plan.reason.split('\n', 1)[0]}`, COMMITTED);

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
    const relative = plan.operation.file;
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
    }
    await this.options.git(['config', 'remote.origin.url', this.options.remote]);
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

  /**
   * The workload guard admits an earlier revision's unpinned images only on
   * workloads carrying ROLLBACK_ANNOTATION, so the annotation brackets the rollback.
   */
  private async rollback(release: string, ns: string, revision: number): Promise<string> {
    const workloads = parseAllDocuments(
      await this.options.helm(['get', 'manifest', release, '-n', ns, '--revision', String(revision)]).catch(() => ''),
    )
      .map((doc) => doc.toJS() as { kind?: string; metadata?: { name?: string } } | null)
      .filter((object) => ['Deployment', 'StatefulSet', 'DaemonSet'].includes(object?.kind ?? ''))
      .map(
        (object) =>
          `/apis/apps/v1/namespaces/${encodeURIComponent(ns)}/${object!.kind!.toLowerCase()}s/${encodeURIComponent(object!.metadata?.name ?? '')}`,
      );
    const annotate = (value: string | null) =>
      Promise.allSettled(
        workloads.map((url) =>
          this.options.client.request(url, {
            method: 'PATCH',
            body: { metadata: { annotations: { [ROLLBACK_ANNOTATION]: value } } },
            contentType: 'application/merge-patch+json',
          }),
        ),
      );
    await annotate(String(revision));
    try {
      await this.options.helm(['rollback', release, String(revision), '-n', ns, '--wait', '--timeout', '10m']);
      return `rolled back to revision ${revision}`;
      // eslint-disable-next-line no-catch-all/no-catch-all -- a failed rollback is reported, not thrown over the upgrade error
    } catch (error) {
      return `rollback to revision ${revision} failed: ${reason(error)}`;
    } finally {
      await annotate(null);
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
