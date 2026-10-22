/**
 * check_updates: newer chart versions for every Helm release and newer image
 * tags for every running workload image, as two column/row tables. A newer
 * tag must keep the running tag's shape: same `v` prefix, same number of
 * version components and the same suffix (`-rootless`, `-apache`), so a
 * variant never jumps to another variant or a pre-release.
 */
import { parse } from 'yaml';

import type { KubernetesJsonClient } from './gateway-client.js';
import type { HelmChart } from './helm-release.js';
import { parseImage } from './policy.js';
import { listTags, tagDigest, type RegistryFetch } from './registry.js';

const HOUR = 60 * 60_000;
const MAX_REPORT = 64 * 1024;
const TAG_RE = /^(v?)(\d+)((?:\.\d+){0,2})(.*)$/;

type Version = { tag: string; parts: number[]; family: string };
type ChartVersion = { version: string; appVersion?: string };
interface PodSpec {
  containers?: Array<{ name: string; image: string }>;
  initContainers?: Array<{ name: string; image: string }>;
}
interface WorkloadItem {
  metadata: { namespace: string; name: string };
  spec?: { template?: { spec?: PodSpec }; jobTemplate?: { spec?: { template?: { spec?: PodSpec } } } };
}

function version(tag: string): Version | undefined {
  const match = TAG_RE.exec(tag);
  if (!match) return undefined;
  const parts = [match[2], ...match[3].split('.').slice(1)].map(Number);
  return { tag, parts, family: `${match[1]}|${parts.length}|${match[4]}` };
}

const newer = (a: Version, b: Version) => {
  for (let i = 0; i < a.parts.length; i++) if (a.parts[i] !== b.parts[i]) return a.parts[i] > b.parts[i];
  return false;
};

/** The highest same-family candidate within the same major and minor, the same major, and overall. */
export function latest(running: string, candidates: string[]) {
  const current = version(running);
  if (!current) return undefined;
  const best = (same: number) =>
    candidates
      .map(version)
      .filter(
        (v): v is Version =>
          !!v && v.family === current.family && v.parts.slice(0, same).join() === current.parts.slice(0, same).join(),
      )
      .reduce((top, v) => (newer(v, top) ? v : top), current).tag;
  return { patch: best(Math.min(2, current.parts.length - 1)), minor: best(1), major: best(0) };
}

function bump(from: string, to: string): 'none' | 'patch' | 'minor' | 'major' {
  const [a, b] = [version(from)?.parts ?? [], version(to)?.parts ?? []];
  if (a[0] !== b[0]) return 'major';
  if (a[1] !== b[1]) return 'minor';
  return from === to ? 'none' : 'patch';
}

async function pool<T, R>(items: T[], size: number, task: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = [];
  for (let i = 0; i < items.length; i += size) out.push(...(await Promise.all(items.slice(i, i + size).map(task))));
  return out;
}

export function createUpdateChecker(options: {
  reader: KubernetesJsonClient;
  helm: (args: string[]) => Promise<string>;
  charts: Record<string, HelmChart>;
  fetch: RegistryFetch;
}): () => Promise<string> {
  const indexes = new Map<string, { at: number; versions: Promise<Record<string, ChartVersion[]>> }>();
  const chartVersions = (repo: string, chart: string) => {
    const key = repo.startsWith('oci://') ? `${repo}/${chart}` : repo;
    const cached = indexes.get(key);
    if (cached && Date.now() - cached.at < HOUR) return cached.versions.then((index) => index[chart] ?? []);
    const versions = repo.startsWith('oci://')
      ? (() => {
          const [registry, ...path] = repo.slice('oci://'.length).replace(/\/$/, '').split('/');
          return listTags(registry, [...path, chart].join('/'), options.fetch).then((tags) => ({
            [chart]: tags.map((tag): ChartVersion => ({ version: tag })),
          }));
        })()
      : options.fetch(`${repo.replace(/\/$/, '')}/index.yaml`, {}).then((response) => {
          if (response.status !== 200) throw new Error(`HTTP ${response.status}`);
          return (parse(response.body) as { entries?: Record<string, ChartVersion[]> }).entries ?? {};
        });
    indexes.set(key, { at: Date.now(), versions });
    versions.catch(() => indexes.delete(key));
    return versions.then((index) => index[chart] ?? []);
  };

  const helmRows = async () => {
    const namespaces =
      ((await options.reader.request('/api/v1/namespaces')) as { items?: Array<{ metadata: { name: string } }> }).items
        ?.map((item) => item.metadata.name)
        .filter((namespace) => !['nanoclaw-remediator', 'orfie-ci'].includes(namespace)) ?? [];
    const releases = (
      await pool(namespaces, 4, async (namespace) =>
        JSON.parse(await options.helm(['list', '-n', namespace, '-o', 'json'])),
      )
    ).flat() as Array<{
      name: string;
      namespace: string;
      chart: string;
      app_version?: string;
    }>;
    return pool(releases, 4, async ({ name, namespace, chart: ref, app_version }) => {
      const [, chart = ref, installed = ''] = /^(.+?)-(v?\d+\.\d+\.\d+(?:[-+].*)?)$/.exec(ref) ?? [];
      const repo = options.charts[`${namespace}/${name}`]?.repo;
      const versions = repo ? await chartVersions(repo, chart).catch(() => undefined) : undefined;
      const stable = (versions ?? []).filter((v) => !/[-+]/.test(v.version));
      const top =
        versions &&
        latest(
          installed,
          stable.map((v) => v.version),
        )?.major;
      const appVersion = stable.find((v) => v.version === top)?.appVersion ?? null;
      return [
        `${namespace}/${name}`,
        chart,
        installed,
        versions ? (top ?? null) : repo ? 'repo unreachable' : 'repo unknown; name it in a helm-values plan once',
        app_version ?? null,
        appVersion,
        top ? bump(installed, top) : null,
      ];
    });
  };

  const imageRows = async () => {
    const lists = await Promise.all(
      ['apps/v1/deployments', 'apps/v1/statefulsets', 'apps/v1/daemonsets', 'batch/v1/cronjobs'].map((path) =>
        options.reader.request(`/apis/${path}`),
      ),
    );
    const containers = lists.flatMap((list) =>
      ((list as { items?: WorkloadItem[] }).items ?? []).flatMap((item) => {
        const spec = item.spec?.jobTemplate?.spec?.template?.spec ?? item.spec?.template?.spec;
        return [...(spec?.containers ?? []), ...(spec?.initContainers ?? [])].map((c) => ({
          workload: `${item.metadata.namespace}/${item.metadata.name}`,
          container: c.name,
          image: c.image,
        }));
      }),
    );
    const tags = new Map<string, Promise<string[]>>();
    const digests = new Map<string, Promise<string | undefined>>();
    return pool(containers, 8, async ({ workload, container, image }) => {
      const { registry, repository, tag } = parseImage(image);
      const key = `${registry}/${repository}`;
      if (!tag || !version(tag)) return null;
      if (!tags.has(key))
        tags.set(
          key,
          listTags(registry, repository, options.fetch).catch(() => []),
        );
      const found = latest(tag, await tags.get(key)!);
      if (!found) return null;
      const pinned = await Promise.all(
        [...new Set([found.patch, found.minor, found.major])]
          .filter((t) => t !== tag)
          .map(async (t) => {
            if (!digests.has(`${key}:${t}`))
              digests.set(
                `${key}:${t}`,
                tagDigest(registry, repository, t, options.fetch).catch(() => undefined),
              );
            return `${t}@${(await digests.get(`${key}:${t}`)) ?? '?'}`;
          }),
      );
      return [workload, container, key, tag, found.patch, found.minor, found.major, pinned.join(' ')];
    }).then((rows) => rows.filter((row) => row !== null));
  };

  return async () => {
    const [helm, images] = await Promise.all([helmRows(), imageRows()]);
    const report = {
      helm: {
        columns: [
          'release',
          'chart',
          'installedChartVersion',
          'latestChartVersion',
          'installedAppVersion',
          'latestAppVersion',
          'bump',
        ],
        rows: helm,
      },
      images: {
        columns: [
          'workload',
          'container',
          'image',
          'runningTag',
          'latestPatch',
          'latestMinor',
          'latestMajor',
          'digests',
        ],
        rows: images,
      },
    };
    // Rows already on their newest tag are dropped first when the report would not fit.
    if (JSON.stringify(report).length > MAX_REPORT)
      report.images.rows = report.images.rows.filter((row) => row[3] !== row[6]);
    const text = JSON.stringify(report);
    return text.length > MAX_REPORT ? `${text.slice(0, MAX_REPORT)}\n(truncated)` : text;
  };
}
