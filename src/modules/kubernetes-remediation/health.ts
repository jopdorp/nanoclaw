/**
 * Health triggers next to Trivy and Falco: Alertmanager, Uptime Kuma and
 * CrowdSec webhooks, and a host-side poll of the cluster that needs no metrics stack.
 * Each condition, id `health:<check>:<condition>:<object>`, is one incident
 * while it lasts and one resolved note when it clears; the poll keeps its
 * active conditions on disk so a host restart does not replay them.
 */
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import type http from 'node:http';

import type { KubernetesJsonClient } from './gateway-client.js';
import { createWebhookHandler, type IncidentSink, PersistentDedupe, record, text } from './triggers.js';
import type { RemediationIncident } from './types.js';

type Handler = (req: http.IncomingMessage, res: http.ServerResponse) => Promise<void>;
type Item = Record<string, unknown>;

const MINUTE = 60_000;
const DAY = 24 * 60 * MINUTE;

function incident(
  source: RemediationIncident['source'],
  fields: Partial<RemediationIncident> & { id: string; summary: string },
): RemediationIncident {
  return {
    source,
    observedAt: new Date().toISOString(),
    namespace: null,
    workload: null,
    severity: 'warning',
    evidence: {},
    ...fields,
  };
}

/** Many at once become one digest, so a first poll or an alert storm is one wake. */
function batched(source: RemediationIncident['source'], incidents: RemediationIncident[]): RemediationIncident[] {
  if (incidents.length <= 5) return incidents;
  const ids = incidents.map((i) => i.id).sort();
  return [
    incident(source, {
      id: `${source}-digest:${createHash('sha256').update(ids.join('\n')).digest('hex').slice(0, 16)}`,
      severity: incidents.every((i) => i.severity === 'resolved') ? 'resolved' : 'warning',
      summary: `${incidents.length} ${source} conditions`,
      evidence: { incidents: incidents.slice(0, 40).map(({ id, severity, summary }) => ({ id, severity, summary })) },
    }),
  ];
}

export function alertmanagerIncidents(payload: Item): RemediationIncident[] {
  return (Array.isArray(payload.alerts) ? payload.alerts : []).flatMap((raw) => {
    const alert = record(raw);
    const labels = record(alert?.labels) ?? {};
    const annotations = record(alert?.annotations) ?? {};
    const fingerprint = text(alert?.fingerprint);
    if (!alert || !fingerprint) return [];
    const resolved = alert.status === 'resolved';
    const name = text(labels.alertname) ?? 'alert';
    return [
      incident('alertmanager', {
        id: `alert:${fingerprint}:${text(alert.startsAt) ?? ''}${resolved ? ':resolved' : ''}`,
        observedAt: text(resolved ? alert.endsAt : alert.startsAt) ?? new Date().toISOString(),
        namespace: text(labels.namespace),
        workload: text(labels.pod) ? { kind: 'Pod', name: String(labels.pod) } : null,
        severity: resolved ? 'resolved' : (text(labels.severity) ?? 'warning'),
        summary: `${name}: ${text(annotations.summary) ?? text(annotations.description) ?? 'no summary'}`,
        evidence: { labels, annotations, generatorURL: alert.generatorURL ?? null, groupKey: payload.groupKey ?? null },
      }),
    ];
  });
}

export function uptimeKumaIncidents(payload: Item, body: Buffer): RemediationIncident[] {
  const heartbeat = record(payload.heartbeat);
  const monitor = record(payload.monitor);
  const up = heartbeat?.status === 1;
  const id = heartbeat
    ? `kuma:${String(monitor?.id ?? heartbeat.monitorID)}:${String(heartbeat.time)}`
    : `kuma:test:${createHash('sha256').update(body).digest('hex').slice(0, 16)}`;
  return [
    incident('uptime-kuma', {
      id,
      severity: !heartbeat ? 'info' : up ? 'resolved' : 'critical',
      summary: `${text(monitor?.name) ?? 'Uptime Kuma'} ${!heartbeat ? 'test' : up ? 'is up' : 'is down'}: ${text(heartbeat?.msg) ?? text(payload.msg) ?? ''}`,
      evidence: {
        monitor: { name: monitor?.name ?? null, url: monitor?.url ?? null, type: monitor?.type ?? null },
        heartbeat,
      },
    }),
  ];
}

/** CrowdSec's http notification plugin, with format `{"alerts": {{.|toJson}}}`. */
export function crowdsecIncidents(payload: Item, body: Buffer): RemediationIncident[] {
  return (Array.isArray(payload.alerts) ? payload.alerts : []).flatMap((raw) => {
    const alert = record(raw);
    if (!alert) return [];
    const source = record(alert.source) ?? {};
    const decision = record((alert.decisions as unknown[] | undefined)?.[0]);
    const key = text(alert.uuid) ?? String(alert.id ?? createHash('sha256').update(body).digest('hex').slice(0, 16));
    return [
      incident('crowdsec', {
        id: `crowdsec:${key}`,
        severity: decision ? 'warning' : 'info',
        summary: `${text(alert.scenario) ?? 'CrowdSec alert'} from ${text(source.value) ?? text(source.ip) ?? 'unknown'}${decision ? `, ${String(decision.type)} for ${String(decision.duration)}` : ''}`,
        evidence: {
          message: alert.message ?? null,
          source,
          decisions: alert.decisions ?? [],
          events: alert.events_count ?? null,
        },
      }),
    ];
  });
}

export function createAlertWebhookHandlers(options: { secret: () => Buffer; sink: IncidentSink; seenFile?: string }): {
  alertmanager: Handler;
  uptimeKuma: Handler;
  crowdsec: Handler;
} {
  const seen = new PersistentDedupe(options.seenFile);
  const fresh = (incidents: RemediationIncident[]) => incidents.filter((i) => seen.add(i.id));
  return {
    alertmanager: createWebhookHandler({
      ...options,
      incidents: (payload) => batched('alertmanager', fresh(alertmanagerIncidents(payload))),
    }),
    uptimeKuma: createWebhookHandler({
      ...options,
      incidents: (payload, body) => fresh(uptimeKumaIncidents(payload, body)),
    }),
    crowdsec: createWebhookHandler({
      ...options,
      incidents: (payload, body) => batched('crowdsec', fresh(crowdsecIncidents(payload, body))),
    }),
  };
}

interface Finding {
  id: string;
  summary: string;
  severity: string;
  namespace?: string | null;
  workload?: { kind: string; name: string } | null;
  /** Only reported once the condition has held this long. */
  forMs?: number;
}

const items = (list: unknown): Item[] => (Array.isArray(record(list)?.items) ? (record(list)!.items as Item[]) : []);
const meta = (item: Item) => record(item.metadata) ?? {};
const status = (item: Item) => record(item.status) ?? {};
const condition = (item: Item, type: string) =>
  (Array.isArray(status(item).conditions) ? (status(item).conditions as Item[]) : []).find((c) => c.type === type);

/** One list per check; a check whose list fails is skipped, so its conditions neither fire nor clear. */
const CHECKS: Record<string, { path: string; findings: (items: Item[], now: number) => Finding[] }> = {
  pods: {
    path: '/api/v1/pods',
    findings: (pods, now) =>
      pods.flatMap((pod) => {
        const { namespace, name } = meta(pod) as { namespace: string; name: string };
        const owner = record((meta(pod).ownerReferences as unknown[] | undefined)?.[0]);
        const workload = { kind: text(owner?.kind) ?? 'Pod', name: text(owner?.name) ?? name };
        const containers = [
          ...((status(pod).containerStatuses as Item[]) ?? []),
          ...((status(pod).initContainerStatuses as Item[]) ?? []),
        ];
        return containers.flatMap((c) => {
          const waiting = record(record(c.state)?.waiting);
          const last = record(record(c.lastState)?.terminated);
          const key = `${namespace}/${workload.name}/${String(c.name)}`;
          const out: Finding[] = [];
          if (waiting?.reason === 'CrashLoopBackOff')
            out.push({
              id: `health:pods:crashloop:${key}`,
              severity: 'critical',
              namespace,
              workload,
              summary: `${key} is crash-looping (${String(c.restartCount)} restarts, last exit ${String(last?.reason ?? last?.exitCode ?? 'unknown')})`,
            });
          if (last?.reason === 'OOMKilled' && now - Date.parse(String(last.finishedAt)) < 30 * MINUTE)
            out.push({
              id: `health:pods:oomkilled:${key}`,
              severity: 'warning',
              namespace,
              workload,
              summary: `${key} was OOM-killed at ${String(last.finishedAt)}`,
            });
          return out;
        });
      }),
  },
  nodes: {
    path: '/api/v1/nodes',
    findings: (nodes) =>
      nodes.flatMap((node) => {
        const ready = condition(node, 'Ready');
        return ready?.status === 'True'
          ? []
          : [
              {
                id: `health:nodes:notready:${String(meta(node).name)}`,
                severity: 'critical',
                summary: `node ${String(meta(node).name)} is NotReady: ${String(ready?.reason ?? 'no Ready condition')}`,
              },
            ];
      }),
  },
  jobs: {
    path: '/apis/batch/v1/jobs',
    findings: (jobs) =>
      jobs.flatMap((job) => {
        const failed = condition(job, 'Failed');
        if (failed?.status !== 'True') return [];
        const { namespace, name } = meta(job) as { namespace: string; name: string };
        const owner = record((meta(job).ownerReferences as unknown[] | undefined)?.[0]);
        return [
          {
            id: `health:jobs:failed:${namespace}/${name}`,
            severity: 'warning',
            namespace,
            workload: { kind: text(owner?.kind) ?? 'Job', name: text(owner?.name) ?? name },
            summary:
              `Job ${namespace}/${name} failed: ${String(failed.reason ?? '')} ${String(failed.message ?? '')}`.trim(),
          },
        ];
      }),
  },
  deployments: {
    path: '/apis/apps/v1/deployments',
    findings: (deployments) =>
      deployments.flatMap((deployment) => {
        const unavailable = Number(status(deployment).unavailableReplicas ?? 0);
        const { namespace, name } = meta(deployment) as { namespace: string; name: string };
        return unavailable > 0
          ? [
              {
                id: `health:deployments:unavailable:${namespace}/${name}`,
                severity: 'warning',
                namespace,
                workload: { kind: 'Deployment', name },
                summary: `Deployment ${namespace}/${name} has ${unavailable} unavailable replicas for over 10 minutes`,
                forMs: 10 * MINUTE,
              },
            ]
          : [];
      }),
  },
  volumes: {
    path: '/apis/longhorn.io/v1beta2/volumes',
    findings: (volumes) =>
      volumes.flatMap((volume) => {
        const size = Number(record(volume.spec)?.size ?? 0);
        const used = Number(status(volume).actualSize ?? 0);
        const pvc = record(status(volume).kubernetesStatus);
        const claim = `${String(pvc?.namespace ?? '')}/${String(pvc?.pvcName ?? meta(volume).name)}`;
        return size > 0 && used / size > 0.85
          ? [
              {
                id: `health:volumes:full:${String(meta(volume).name)}`,
                severity: 'warning',
                namespace: text(pvc?.namespace),
                summary: `Longhorn volume ${String(meta(volume).name)} (${claim}) is ${Math.round((100 * used) / size)}% allocated, snapshots included`,
              },
            ]
          : [];
      }),
  },
  certificates: {
    path: '/apis/cert-manager.io/v1/certificates',
    findings: (certificates, now) =>
      certificates.flatMap((certificate) => {
        const { namespace, name } = meta(certificate) as { namespace: string; name: string };
        const ready = condition(certificate, 'Ready');
        const notAfter = Date.parse(String(status(certificate).notAfter ?? ''));
        const out: Finding[] = [];
        if (ready?.status !== 'True')
          out.push({
            id: `health:certificates:notready:${namespace}/${name}`,
            severity: 'warning',
            namespace,
            summary: `Certificate ${namespace}/${name} is not Ready: ${String(ready?.message ?? 'no Ready condition')}`,
          });
        if (notAfter - now < 14 * DAY)
          out.push({
            id: `health:certificates:expiring:${namespace}/${name}`,
            severity: 'warning',
            namespace,
            summary: `Certificate ${namespace}/${name} expires ${new Date(notAfter).toISOString()}`,
          });
        return out;
      }),
  },
};

export async function runHealthWatch(
  client: KubernetesJsonClient,
  sink: IncidentSink,
  signal: AbortSignal,
  stateFile: string,
  intervalMs = MINUTE,
): Promise<void> {
  const active = (fs.existsSync(stateFile) ? JSON.parse(fs.readFileSync(stateFile, 'utf8')) : {}) as Record<
    string,
    string
  >;
  const since = new Map<string, number>();
  while (!signal.aborted) {
    const now = Date.now();
    const fired: RemediationIncident[] = [];
    const cleared: RemediationIncident[] = [];
    for (const [check, { path, findings }] of Object.entries(CHECKS)) {
      let found: Finding[];
      try {
        found = findings(items(await client.request(path, { signal })), now);
        // eslint-disable-next-line no-catch-all/no-catch-all -- an absent CRD or a failed list skips the check this round
      } catch {
        continue;
      }
      const current = new Set(found.map((f) => f.id));
      for (const { forMs, ...finding } of found) {
        if (!since.has(finding.id)) since.set(finding.id, now);
        if (active[finding.id] || now - since.get(finding.id)! < (forMs ?? 0)) continue;
        active[finding.id] = finding.summary;
        fired.push(incident('health', finding));
      }
      const ofCheck = (id: string) => id.startsWith(`health:${check}:`) && !current.has(id);
      for (const id of [...since.keys()].filter(ofCheck)) since.delete(id);
      for (const [id, summary] of Object.entries(active)) {
        if (!ofCheck(id)) continue;
        delete active[id];
        cleared.push(
          incident('health', { id: `${id}:resolved:${now}`, severity: 'resolved', summary: `cleared: ${summary}` }),
        );
      }
    }
    if (fired.length || cleared.length) fs.writeFileSync(stateFile, JSON.stringify(active));
    for (const i of [...batched('health', fired), ...batched('health', cleared)]) await sink(i);
    await new Promise((resolve) => setTimeout(resolve, intervalMs).unref());
  }
}
