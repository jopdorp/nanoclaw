import { createHash, timingSafeEqual } from 'node:crypto';
import fs from 'node:fs';
import type http from 'node:http';
import { setTimeout as sleep } from 'node:timers/promises';

import { log } from '../../log.js';
import type { KubernetesJsonClient } from './gateway-client.js';
import type { RemediationIncident } from './types.js';

const TRIVY_REPORTS = '/apis/aquasecurity.github.io/v1alpha1/vulnerabilityreports';
const TRIVY_CLUSTER_REPORTS = '/apis/aquasecurity.github.io/v1alpha1/clustervulnerabilityreports';
const MAX_FALCO_BODY = 64 * 1024;

export type IncidentSink = (incident: RemediationIncident) => Promise<void>;

export function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

export function text(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 ? value : null;
}

export function trivyIncident(value: unknown): RemediationIncident | null {
  const report = record(value);
  const metadata = record(report?.metadata);
  const body = record(report?.report);
  const summary = record(body?.summary);
  const uid = text(metadata?.uid);
  const resourceVersion = text(metadata?.resourceVersion);
  if (!uid || !resourceVersion) return null;
  const owner = Array.isArray(metadata?.ownerReferences) ? record(metadata.ownerReferences[0]) : null;
  const namespace = text(metadata?.namespace);
  const critical = Number(summary?.criticalCount ?? 0);
  const high = Number(summary?.highCount ?? 0);
  if (critical + high === 0) return null;
  return {
    // Keyed on the finding counts, not resourceVersion: Trivy rescans bump the version without new findings.
    id: `trivy:${uid}:c${critical}h${high}`,
    source: 'trivy',
    observedAt: new Date().toISOString(),
    namespace,
    workload: owner ? { kind: text(owner.kind) ?? 'Unknown', name: text(owner.name) ?? 'unknown' } : null,
    severity: critical > 0 ? 'critical' : 'high',
    summary: `Trivy report ${text(metadata?.name) ?? uid} changed`,
    evidence: { uid, resourceVersion, summary: summary ?? {}, artifact: body?.artifact ?? null },
  };
}

/** Survives restarts so a host restart does not replay every existing report. */
export class PersistentDedupe {
  private readonly ids: Set<string>;
  constructor(
    private readonly file: string | undefined,
    private readonly limit = 4096,
  ) {
    let saved: unknown = [];
    try {
      saved = file ? JSON.parse(fs.readFileSync(file, 'utf8')) : [];
      // eslint-disable-next-line no-catch-all/no-catch-all -- a missing or corrupt file just starts empty
    } catch {}
    this.ids = new Set(Array.isArray(saved) ? saved.filter((id): id is string => typeof id === 'string') : []);
  }
  add(id: string): boolean {
    if (this.ids.has(id)) return false;
    this.ids.add(id);
    if (this.ids.size > this.limit) this.ids.delete(this.ids.values().next().value!);
    if (this.file) fs.writeFileSync(this.file, JSON.stringify([...this.ids]));
    return true;
  }
}

function backlogDigest(incidents: RemediationIncident[]): RemediationIncident {
  const ids = incidents.map((incident) => incident.id).sort();
  return {
    id: `trivy-backlog:${createHash('sha256').update(ids.join('\n')).digest('hex').slice(0, 16)}`,
    source: 'trivy',
    observedAt: new Date().toISOString(),
    namespace: null,
    workload: null,
    severity: incidents.some((incident) => incident.severity === 'critical') ? 'critical' : 'high',
    summary: `${incidents.length} existing Trivy reports with critical/high findings (backlog digest)`,
    evidence: {
      total: incidents.length,
      reports: incidents.slice(0, 25).map(({ namespace, workload, severity, evidence }) => ({
        namespace,
        workload,
        severity,
        summary: evidence.summary,
        artifact: evidence.artifact,
      })),
    },
  };
}

async function watchResource(
  client: KubernetesJsonClient,
  path: string,
  sink: IncidentSink,
  signal: AbortSignal,
  seen: PersistentDedupe,
) {
  let backoff = 1_000;
  while (!signal.aborted) {
    try {
      const list = record(await client.request(path, { signal }));
      let resourceVersion = text(record(list?.metadata)?.resourceVersion) ?? '0';
      const fresh = (Array.isArray(list?.items) ? list.items : [])
        .map(trivyIncident)
        .filter((incident): incident is RemediationIncident => incident !== null && seen.add(incident.id));
      if (fresh.length === 1) await sink(fresh[0]);
      else if (fresh.length > 1) await sink(backlogDigest(fresh));
      for await (const raw of client.watch(path, resourceVersion, signal)) {
        backoff = 1_000;
        const event = record(raw);
        const type = text(event?.type);
        const object = record(event?.object);
        const next = text(record(object?.metadata)?.resourceVersion);
        if (next) resourceVersion = next;
        if (type === 'ERROR' && Number(record(object)?.code) === 410) break;
        if (!['ADDED', 'MODIFIED'].includes(type ?? '')) continue;
        const incident = trivyIncident(object);
        if (incident && seen.add(incident.id)) await sink(incident);
      }
      // eslint-disable-next-line no-catch-all/no-catch-all -- any failure restarts the watch; dying silently loses the feed
    } catch (error) {
      if (signal.aborted) return;
      log.warn('Trivy watch failed, restarting', { path, retryMs: backoff, err: error });
      await sleep(backoff, undefined, { signal }).catch(() => undefined);
      backoff = Math.min(backoff * 2, 60_000);
    }
  }
}

export async function runTrivyWatchers(
  client: KubernetesJsonClient,
  sink: IncidentSink,
  signal: AbortSignal,
  seenFile?: string,
): Promise<void> {
  const seen = new PersistentDedupe(seenFile);
  await Promise.all([
    watchResource(client, TRIVY_REPORTS, sink, signal, seen),
    watchResource(client, TRIVY_CLUSTER_REPORTS, sink, signal, seen),
  ]);
}

async function readBody(req: http.IncomingMessage, limit: number): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.length;
    if (size > limit) throw new Error('body too large');
    chunks.push(buffer);
  }
  return Buffer.concat(chunks);
}

function bearerOk(header: string, secret: Buffer): boolean {
  const expected = `Bearer ${secret.toString('utf8').trim()}`;
  return header.length === expected.length && timingSafeEqual(Buffer.from(header), Buffer.from(expected));
}

/** A bearer-authenticated, rate-limited JSON webhook whose payload becomes zero or more incidents. */
export function createWebhookHandler(options: {
  secret: () => Buffer;
  sink: IncidentSink;
  incidents: (payload: Record<string, unknown>, body: Buffer) => RemediationIncident[];
  requestsPerMinute?: number;
}): (req: http.IncomingMessage, res: http.ServerResponse) => Promise<void> {
  let window = 0;
  let count = 0;
  const limit = options.requestsPerMinute ?? 60;
  return async (req, res) => {
    if (req.method !== 'POST') {
      res.writeHead(405).end();
      return;
    }
    const minute = Math.floor(Date.now() / 60_000);
    if (window !== minute) [window, count] = [minute, 0];
    if (++count > limit) {
      res.writeHead(429).end();
      return;
    }
    let body: Buffer;
    try {
      body = await readBody(req, MAX_FALCO_BODY);
      // eslint-disable-next-line no-catch-all/no-catch-all -- body limit failures are client errors
    } catch {
      res.writeHead(413).end();
      return;
    }
    const authorization = String(req.headers.authorization ?? '');
    if (!bearerOk(authorization, options.secret())) {
      res.writeHead(401).end();
      return;
    }
    let payload: Record<string, unknown>;
    try {
      payload = record(JSON.parse(body.toString('utf8'))) ?? {};
      // eslint-disable-next-line no-catch-all/no-catch-all -- malformed JSON is a client error
    } catch {
      res.writeHead(400).end();
      return;
    }
    for (const incident of options.incidents(payload, body)) await options.sink(incident);
    res.writeHead(202).end();
  };
}

export function createFalcoWebhookHandler(options: {
  secret: () => Buffer;
  sink: IncidentSink;
  requestsPerMinute?: number;
}): (req: http.IncomingMessage, res: http.ServerResponse) => Promise<void> {
  return createWebhookHandler({
    ...options,
    incidents: (payload, body) => {
      const outputFields = record(payload.output_fields) ?? record(payload.outputFields) ?? {};
      const namespace = text(outputFields['k8s.ns.name']);
      const workloadName = text(outputFields['k8s.deployment.name']) ?? text(outputFields['k8s.pod.name']);
      return [
        {
          id: `falco:${createHash('sha256').update(body).digest('hex')}`,
          source: 'falco',
          observedAt: text(payload.time) ?? new Date().toISOString(),
          namespace,
          workload: workloadName
            ? { kind: outputFields['k8s.deployment.name'] ? 'Deployment' : 'Pod', name: workloadName }
            : null,
          severity: text(payload.priority)?.toLowerCase() ?? 'unknown',
          summary: text(payload.rule) ?? text(payload.output) ?? 'Falco event',
          evidence: { rule: payload.rule ?? null, source: payload.source ?? null, outputFields },
        },
      ];
    },
  });
}
