import { Readable } from 'node:stream';
import type http from 'node:http';
import { describe, expect, it } from 'vitest';

import { createFalcoWebhookHandler, trivyIncident } from './triggers.js';

describe('Trivy trigger normalization', () => {
  it('binds dedupe identity to report UID and finding counts and keeps only bounded evidence', () => {
    const incident = trivyIncident({
      metadata: {
        uid: 'report-uid',
        resourceVersion: '19',
        namespace: 'gitea',
        name: 'deployment-gitea',
        ownerReferences: [{ kind: 'ReplicaSet', name: 'gitea-abc' }],
      },
      report: {
        artifact: { repository: 'gitea/gitea', digest: 'sha256:abc' },
        summary: { criticalCount: 1, highCount: 3 },
        vulnerabilities: [{ title: 'not copied into the incident' }],
      },
    });
    expect(incident).toMatchObject({
      id: 'trivy:report-uid:c1h3',
      source: 'trivy',
      namespace: 'gitea',
      severity: 'critical',
      workload: { kind: 'ReplicaSet', name: 'gitea-abc' },
    });
    expect(incident?.evidence).not.toHaveProperty('vulnerabilities');
  });

  it('drops reports without critical or high findings', () => {
    const low = { metadata: { uid: 'u', resourceVersion: '1' }, report: { summary: { mediumCount: 9, lowCount: 4 } } };
    expect(trivyIncident(low)).toBeNull();
  });

  it('drops reports without stable Kubernetes identity', () => {
    expect(trivyIncident({ metadata: { name: 'partial' }, report: {} })).toBeNull();
  });
});

describe('Falco webhook authentication', () => {
  it('accepts only the configured bearer before enqueueing an event', async () => {
    const incidents: unknown[] = [];
    const handler = createFalcoWebhookHandler({
      secret: () => Buffer.from('review-secret'),
      sink: async (incident) => void incidents.push(incident),
    });
    const invoke = async (authorization: string) => {
      const req = Object.assign(
        Readable.from([
          JSON.stringify({
            time: '2026-10-21T12:00:00Z',
            rule: 'Terminal shell in container',
            priority: 'Warning',
            output_fields: { 'k8s.ns.name': 'gitea', 'k8s.pod.name': 'gitea-0' },
          }),
        ]),
        { method: 'POST', headers: { authorization } },
      ) as http.IncomingMessage;
      let status = 0;
      const res = {
        writeHead(code: number) {
          status = code;
          return this;
        },
        end() {
          return this;
        },
      } as unknown as http.ServerResponse;
      await handler(req, res);
      return status;
    };

    await expect(invoke('Bearer wrong')).resolves.toBe(401);
    await expect(invoke('Bearer review-secret')).resolves.toBe(202);
    expect(incidents).toHaveLength(1);
  });
});
