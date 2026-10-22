/**
 * REVIEW ARTIFACT: this file is intentionally absent from src/modules/index.ts.
 * Import and call it only after the deployment runbook's checkpoints pass.
 */
import fs from 'node:fs';
import path from 'node:path';

import { DATA_DIR } from '../../config.js';
import { getAgentGroup } from '../../db/agent-groups.js';
import { resolveGroupFolderPath } from '../../group-folder.js';
import { requestWake } from '../../request-wake.js';
import { resolveSession, writeSessionMessage } from '../../session-manager.js';
import { registerWebhookHandler } from '../../webhook-server.js';
import { log } from '../../log.js';
import { notifyApprover, registerKubernetesRemediationApproval } from './approval.js';
import {
  cleanupRemediationOrphans,
  GatewayRemediationExecutor,
  KubernetesRolloutObserver,
  OneCliKubernetesClient,
  registryThroughOneCli,
} from './gateway-client.js';
import { gitWithDeployKey, helmThroughOneCli, HelmReleaseExecutor, type HelmChart } from './helm-release.js';
import { createFalcoWebhookHandler, runTrivyWatchers } from './triggers.js';
import type { RemediationIncident } from './types.js';

export interface KubernetesRemediationConfig {
  agentGroupId: string;
  matrixApproverUserId: string;
  apiServer: string;
  executorOneCliAgent: string;
  annotatorOneCliAgent: string;
  falcoBearerFile: string;
  helmOneCliAgent?: string;
  /** Applies approved Lane C plans, including the Lane C releases in helmReleases. */
  breakGlassOneCliAgent?: string;
  /** Verified chart sources keyed `<namespace>/<release>`, cached by the host; hints only. */
  helmReleases?: Record<string, HelmChart>;
  /** `namespace` or `namespace/name`: image updates there need approval beyond a patch version. */
  t1: string[];
}

const DAY = 24 * 60 * 60_000;

export async function startKubernetesRemediation(
  config: KubernetesRemediationConfig,
  signal: AbortSignal,
): Promise<void> {
  const reader = new OneCliKubernetesClient(config.agentGroupId, config.apiServer);
  const executorClient = new OneCliKubernetesClient(config.executorOneCliAgent, config.apiServer);
  const annotator = new OneCliKubernetesClient(config.annotatorOneCliAgent, config.apiServer);
  if (!Array.isArray(config.t1)) throw new Error('kubernetes-remediation.json needs a t1 list');
  const group = await getAgentGroup(config.agentGroupId);
  // Each identity gets its own checkout, so the two executors never share a working tree.
  const charts = config.helmReleases ?? {};
  const remember = (key: string, chart: HelmChart) => {
    charts[key] = chart;
    const file = path.join(DATA_DIR, 'kubernetes-remediation.json');
    const current = JSON.parse(fs.readFileSync(file, 'utf8')) as KubernetesRemediationConfig;
    fs.writeFileSync(`${file}.tmp`, JSON.stringify({ ...current, helmReleases: charts }, null, 2), { mode: 0o600 });
    fs.renameSync(`${file}.tmp`, file);
  };
  const helmFor = (agent: string | undefined, laneC: boolean) => {
    if (!agent || !group) return undefined;
    const checkout = path.join(DATA_DIR, laneC ? 'k8s.jegor.nl-breakglass' : 'k8s.jegor.nl');
    return new HelmReleaseExecutor({
      client: new OneCliKubernetesClient(agent, config.apiServer),
      charts,
      remember,
      checkout,
      memoryDir: path.join(resolveGroupFolderPath(group.folder), 'memory'),
      helm: helmThroughOneCli(agent, config.apiServer, path.join(DATA_DIR, 'helm')),
      git: gitWithDeployKey(checkout, '/run/nanoclaw/git'),
      remote: 'git@github.com:jopdorp/k8s.jegor.nl.git',
    });
  };
  const helm = helmFor(config.helmOneCliAgent, false);
  const breakGlassHelm = helmFor(config.breakGlassOneCliAgent, true);
  const executor = new GatewayRemediationExecutor(
    executorClient,
    annotator,
    new KubernetesRolloutObserver(executorClient),
    helm,
    config.breakGlassOneCliAgent
      ? { client: new OneCliKubernetesClient(config.breakGlassOneCliAgent, config.apiServer), helm: breakGlassHelm }
      : undefined,
  );
  const cleaned = await cleanupRemediationOrphans(annotator);
  if (cleaned) log.warn('Cleaned stale Kubernetes remediation capabilities', { cleaned });
  registerKubernetesRemediationApproval({
    agentGroupId: config.agentGroupId,
    approverUserId: config.matrixApproverUserId,
    executor,
    helm,
    breakGlassHelm,
    registry: registryThroughOneCli(config.executorOneCliAgent),
    t1: new Set(config.t1),
  });
  if (helm) {
    const remind = () => {
      const stale = helm.staleDrift();
      if (stale)
        void notifyApprover(
          config.matrixApproverUserId,
          `Helm drift still open, Orfie owes a helm-values plan:\n${stale}`,
        );
    };
    // The first reminder waits for the Matrix adapter to come up.
    const first = setTimeout(() => {
      remind();
      const daily = setInterval(remind, DAY).unref();
      signal.addEventListener('abort', () => clearInterval(daily));
    }, 60_000).unref();
    signal.addEventListener('abort', () => clearTimeout(first));
  }

  const sink = (incident: RemediationIncident) => enqueueIncident(config.agentGroupId, incident);
  registerWebhookHandler(
    'kubernetes-falco',
    createFalcoWebhookHandler({ secret: () => fs.readFileSync(config.falcoBearerFile), sink }),
  );
  void runTrivyWatchers(reader, sink, signal, path.join(DATA_DIR, 'kubernetes-remediation-seen.json')).catch(
    (error) => {
      if (!signal.aborted) log.error('Kubernetes remediation Trivy watcher stopped', { err: error });
    },
  );
}

async function enqueueIncident(agentGroupId: string, incident: RemediationIncident): Promise<void> {
  const { session } = await resolveSession(agentGroupId, null, null, 'agent-shared');
  await writeSessionMessage(agentGroupId, session.id, {
    id: `k8s-${incident.source}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    kind: 'chat',
    timestamp: new Date().toISOString(),
    platformId: agentGroupId,
    channelType: 'agent',
    threadId: null,
    content: JSON.stringify({
      sender: 'kubernetes-remediation-trigger',
      senderId: 'system',
      text: `Investigate this Kubernetes incident. Read only until you submit a typed remediation proposal.\n${JSON.stringify(incident)}`,
    }),
  });
  const fresh = await import('../../db/sessions.js').then(({ getSession }) => getSession(session.id));
  if (fresh) await requestWake(fresh, 'inbound-message');
}
