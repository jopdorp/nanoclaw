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
  /** Keyed `<namespace>/<release>`. */
  helmReleases?: Record<string, HelmChart>;
}

const DAY = 24 * 60 * 60_000;

export async function startKubernetesRemediation(
  config: KubernetesRemediationConfig,
  signal: AbortSignal,
): Promise<void> {
  const reader = new OneCliKubernetesClient(config.agentGroupId, config.apiServer);
  const executorClient = new OneCliKubernetesClient(config.executorOneCliAgent, config.apiServer);
  const annotator = new OneCliKubernetesClient(config.annotatorOneCliAgent, config.apiServer);
  const group = await getAgentGroup(config.agentGroupId);
  const checkout = path.join(DATA_DIR, 'k8s.jegor.nl');
  const helm =
    config.helmOneCliAgent && config.helmReleases && group
      ? new HelmReleaseExecutor({
          client: new OneCliKubernetesClient(config.helmOneCliAgent, config.apiServer),
          charts: config.helmReleases,
          checkout,
          memoryDir: path.join(resolveGroupFolderPath(group.folder), 'memory'),
          helm: helmThroughOneCli(config.helmOneCliAgent, config.apiServer, path.join(DATA_DIR, 'helm')),
          git: gitWithDeployKey(checkout, '/run/nanoclaw/git'),
          remote: 'git@github.com:jopdorp/k8s.jegor.nl.git',
        })
      : undefined;
  const executor = new GatewayRemediationExecutor(
    executorClient,
    annotator,
    new KubernetesRolloutObserver(executorClient),
    helm,
  );
  const cleaned = await cleanupRemediationOrphans(annotator);
  if (cleaned) log.warn('Cleaned stale Kubernetes remediation capabilities', { cleaned });
  registerKubernetesRemediationApproval({
    agentGroupId: config.agentGroupId,
    approverUserId: config.matrixApproverUserId,
    executor,
    helm,
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
      if (!signal.aborted) log.error('Kubernetes remediation Trivy watcher stopped', { error });
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
