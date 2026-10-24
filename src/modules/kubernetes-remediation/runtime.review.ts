/**
 * REVIEW ARTIFACT: this file is intentionally absent from src/modules/index.ts.
 * Import and call it only after the deployment runbook's checkpoints pass.
 */
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';

import { DATA_DIR } from '../../config.js';
import { getAgentGroup } from '../../db/agent-groups.js';
import { getContainerConfig, updateContainerConfigJson } from '../../db/container-configs.js';
import { materializeContainerJson } from '../../container-config.js';
import { registerDeliveryAction } from '../../delivery.js';
import { unguarded } from '../../guard/index.js';
import { onOneCliAgentEnsured } from '../../gateway-providers/onecli.js';
import { resolveGroupFolderPath } from '../../group-folder.js';
import { requestWake } from '../../request-wake.js';
import { resolveSession, writeSessionMessage } from '../../session-manager.js';
import { registerWebhookHandler } from '../../webhook-server.js';
import { log } from '../../log.js';
import { killContainer } from '../../container-runner.js';
import { getSessionsByAgentGroup } from '../../db/sessions.js';
import { getDestinations } from '../agent-to-agent/db/agent-destinations.js';
import { trustCreateAgent } from '../agent-to-agent/guard.js';
import { notifyAgent } from '../approvals/index.js';
import { notifyApprover, registerKubernetesRemediationApproval } from './approval.js';
import {
  cleanupRemediationOrphans,
  GatewayRemediationExecutor,
  KubernetesRolloutObserver,
  OneCliKubernetesClient,
  registryThroughOneCli,
  runningDigest,
} from './gateway-client.js';
import { listGiteaRunners } from './gitea-runners.js';
import { gitWithDeployKey, helmThroughOneCli, HelmReleaseExecutor, type HelmChart } from './helm-release.js';
import { createAlertWebhookHandlers, runHealthWatch } from './health.js';
import { readGrants, registerStandingApprovals } from './standing.js';
import { createFalcoWebhookHandler, runTrivyWatchers } from './triggers.js';
import { createUpdateChecker } from './updates.js';
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
  /** Where build-image pushes and the Secret in security holding its push credentials; Gitea's registry by default. */
  imageRegistry?: string;
  registryPullSecret?: string;
  /** `namespace` or `namespace/name`: image updates there need approval beyond a patch version. */
  t1: string[];
}

const DAY = 24 * 60 * 60_000;
// The investigator, the verifier and six workers.
const TEAM_LIMIT = 8;
const exec = promisify(execFile);

async function onecli<T>(...args: string[]): Promise<T> {
  return (JSON.parse((await exec('onecli', args)).stdout) as { data: T }).data;
}

/** Exactly the readers and its model key: OneCLI injects one anthropic-type key, so any other (DeepSeek) shadows the subscription. */
async function scopeHelperSecrets(agentGroupId: string): Promise<void> {
  const agent = (await onecli<Array<{ id: string; identifier: string }>>('agents', 'list')).find(
    (a) => a.identifier === agentGroupId,
  );
  if (!agent) return;
  const secrets = await onecli<Array<{ id: string; name: string }>>('secrets', 'list');
  const id = (name: string) => secrets.find((s) => s.name === name)?.id;
  const reader = id('Kubernetes reader');
  const provider = (await getContainerConfig(agentGroupId))?.provider ?? 'claude';
  const model = id(provider === 'claude' ? 'Claude subscription' : 'Codex');
  const current = await onecli<string[]>('agents', 'secrets', '--id', agent.id);
  const wanted = [
    reader,
    model,
    id('Gitea repository reader (gitea-http.gitea.svc:3000)'),
    id('Gitea repository reader (gitea.claw.jopdorp.nl)'),
  ].filter((s): s is string => !!s);
  await exec('onecli', ['agents', 'set-secret-mode', '--id', agent.id, '--mode', 'selective']);
  if (wanted.sort().join() !== [...current].sort().join())
    await exec('onecli', ['agents', 'set-secrets', '--id', agent.id, '--secret-ids', wanted.join(',')]);
}

/** Helpers get Orfie's shared-mind server; container.json is rewritten because this runs after spawn materialized it. */
async function shareMemory(orfieId: string, helperId: string): Promise<void> {
  const servers = async (id: string) =>
    JSON.parse((await getContainerConfig(id))?.mcp_servers ?? '{}') as Record<string, unknown>;
  const memory = (await servers(orfieId))['shared-mind'];
  const own = await servers(helperId);
  if (!memory || own['shared-mind']) return;
  await updateContainerConfigJson(helperId, 'mcp_servers', { ...own, 'shared-mind': memory });
  await materializeContainerJson(helperId);
}

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
      remote: 'ssh://git@gitea-ssh.gitea.svc.cluster.local:2222/cluster/k8s.jegor.nl.git',
      notify: (message) => notifyApprover(config.matrixApproverUserId, message),
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
    config.imageRegistry && config.registryPullSecret
      ? { registry: config.imageRegistry, pushSecret: config.registryPullSecret }
      : undefined,
  );
  const team = async (groupId: string) =>
    groupId === config.agentGroupId ||
    (await getDestinations(config.agentGroupId)).some((d) => d.target_type === 'agent' && d.target_id === groupId);
  trustCreateAgent(
    async (groupId) =>
      groupId === config.agentGroupId &&
      (await getDestinations(config.agentGroupId)).filter((d) => d.target_type === 'agent').length < TEAM_LIMIT,
  );
  registerDeliveryAction(
    'kubernetes_stop_session',
    async (content, session) => {
      if (session.agent_group_id !== config.agentGroupId) return;
      const agent = String(content.agent ?? '');
      const target = (await getDestinations(config.agentGroupId)).find(
        (d) => d.target_type === 'agent' && (d.local_name === agent || d.target_id === agent),
      )?.target_id;
      const sessions = target ? await getSessionsByAgentGroup(target) : [];
      for (const s of sessions) killContainer(s.id, 'stopped by Orfie');
      await notifyAgent(
        session,
        target
          ? `stopped the running sessions of ${agent}; it starts again on its next message`
          : `stop_session: ${agent} is not one of your agents`,
      );
    },
    unguarded('stops only a team agent’s container; it respawns on its next message'),
  );
  onOneCliAgentEnsured(async (groupId) => {
    if (groupId === config.agentGroupId || !(await team(groupId))) return;
    await scopeHelperSecrets(groupId);
    await shareMemory(config.agentGroupId, groupId);
  });
  registerStandingApprovals({
    approverUserId: config.matrixApproverUserId,
    configFile: path.join(DATA_DIR, 'kubernetes-remediation.json'),
  });
  const cleaned = await cleanupRemediationOrphans(annotator);
  if (cleaned) log.warn('Cleaned stale Kubernetes remediation capabilities', { cleaned });
  registerKubernetesRemediationApproval({
    team,
    runningDigest: (target, containers) => runningDigest(reader, target, containers),
    grants: () => readGrants(path.join(DATA_DIR, 'kubernetes-remediation.json')),
    yesFile: path.join(DATA_DIR, 'kubernetes-remediation-yes.json'),
    approverUserId: config.matrixApproverUserId,
    executor,
    helm,
    breakGlassHelm,
    registry: registryThroughOneCli(config.executorOneCliAgent),
    t1: new Set(config.t1),
  });
  if (helm) {
    const remind = async () => {
      const stale = await helm.staleDrift();
      if (stale)
        void notifyApprover(
          config.matrixApproverUserId,
          `Helm drift still open, Orfie owes a helm-values plan:\n${stale}`,
        );
    };
    // The first reminder waits for the Matrix adapter to come up.
    const first = setTimeout(() => {
      void remind();
      const daily = setInterval(() => void remind(), DAY).unref();
      signal.addEventListener('abort', () => clearInterval(daily));
    }, 60_000).unref();
    signal.addEventListener('abort', () => clearTimeout(first));
  }

  const sink = (incident: RemediationIncident) => enqueueIncident(config.agentGroupId, incident);
  registerWebhookHandler(
    'kubernetes-falco',
    createFalcoWebhookHandler({ secret: () => fs.readFileSync(config.falcoBearerFile), sink }),
  );
  // Its own bearer, mounted next to Falco's, so Orfie may hand it to the Alertmanager, Uptime Kuma and CrowdSec it configures.
  const alerts = createAlertWebhookHandlers({
    secret: () => fs.readFileSync(path.join(path.dirname(config.falcoBearerFile), 'alerts')),
    sink,
    seenFile: path.join(DATA_DIR, 'kubernetes-remediation-alerts-seen.json'),
  });
  registerWebhookHandler('alertmanager', alerts.alertmanager);
  registerWebhookHandler('uptime-kuma', alerts.uptimeKuma);
  registerWebhookHandler('crowdsec', alerts.crowdsec);
  void runHealthWatch(reader, sink, signal, path.join(DATA_DIR, 'kubernetes-remediation-health.json')).catch(
    (error) => {
      if (!signal.aborted) log.error('Kubernetes remediation health watch stopped', { error });
    },
  );
  registerDeliveryAction(
    'kubernetes_repo_read',
    async (content, session) => {
      if (!helm || !(await team(session.agent_group_id))) return;
      const relative = typeof content.path === 'string' ? content.path : '';
      const reply = await helm.readRepo(relative).then(
        (body) => `k8s.jegor.nl/${relative}:\n${body}`,
        (error: unknown) => `repo read failed: ${error instanceof Error ? error.message : String(error)}`,
      );
      await notifyAgent(session, reply);
    },
    unguarded('read-only, served from the host checkout of k8s.jegor.nl'),
  );
  registerDeliveryAction(
    'gitea_runners_list',
    async (_content, session) => {
      if (!(await team(session.agent_group_id))) return;
      const reply = await listGiteaRunners().then(
        (runners) => JSON.stringify(runners),
        (error: unknown) => `gitea_runners_list failed: ${error instanceof Error ? error.message : String(error)}`,
      );
      await notifyAgent(session, reply);
    },
    unguarded('read-only: the Gitea runner list'),
  );
  if (config.helmOneCliAgent) {
    const checkUpdates = createUpdateChecker({
      reader,
      helm: helmThroughOneCli(config.helmOneCliAgent, config.apiServer, path.join(DATA_DIR, 'helm')),
      charts,
      fetch: registryThroughOneCli(config.executorOneCliAgent),
    });
    registerDeliveryAction(
      'kubernetes_check_updates',
      async (_content, session) => {
        if (!(await team(session.agent_group_id))) return;
        await notifyAgent(
          session,
          await checkUpdates().catch(
            (error: unknown) => `check_updates failed: ${error instanceof Error ? error.message : String(error)}`,
          ),
        );
      },
      unguarded('read-only: chart indexes and registry tag lists'),
    );
  }
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
      text: `${incident.severity === 'resolved' ? 'This Kubernetes incident cleared; close what you opened for it.' : 'Investigate this Kubernetes incident. Read only until you submit a typed remediation proposal.'}\n${JSON.stringify(incident)}`,
    }),
  });
  const fresh = await import('../../db/sessions.js').then(({ getSession }) => getSession(session.id));
  if (fresh) await requestWake(fresh, 'inbound-message');
}
