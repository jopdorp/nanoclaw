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
import { readGroupPersona } from '../../group-persona.js';
import { requestWake } from '../../request-wake.js';
import { destroySessionMailbox, resolveSession, sessionDir, writeSessionMessage } from '../../session-manager.js';
import { registerWebhookHandler } from '../../webhook-server.js';
import { log } from '../../log.js';
import { isContainerRunning, killContainer } from '../../container-runner.js';
import { deleteSession, getSessionsByAgentGroup } from '../../db/sessions.js';
import { getDestinations } from '../agent-to-agent/db/agent-destinations.js';
import { trustCreateAgent } from '../agent-to-agent/guard.js';
import { notifyAgent } from '../approvals/index.js';
import { applyingFor, notifyApprover, registerKubernetesRemediationApproval } from './approval.js';
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
import { createIncidentGuard, ensureGuardGroup, GUARD_AGENT_GROUP_ID } from './incident-guard.js';
import { createLogReader } from './log-reader.js';
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
async function scopeHelperSecrets(agentGroupId: string, modelOnly = false): Promise<void> {
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
    model,
    ...(modelOnly
      ? []
      : [
          reader,
          id('Gitea repository reader (gitea-http.gitea.svc:3000)'),
          id('Gitea repository reader (gitea.claw.jopdorp.nl)'),
        ]),
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
  registerDeliveryAction(
    'restart_self',
    async (_content, session) => {
      if (session.agent_group_id !== config.agentGroupId) return;
      if (applyingFor(session.id))
        return notifyAgent(
          session,
          'restart_self refused: a plan of this session is being applied; ask again after its outcome',
        );
      killContainer(
        session.id,
        'restarted by Orfie',
        () => void notifyAgent(session, 'You restarted; this is a fresh session.'),
      );
    },
    unguarded('ends only Orfie’s own container; it respawns on the message that says so'),
  );
  onOneCliAgentEnsured(async (groupId) => {
    if (groupId === GUARD_AGENT_GROUP_ID) return scopeHelperSecrets(groupId, true);
    if (groupId === config.agentGroupId && group)
      return reportStandingRules(resolveGroupFolderPath(group.folder), config.matrixApproverUserId).catch(
        (err: unknown) => log.warn('Reporting a standing-rule change failed', { err }),
      );
    if (!(await team(groupId))) return;
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
  const guarded = await ensureGuardGroup().then(
    () => true,
    (err: unknown) => {
      log.error('GUARD DISABLED: its group setup failed, webhook incidents reach Orfie with the host fields only', {
        err,
      });
      return false;
    },
  );
  // Sessions a stopped host left mid-classification; their incidents come back through recover.
  for (const s of await getSessionsByAgentGroup(GUARD_AGENT_GROUP_ID)) endGuardSession(s.id);
  // One guard session at a time, each still fresh: a burst queues in order instead of filling the node.
  let turn = Promise.resolve();
  const releases = new Map<string, () => void>();
  const askGuard = async (ref: string, text: string) => {
    let release = () => {};
    const previous = turn;
    turn = new Promise((resolve) => (release = resolve));
    await previous;
    try {
      const session = await enqueue(GUARD_AGENT_GROUP_ID, 'kubernetes-remediation-guard', text, ref);
      releases.set(session, release);
      return session;
    } catch (err) {
      release();
      throw err;
    }
  };
  const endGuard = (session: string) => {
    endGuardSession(session);
    releases.get(session)?.();
    releases.delete(session);
  };
  const guard = createIncidentGuard({
    dir: path.join(DATA_DIR, 'kubernetes-remediation-raw'),
    available: guarded,
    ask: askGuard,
    end: endGuard,
    wake: (incident, note, data) => enqueueIncident(config.agentGroupId, incident, note, data),
  });
  await guard.recover();
  registerDeliveryAction(
    'guard_report_finding',
    async (content, session) => {
      if (session.agent_group_id !== GUARD_AGENT_GROUP_ID) return;
      const reply = await guard.report(content.finding);
      if (reply) await notifyAgent(session, reply);
    },
    unguarded('the guard classifies an incident; the host validates the finding before Orfie sees it'),
  );
  const logs = createLogReader({
    pods: executorClient,
    available: guarded,
    ask: askGuard,
    end: endGuard,
  });
  registerDeliveryAction(
    'read_logs',
    async (content, session) => {
      if (!(await team(session.agent_group_id))) return;
      const reply = (text: string) => notifyAgent(session, text);
      void logs
        .read(content, reply)
        .then(reply)
        .catch((err: unknown) => log.warn('Delivering read_logs failed', { err }));
    },
    unguarded('read-only: pod logs and VictoriaLogs, outside text masked or fenced'),
  );
  registerDeliveryAction(
    'guard_report_verdicts',
    async (content, session) => {
      if (session.agent_group_id !== GUARD_AGENT_GROUP_ID) return;
      const reply = logs.verdicts(content.verdicts);
      if (reply) await notifyAgent(session, reply);
    },
    unguarded('the guard classifies masked log values; the host keeps only ids it handed out'),
  );
  registerDeliveryAction(
    'open_incident_payload',
    async (content, session) => {
      if (await team(session.agent_group_id)) await notifyAgent(session, guard.open(String(content.ref ?? '')));
    },
    unguarded('read-only: a webhook payload the host kept, fenced as untrusted'),
  );
  registerWebhookHandler(
    'kubernetes-falco',
    createFalcoWebhookHandler({ secret: () => fs.readFileSync(config.falcoBearerFile), sink: guard.sink }),
  );
  // Its own bearer, mounted next to Falco's, so Orfie may hand it to the Alertmanager, Uptime Kuma and CrowdSec it configures.
  const alerts = createAlertWebhookHandlers({
    secret: () => fs.readFileSync(path.join(path.dirname(config.falcoBearerFile), 'alerts')),
    sink: guard.sink,
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

async function enqueueIncident(
  agentGroupId: string,
  incident: Pick<RemediationIncident, 'severity'>,
  note?: string,
  data?: string,
): Promise<void> {
  await enqueue(
    agentGroupId,
    'kubernetes-remediation-trigger',
    `${incident.severity === 'resolved' ? 'This Kubernetes incident cleared; close what you opened for it.' : 'Investigate this Kubernetes incident. Read only until you submit a typed remediation proposal.'}${note ? ` ${note}` : ''}\n${JSON.stringify(incident)}${data ? `\n${data}` : ''}`,
  );
}

/** A thread gets its own fresh session; without one the group's shared session takes the message. */
async function enqueue(agentGroupId: string, sender: string, text: string, thread?: string): Promise<string> {
  const { session } = await resolveSession(agentGroupId, null, thread ?? null, thread ? 'per-thread' : 'agent-shared');
  await writeSessionMessage(agentGroupId, session.id, {
    id: `k8s-${sender}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    kind: 'chat',
    timestamp: new Date().toISOString(),
    platformId: agentGroupId,
    channelType: 'agent',
    threadId: null,
    content: JSON.stringify({ sender, senderId: 'system', text }),
  });
  const fresh = await import('../../db/sessions.js').then(({ getSession }) => getSession(session.id));
  if (fresh) await requestWake(fresh, 'inbound-message');
  return session.id;
}

/** Orfie edits its own standing rules, so the host shows Jegor each change it is about to compose. */
async function reportStandingRules(groupDir: string, approverUserId: string): Promise<void> {
  const snapshot = path.join(DATA_DIR, 'kubernetes-remediation-standing-rules.md');
  fs.writeFileSync(`${snapshot}.next`, `${readGroupPersona(groupDir) ?? ''}\n`);
  if (fs.existsSync(snapshot)) {
    const diff = await exec('diff', ['-u', '--label', 'before', '--label', 'after', snapshot, `${snapshot}.next`]).then(
      () => '',
      (error: { code?: number; stdout?: string }) => {
        if (error.code !== 1) throw error;
        return error.stdout ?? '';
      },
    );
    // Kept unsent, the change is diffed again on the next spawn.
    if (diff && !(await notifyApprover(approverUserId, `Orfie changed its standing rules:\n${diff}`))) return;
  }
  fs.renameSync(`${snapshot}.next`, snapshot);
}

/** A guard session lives for one incident, so no payload can colour another verdict. */
function endGuardSession(sessionId: string): void {
  const forget = () =>
    void (async () => {
      await destroySessionMailbox(GUARD_AGENT_GROUP_ID, sessionId);
      fs.rmSync(sessionDir(GUARD_AGENT_GROUP_ID, sessionId), { recursive: true, force: true });
      await deleteSession(sessionId);
    })().catch((err: unknown) => log.warn('Removing a guard session failed', { sessionId, err }));
  if (isContainerRunning(sessionId)) killContainer(sessionId, 'its incident is classified', forget);
  else forget();
}
