export const REMEDIATION_ACTION = 'kubernetes_remediation';
export const APPROVAL_ANNOTATION = 'remediation.nanoclaw.io/approval-id';

export type RemediationLane = 'A' | 'always-ask' | 'C';
export type WorkloadKind = 'Deployment' | 'StatefulSet' | 'DaemonSet';

export type KnownKind =
  | WorkloadKind
  | 'CronJob'
  | 'Job'
  | 'PersistentVolume'
  | 'PersistentVolumeClaim'
  | 'Secret'
  | 'Pod'
  /** A Longhorn volume, longhorn.io/v1beta2. */
  | 'Volume'
  | 'VolumeAttachment'
  | 'Snapshot';

export interface TargetRef {
  apiVersion: string;
  /** A KnownKind, or any kind a manifest-edit or manifest-sync names. */
  kind: string;
  namespace: string | null;
  name: string;
  uid: string;
  resourceVersion: string;
}

interface PlanBase {
  schemaVersion: 1;
  id: string;
  incidentIds: string[];
  target: TargetRef;
  reason: string;
  expiresAt: string;
  /** git-backed operations only: commit and push, and leave the apply to the git→cluster applier. */
  commitOnly?: true;
}

export interface ImagePlan extends PlanBase {
  operation: {
    type: 'patch-image';
    containers: Array<{ name: string; initContainer: boolean }>;
    before: string;
    after: string;
    /** Bound by the host: the digest the target's pods run when `before` is tag-only. */
    runningDigest?: string;
  };
}

export interface RestartPlan extends PlanBase {
  operation: { type: 'restart'; restartedAt: string };
}

export interface ScalePlan extends PlanBase {
  operation: { type: 'scale'; before: number; after: number };
}

export interface JobDeletePlan extends PlanBase {
  operation: { type: 'delete-job' };
}

export interface CronJobRunPlan extends PlanBase {
  operation: { type: 'run-cronjob'; jobName?: string };
}

export interface PodExecPlan extends PlanBase {
  operation: { type: 'pod-exec'; container: string; command: string[] };
}

export interface BuildImagePlan extends PlanBase {
  /** `dockerfile` and `context` are k8s.jegor.nl paths; `image` is <own registry>/<name>:<tag>. */
  operation: { type: 'build-image'; dockerfile: string; context: string; image: string };
}

export interface StorageDeletePlan extends PlanBase {
  operation: { type: 'delete-storage'; reclaimConfirmed: boolean };
}

/** A Longhorn snapshot of `volume`; never one a backup references. */
export interface SnapshotDeletePlan extends PlanBase {
  operation: { type: 'delete-snapshot'; volume: string };
}

export interface AttachmentTicketRemovePlan extends PlanBase {
  operation: { type: 'remove-attachment-ticket'; ticket: string };
}

/** Creates or replaces the target Secret on the cluster only; its values are never echoed. */
export interface SecretWritePlan extends PlanBase {
  operation: { type: 'write-secret'; secretType: string; stringData: Record<string, string> };
}

export type ValuesScalar = string | number | boolean;
export type ValuesValue = ValuesScalar | null | ValuesValue[] | { [key: string]: ValuesValue };
export type ValuesEdit = { path: string; before: ValuesValue; after: ValuesValue };

/** Targets the Helm release: `target.name` is the release, uid/resourceVersion its latest release Secret. */
export interface HelmValuesPlan extends PlanBase {
  operation: {
    type: 'helm-values';
    file: string;
    /** A requested exact version and/or repository; the repository is optional once the host has cached it. */
    chart?: { repo?: string; version?: string };
    set: ValuesEdit[];
  };
}

/** Edits one object of a k8s.jegor.nl manifest, the plan's target, and applies it server-side. */
export interface ManifestEditPlan extends PlanBase {
  operation: { type: 'manifest-edit'; file: string; set: ValuesEdit[]; runningDigest?: string };
}

/** Writes the target's live object to its manifest file; no cluster change. */
export interface ManifestSyncPlan extends PlanBase {
  operation: { type: 'manifest-sync'; file: string };
}

/** Writes the release's live user-supplied values to its values file; no cluster change. */
export interface HelmSyncPlan extends PlanBase {
  operation: { type: 'helm-sync-values'; file: string };
}

/** Installs a new release from a values file already in k8s.jegor.nl; same release target as helm-values. */
export interface HelmInstallPlan extends PlanBase {
  operation: { type: 'helm-install'; chart: string; repo: string; version: string; file: string };
}

export interface HelmUninstallPlan extends PlanBase {
  operation: { type: 'helm-uninstall' };
}

/** Writes a whole kubernetes/** file and applies every object in it server-side; the target is the file. */
export interface RepoWritePlan extends PlanBase {
  operation: { type: 'repo-write'; path: string; content: string };
}

/** What the host learned while binding a helm-values plan to its release and values file. */
export interface HelmBinding {
  plan: HelmValuesPlan;
  /** The installed and requested chart versions, when this is a chart bump. */
  chart?: { before: string; after: string };
  /** Every values change the upgrade would apply, file after the edits against live. */
  diff: string[];
  /** Full image references before and after, keyed by the edited path. */
  images: Record<string, { before?: string; after?: string }>;
  statefulRepositories: string[];
  hasStatefulSet: boolean;
  /** The upgrade would leave every live object as it is, so it only updates the record. */
  unchanged: boolean;
}

export type RemediationPlan =
  | ImagePlan
  | RestartPlan
  | ScalePlan
  | JobDeletePlan
  | CronJobRunPlan
  | StorageDeletePlan
  | SnapshotDeletePlan
  | AttachmentTicketRemovePlan
  | SecretWritePlan
  | HelmValuesPlan
  | HelmSyncPlan
  | HelmInstallPlan
  | HelmUninstallPlan
  | RepoWritePlan
  | PodExecPlan
  | BuildImagePlan
  | ManifestEditPlan
  | ManifestSyncPlan;

export interface ValidatedPlan {
  plan: RemediationPlan;
  lane: RemediationLane;
  canonical: string;
  digest: string;
  automaticWriteCap: 0 | 1 | 2;
}

export interface RemediationIncident {
  id: string;
  source: 'trivy' | 'falco' | 'alertmanager' | 'uptime-kuma' | 'crowdsec' | 'health';
  observedAt: string;
  namespace: string | null;
  workload: { kind: string; name: string } | null;
  severity: string;
  summary: string;
  evidence: Record<string, unknown>;
}

export interface ApprovalGrant {
  approvalRowId: string;
  approverUserId: string;
  planId: string;
  planDigest: string;
}

export interface ExecutionResult {
  applied: boolean;
  message: string;
  automaticWrites: number;
}

export interface RemediationExecutor {
  execute(validated: ValidatedPlan, grant: ApprovalGrant): Promise<ExecutionResult>;
}
