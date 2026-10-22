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
  | 'Volume';

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
}

export interface ImagePlan extends PlanBase {
  operation: {
    type: 'patch-image';
    containers: Array<{ name: string; initContainer: boolean }>;
    before: string;
    after: string;
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

export interface PodExecPlan extends PlanBase {
  operation: { type: 'pod-exec'; container: string; command: string[] };
}

export interface BuildImagePlan extends PlanBase {
  /** `dockerfile` and `context` are k8s.jegor.nl paths; `image` is registry.prophet.jopdorp.nl/<name>:<tag>. */
  operation: { type: 'build-image'; dockerfile: string; context: string; image: string };
}

export interface StorageDeletePlan extends PlanBase {
  operation: { type: 'delete-storage'; reclaimConfirmed: boolean };
}

export type ValuesScalar = string | number | boolean;
export type ValuesEdit = { path: string; before: ValuesScalar | null; after: ValuesScalar };

/** Targets the Helm release: `target.name` is the release, uid/resourceVersion its latest release Secret. */
export interface HelmValuesPlan extends PlanBase {
  operation: {
    type: 'helm-values';
    file: string;
    /** The chart's repository, `https://...` or `oci://...`; optional once the host has verified and cached it. */
    chart?: { repo: string };
    set: ValuesEdit[];
  };
}

/** Edits one object of a k8s.jegor.nl manifest, the plan's target, and applies it server-side. */
export interface ManifestEditPlan extends PlanBase {
  operation: { type: 'manifest-edit'; file: string; set: ValuesEdit[] };
}

/** Writes the target's live object to its manifest file; no cluster change. */
export interface ManifestSyncPlan extends PlanBase {
  operation: { type: 'manifest-sync'; file: string };
}

/** Writes the release's live user-supplied values to its values file; no cluster change. */
export interface HelmSyncPlan extends PlanBase {
  operation: { type: 'helm-sync-values' };
}

/** What the host learned while binding a helm-values plan to its release and values file. */
export interface HelmBinding {
  plan: HelmValuesPlan;
  /** Every values change the upgrade would apply, file after the edits against live. */
  diff: string[];
  /** Full image references before and after, keyed by the edited path. */
  images: Record<string, { before?: string; after?: string }>;
  statefulRepositories: string[];
  hasStatefulSet: boolean;
}

export type RemediationPlan =
  | ImagePlan
  | RestartPlan
  | ScalePlan
  | JobDeletePlan
  | StorageDeletePlan
  | HelmValuesPlan
  | HelmSyncPlan
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
  source: 'trivy' | 'falco';
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
