export const REMEDIATION_ACTION = 'kubernetes_remediation';
export const APPROVAL_ANNOTATION = 'remediation.nanoclaw.io/approval-id';

export type RemediationLane = 'A' | 'always-ask' | 'C';
export type WorkloadKind = 'Deployment' | 'StatefulSet' | 'DaemonSet';

export interface TargetRef {
  apiVersion: 'apps/v1' | 'batch/v1' | 'v1';
  kind: WorkloadKind | 'CronJob' | 'Job' | 'PersistentVolume' | 'PersistentVolumeClaim' | 'Secret';
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

export interface StorageDeletePlan extends PlanBase {
  operation: { type: 'delete-storage'; reclaimConfirmed: boolean };
}

export type ValuesScalar = string | number | boolean;

/** Targets the Helm release: `target.name` is the release, uid/resourceVersion its latest release Secret. */
export interface HelmValuesPlan extends PlanBase {
  operation: {
    type: 'helm-values';
    file: string;
    set: Array<{ path: string; before: ValuesScalar | null; after: ValuesScalar }>;
  };
}

export type RemediationPlan = ImagePlan | RestartPlan | ScalePlan | JobDeletePlan | StorageDeletePlan | HelmValuesPlan;

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
