export const REMEDIATION_ACTION = 'kubernetes_remediation';
export const APPROVAL_ANNOTATION = 'remediation.nanoclaw.io/approval-id';

export type RemediationLane = 'A' | 'always-ask' | 'C';
export type WorkloadKind = 'Deployment' | 'StatefulSet' | 'DaemonSet';

export interface TargetRef {
  apiVersion: 'apps/v1' | 'v1';
  kind: WorkloadKind | 'PersistentVolume' | 'PersistentVolumeClaim';
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
    container: string;
    initContainer: boolean;
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

export interface StorageDeletePlan extends PlanBase {
  operation: { type: 'delete-storage'; reclaimConfirmed: boolean };
}

export interface LaneCEscalationPlan extends PlanBase {
  operation: { type: 'lane-c-escalation'; requestedChange: string };
}

export type RemediationPlan = ImagePlan | RestartPlan | ScalePlan | StorageDeletePlan | LaneCEscalationPlan;

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
