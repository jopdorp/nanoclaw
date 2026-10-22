#!/usr/bin/env bash
set -euo pipefail

export KUBECONFIG=/home/jopdorp/.kube/mini-pc.fresh

ROOT=/home/jopdorp/development/nanoclaw-v2
DOCS="$ROOT/docs/kubernetes-remediation"
K8S_REPO=/home/jopdorp/development/k8s.jegor.nl
NAMESPACE=nanoclaw-remediator
ORCHESTRATOR=nanoclaw-remediator-orchestrator
ORCHESTRATOR_GROUP=ag-4be55056-f0a3-4991-a83e-a347b75de07d
INVESTIGATOR_GROUP=ag-491b4ac2-4451-47dc-8d4e-6872dbe66ac5
VERIFIER_GROUP=ag-e95b148c-8c90-4247-b6d1-0b75db805138
APPROVER='matrix:@jopdorp:matrix.org'
API_SERVER=https://192.168.1.11:6443
API_HOST=192.168.1.11
GITEA_NAMESPACE=gitea
GITEA_USER=orfie-repo-read
GITEA_REPOSITORY=k8s.jegor.nl
GITEA_TOKEN_NAME=onecli-read
GITEA_HOSTS=(gitea-http.gitea.svc gitea.claw.jopdorp.nl)
GITEA_SECRET_NAMES=('Gitea repository reader (gitea-http.gitea.svc:3000)' 'Gitea repository reader (gitea.claw.jopdorp.nl)')
EXECUTOR=nanoclaw-remediation-executor
ANNOTATOR=nanoclaw-remediation-annotator
HELM=nanoclaw-helm
BREAKGLASS=nanoclaw-breakglass
# OneCLI secret names, in TOKEN_FILES order: the agent's reader, then the host executor, annotator, helm and break-glass.
SECRET_NAMES=('Kubernetes reader' 'Kubernetes remediator' 'Kubernetes approver' 'Kubernetes helm' 'Kubernetes breakglass')
LOGIN_JOB=nanoclaw-provider-login
LOGIN_POD=
CREATED_LOGIN_JOB=0
TOKEN_FILES=(/tmp/nanoclaw-remediator-reader.token /tmp/nanoclaw-remediator.token /tmp/nanoclaw-remediation-approver.token
  /tmp/nanoclaw-helm.token /tmp/nanoclaw-breakglass.token)
GITEA_TOKEN_FILE=/tmp/nanoclaw-gitea-reader.token

step() { printf '\n==> %s\n' "$*"; }
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
todo() { printf 'TODO: %s\n' "$*" >&2; exit 1; }

ncl() {
  kubectl exec -n "$NAMESPACE" "deploy/$ORCHESTRATOR" -c orchestrator -- \
    env HOME=/tmp node_modules/.bin/tsx src/cli/client.ts "$@"
}

onecli_cli() {
  kubectl exec -n "$NAMESPACE" "$LOGIN_POD" -c login -- onecli "$@"
}

cleanup() {
  if [[ -n "$LOGIN_POD" ]]; then
    kubectl exec -n "$NAMESPACE" "$LOGIN_POD" -c login -- \
      rm -f "${TOKEN_FILES[@]}" "$GITEA_TOKEN_FILE" >/dev/null 2>&1 || true
  fi
  if [[ "$CREATED_LOGIN_JOB" = 1 ]]; then
    kubectl delete -n "$NAMESPACE" job "$LOGIN_JOB" --wait=false >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

command -v kubectl >/dev/null || fail 'kubectl is required'
command -v jq >/dev/null || fail 'jq is required'
test "$(kubectl config current-context)" = default || fail 'HOME kubeconfig context is not default'
test "$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')" = "$API_SERVER" \
  || fail "kubeconfig does not point at HOME ($API_SERVER)"

step 'precheck: prove the latest Investigator turn used working gateway routing'
AGENT_GROUPS=$(ncl groups list --json --limit 100000)
for group_id in "$ORCHESTRATOR_GROUP" "$INVESTIGATOR_GROUP" "$VERIFIER_GROUP"; do
  jq -e --arg id "$group_id" '.data[] | select(.id == $id)' <<<"$AGENT_GROUPS" >/dev/null \
    || todo "agent group $group_id is absent; update the pinned IDs before enabling remediation"
done

INVESTIGATOR_POD=$(kubectl get pods -n "$NAMESPACE" -l "nanoclaw-group=$INVESTIGATOR_GROUP" \
  --sort-by=.metadata.creationTimestamp -o name | tail -n 1)
ROUTING_STATUS='not proven: no Investigator session pod exists'
if [[ -n "$INVESTIGATOR_POD" ]]; then
  INVESTIGATOR_LOG=$(kubectl logs -n "$NAMESPACE" "$INVESTIGATOR_POD" -c agent --tail=1000 2>&1 || true)
  LAST_SIGNAL=$(grep -E '\[poll-loop\] (Result:|Error:)|\[agent-runner\] Fatal|Failed to authenticate|API Error:' \
    <<<"$INVESTIGATOR_LOG" | tail -n 1 || true)
  if [[ "$LAST_SIGNAL" == *'[poll-loop] Result:'* ]] \
    && ! grep -Eqi 'error|fail|401|403|no credentials|unauthorized|authentication' <<<"$LAST_SIGNAL"; then
    ROUTING_STATUS="proven by the latest successful Investigator result in ${INVESTIGATOR_POD#pod/}"
  elif [[ -n "$LAST_SIGNAL" ]]; then
    ROUTING_STATUS="not proven: the latest Investigator turn in ${INVESTIGATOR_POD#pod/} ended in an error"
  else
    ROUTING_STATUS="not proven: ${INVESTIGATOR_POD#pod/} has no completed turn"
  fi
fi
printf 'Subagent routing: %s\n' "$ROUTING_STATUS"
if [[ "$ROUTING_STATUS" != proven* && "${FORCE:-0}" != 1 ]]; then
  printf '%s\n' 'WARNING: gateway-config.yaml keeps launch blocked until subagent-routing-proven.' >&2
  fail 're-run with FORCE=1 only if you intentionally accept this unresolved launch gate'
fi
if [[ "$ROUTING_STATUS" != proven* ]]; then
  printf '%s\n' 'WARNING: FORCE=1 accepted; Subagent routing remains an unresolved production gate.' >&2
fi

step '1/6 apply the approval-controller identity and admission policies idempotently'
kubectl apply -f "$DOCS/approval-controller-rbac.yaml" >/dev/null
kubectl apply --server-side --force-conflicts -f "$DOCS/approval-controller-policy.yaml" >/dev/null
# It required an approval annotation on every write, so nothing could ever auto-apply.
kubectl delete validatingadmissionpolicybinding,validatingadmissionpolicy nanoclaw-remediation-approved-write \
  --ignore-not-found >/dev/null
printf '%s\n' 'approval-controller RBAC and policies are present'

step '1b/6 bind the per-namespace rights; namespace-binder keeps them on every namespace, new ones too'
kubectl apply -f - >/dev/null <<'YAML'
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: nanoclaw-remediator-reader-wide
rules:
  - apiGroups: [""]
    resources:
      - bindings
      - componentstatuses
      - configmaps
      - endpoints
      - events
      - limitranges
      - namespaces
      - nodes
      - nodes/proxy
      - persistentvolumeclaims
      - persistentvolumes
      - pods
      - pods/log
      - podtemplates
      - replicationcontrollers
      - resourcequotas
      - serviceaccounts
      - services
    verbs: [get, list, watch]
  - apiGroups:
      - acme.cert-manager.io
      - admissionregistration.k8s.io
      - apiextensions.k8s.io
      - apiregistration.k8s.io
      - apps
      - aquasecurity.github.io
      - argoproj.io
      - authentication.k8s.io
      - authorization.k8s.io
      - autoscaling
      - batch
      - ceph.rook.io
      - cert-manager.io
      - certificates.k8s.io
      - coordination.k8s.io
      - discovery.k8s.io
      - events.k8s.io
      - flowcontrol.apiserver.k8s.io
      - gateway.networking.k8s.io
      - helm.cattle.io
      - hermes.ai
      - hub.traefik.io
      - k3s.cattle.io
      - longhorn.io
      - metrics.k8s.io
      - networking.k8s.io
      - node.k8s.io
      - objectbucket.io
      - policy
      - rbac.authorization.k8s.io
      - resource.k8s.io
      - scheduling.k8s.io
      - storage.k8s.io
      - traefik.io
      - upgrade.cattle.io
    resources: ["*"]
    verbs: [get, list, watch]
YAML
kubectl apply -f "$K8S_REPO/kubernetes/security/namespace-binder.yaml" >/dev/null
kubectl rollout status -n security deploy/namespace-binder --timeout=5m >/dev/null
# Grants replaced by the bindings above.
for kind in rolebinding role; do
  kubectl get "$kind" -A -o json | jq -r '.items[].metadata | select(.name | IN("nanoclaw-remediator-read",
      "nanoclaw-remediator-reader", "nanoclaw-helm-release", "nanoclaw-breakglass-helm", "nanoclaw-breakglass-lane-c",
      "nanoclaw-remediator-always-ask", "nanoclaw-remediator-reader-logs")) | "\(.namespace) \(.name)"' \
    | while read -r ns name; do kubectl delete "$kind" -n "$ns" "$name" >/dev/null; done
done
kubectl delete clusterrolebinding nanoclaw-remediator-reader-cluster-read nanoclaw-remediator-reader-trivy-read \
  --ignore-not-found >/dev/null
kubectl delete clusterrole nanoclaw-breakglass-lane-c nanoclaw-remediator-reader-logs --ignore-not-found >/dev/null
printf '%s\n' 'namespace-binder binds the reader, exec and helm rights in every namespace'
kubectl get secret -n "$NAMESPACE" registry-prophet -o json \
  | jq '{apiVersion, kind, type, data, metadata: {name: .metadata.name, namespace: "security"}}' \
  | kubectl apply -f - >/dev/null
printf '%s\n' 'the build-image Job in security can push to registry.prophet.jopdorp.nl'
kubectl get secret -n "$NAMESPACE" nanoclaw-runtime -o json | jq -e '.data["alert-webhook-bearer"]' >/dev/null \
  || jq -n --arg b "$(openssl rand -hex 32 | base64 -w0)" '{data: {"alert-webhook-bearer": $b}}' \
    | kubectl patch secret -n "$NAMESPACE" nanoclaw-runtime --type=merge --patch-file /dev/stdin >/dev/null
# Orfie hands this bearer to the Alertmanager, Uptime Kuma and CrowdSec it configures.
for ns in monitoring crowdsec; do
  kubectl create namespace "$ns" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  kubectl get secret -n "$NAMESPACE" nanoclaw-runtime -o json \
    | jq --arg ns "$ns" '{apiVersion, kind, type, data: {bearer: .data["alert-webhook-bearer"]}, metadata: {name: "orfie-alert-webhook", namespace: $ns}}' \
    | kubectl apply -f - >/dev/null
done
printf '%s\n' 'the alert webhooks have their bearer, readable as orfie-alert-webhook in monitoring and crowdsec'
for account in nanoclaw-remediator nanoclaw-remediation-approver nanoclaw-helm nanoclaw-breakglass; do
  kubectl apply -f - >/dev/null <<YAML
apiVersion: v1
kind: ServiceAccount
metadata: { name: $account, namespace: $NAMESPACE }
automountServiceAccountToken: false
---
apiVersion: v1
kind: Secret
type: kubernetes.io/service-account-token
metadata:
  name: $account-token
  namespace: $NAMESPACE
  annotations: { kubernetes.io/service-account.name: $account }
YAML
done
kubectl get secret -n "$NAMESPACE" nanoclaw-remediator-reader-token >/dev/null 2>&1 \
  || todo 'apply reader-rbac.yaml first: the nanoclaw-remediator-reader token Secret is absent'
printf '%s\n' 'ServiceAccounts and token Secrets are present'

step '2/6 start or reuse the disposable OneCLI setup Job'
if kubectl get job -n "$NAMESPACE" "$LOGIN_JOB" >/dev/null 2>&1; then
  printf 'reusing existing disposable Job %s\n' "$LOGIN_JOB"
else
  kubectl apply -f "$DOCS/provider-login-job.review.yaml" >/dev/null
  CREATED_LOGIN_JOB=1
  printf 'created disposable Job %s\n' "$LOGIN_JOB"
fi
kubectl wait -n "$NAMESPACE" --for=condition=Ready pod -l "job-name=$LOGIN_JOB" --timeout=120s >/dev/null \
  || todo "Job $LOGIN_JOB is not Ready; inspect it without replacing an active interactive-login Job"
LOGIN_POD=$(kubectl get pods -n "$NAMESPACE" -l "job-name=$LOGIN_JOB" \
  --sort-by=.metadata.creationTimestamp -o jsonpath='{.items[-1:].metadata.name}')
[[ -n "$LOGIN_POD" ]] || todo "could not resolve the pod for Job $LOGIN_JOB"
onecli_cli config set api-host http://onecli.nanoclaw-remediator.svc:10254 >/dev/null
GATEWAY_VERSION=$(kubectl exec -n "$NAMESPACE" "$LOGIN_POD" -c login -- \
  curl -fsS http://onecli.nanoclaw-remediator.svc:10254/v1/health | jq -er '.version')
[[ "$GATEWAY_VERSION" = 1.42.0 ]] \
  || todo "OneCLI gateway is $GATEWAY_VERSION; this script requires the runbook pin 1.42.0"
printf 'OneCLI gateway %s is ready\n' "$GATEWAY_VERSION"

upsert_generic_secret() {
  local name=$1 token_file=$2 host=$3 value_format=$4
  kubectl exec -i -n "$NAMESPACE" "$LOGIN_POD" -c login -- \
    node - "$name" "$token_file" "$host" "$value_format" <<'NODE'
import fs from 'node:fs';

const [name, file, hostPattern, valueFormat] = process.argv.slice(2);
const base = process.env.ONECLI_URL?.replace(/\/+$/, '');
const apiKey = process.env.ONECLI_API_KEY;
if (!base || !apiKey) throw new Error('OneCLI management environment is unavailable');
const headers = { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' };
const request = async (path, method = 'GET', body) => {
  const response = await fetch(`${base}/v1/secrets${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
    redirect: 'error',
    signal: AbortSignal.timeout(30000),
  });
  if (!response.ok) throw new Error(`OneCLI secret request failed (${response.status})`);
  return response.json();
};
const token = fs.readFileSync(file, 'utf8').trim();
if (!token) throw new Error('TokenRequest returned an empty token');
const secrets = await request('');
const matches = secrets.filter((secret) => secret.name === name);
if (matches.length > 1) throw new Error(`Multiple OneCLI secrets are named ${name}`);
const injectionConfig = { headerName: 'Authorization', valueFormat };
const existing = matches[0];
if (existing && (
  existing.type !== 'generic' ||
  existing.hostPattern !== hostPattern ||
  existing.pathPattern ||
  (existing.valueSource && existing.valueSource !== 'inline') ||
  (existing.opRef !== undefined && existing.opRef !== null)
)) throw new Error(`Existing OneCLI secret ${name} has unexpected metadata`);
const payload = { value: token, hostPattern, injectionConfig };
const result = existing
  ? await request(`/${encodeURIComponent(existing.id)}`, 'PATCH', payload)
  : await request('', 'POST', {
      name,
      type: 'generic',
      valueSource: 'inline',
      ...payload,
    });
const id = existing?.id || result.id;
if (!id) throw new Error(`OneCLI did not confirm secret ${name}`);
process.stdout.write(id);
NODE
}

ensure_agent() {
  local identifier=$1 name=$2 create=$3 agents count
  agents=$(onecli_cli agents list)
  count=$(jq -r --arg identifier "$identifier" '[.data[] | select(.identifier == $identifier)] | length' <<<"$agents")
  (( count <= 1 )) || todo "multiple OneCLI agents use identifier $identifier"
  if (( count == 0 )); then
    [[ "$create" = true ]] || todo "required OneCLI agent $identifier is absent"
    onecli_cli agents create --name "$name" --identifier "$identifier" >/dev/null
    printf 'created OneCLI agent %s\n' "$identifier" >&2
    agents=$(onecli_cli agents list)
  else
    printf 'reusing OneCLI agent %s\n' "$identifier" >&2
  fi
  ENSURED_AGENT_ID=$(jq -er --arg identifier "$identifier" \
    '.data[] | select(.identifier == $identifier) | .id' <<<"$agents")
}

step '3/6 make the OneCLI identities selective and block orchestrator writes'
SECRETS=$(onecli_cli secrets list)
CODEX_SECRET_COUNT=$(jq -r '[.data[] | select(.name == "Codex" and .type == "openai")] | length' <<<"$SECRETS")
(( CODEX_SECRET_COUNT == 1 )) \
  || todo 'the Codex-primary orchestrator requires exactly one OneCLI Codex credential'
CODEX_SECRET_ID=$(jq -er '.data[] | select(.name == "Codex" and .type == "openai") | .id' <<<"$SECRETS")

# OneCLI 2.x serves custom rules only through its policy API, and a draft rule takes effect once published.
onecli_policy() {
  kubectl exec -i -n "$NAMESPACE" "$LOGIN_POD" -c login -- sh -c 'curl -fsS -X "$1" -H "Authorization: Bearer $ONECLI_API_KEY" \
    -H "Content-Type: application/json" --data-binary @- "$ONECLI_URL/v1/policy$2"' sh "$@"
}

ensure_block_rule() {
  local method=$1 name="nanoclaw-remediator-kubernetes-block-${1,,}" rule ids
  rule=$(jq -nc --arg name "$name" --arg host "$API_HOST" --arg method "$method" --arg agent "$PRIMARY_AGENT_ID" \
    '{name: $name, action: "block", enabled: true, identities: [{type: "agent", id: $agent}],
      targets: [{kind: "network", hostPattern: $host, method: $method}]}')
  ids=$(onecli_policy GET /rules </dev/null | jq -r --arg name "$name" '[.[] | select(.name == $name) | .id] | join(" ")')
  case $ids in
    '') onecli_policy POST /rules <<<"$rule" >/dev/null; printf 'created orchestrator block rule for %s\n' "$method" ;;
    *' '*) todo "multiple OneCLI rules are named $name" ;;
    *) onecli_policy PATCH "/rules/$ids" <<<"$rule" >/dev/null; printf 'confirmed orchestrator block rule for %s\n' "$method" ;;
  esac
}

ensure_agent "$ORCHESTRATOR_GROUP" 'Kubernetes Remediator' false
PRIMARY_AGENT_ID=$ENSURED_AGENT_ID
ensure_agent "$INVESTIGATOR_GROUP" 'Kubernetes Remediation Investigator' false
INVESTIGATOR_AGENT_ID=$ENSURED_AGENT_ID
ensure_agent "$VERIFIER_GROUP" 'Kubernetes Remediation Verifier' false
VERIFIER_AGENT_ID=$ENSURED_AGENT_ID
for method in POST PUT PATCH DELETE; do ensure_block_rule "$method"; done

ensure_gitea_block_rule() {
  local method=$1 label=$2 host=$3 name="nanoclaw-remediator-gitea-$2-block-${1,,}" rule ids
  rule=$(jq -nc --arg name "$name" --arg host "$host" --arg method "$method" \
    --arg agents "$PRIMARY_AGENT_ID $INVESTIGATOR_AGENT_ID $VERIFIER_AGENT_ID" \
    '{name: $name, action: "block", enabled: true,
      identities: ($agents | split(" ") | map({type: "agent", id: .})),
      targets: [{kind: "network", hostPattern: $host, method: $method}]}')
  ids=$(onecli_policy GET /rules </dev/null | jq -r --arg name "$name" '[.[] | select(.name == $name) | .id] | join(" ")')
  case $ids in
    '') onecli_policy POST /rules <<<"$rule" >/dev/null; printf 'created Gitea %s block rule for %s\n' "$label" "$method" ;;
    *' '*) todo "multiple OneCLI rules are named $name" ;;
    *) onecli_policy PATCH "/rules/$ids" <<<"$rule" >/dev/null; printf 'confirmed Gitea %s block rule for %s\n' "$label" "$method" ;;
  esac
}
for method in POST PUT PATCH DELETE; do
  ensure_gitea_block_rule "$method" internal "${GITEA_HOSTS[0]}"
  ensure_gitea_block_rule "$method" external "${GITEA_HOSTS[1]}"
done
onecli_policy GET /rules </dev/null \
  | jq -c '{orderedIds: sort_by((.name | startswith("nanoclaw-remediator-") and contains("-block-")) | not) | map(.id)}' \
  | onecli_policy PUT /rules/order >/dev/null
onecli_policy POST /publish </dev/null >/dev/null
onecli_policy GET '/rules?status=published' </dev/null \
  | jq -e '([.[] | select(.name | startswith("nanoclaw-remediator-kubernetes-block-"))] | length == 4)
      and ([.[] | select(.name | startswith("nanoclaw-remediator-gitea-"))] | length == 8)' >/dev/null \
  || todo 'the orchestrator block rules are not published'

PRIMARY_PROVIDER_IDS=$(onecli_cli agents secrets --id "$PRIMARY_AGENT_ID" \
  | jq -r --arg codex "$CODEX_SECRET_ID" '[.data[], $codex] | unique | join(",")')
onecli_cli agents set-secrets --id "$PRIMARY_AGENT_ID" --secret-ids "$PRIMARY_PROVIDER_IDS" >/dev/null
ensure_agent "$EXECUTOR" 'NanoClaw Remediation Executor' true
EXECUTOR_AGENT_ID=$ENSURED_AGENT_ID
onecli_cli agents set-secret-mode --id "$EXECUTOR_AGENT_ID" --mode selective >/dev/null
ensure_agent "$ANNOTATOR" 'NanoClaw Remediation Annotator' true
ANNOTATOR_AGENT_ID=$ENSURED_AGENT_ID
onecli_cli agents set-secret-mode --id "$ANNOTATOR_AGENT_ID" --mode selective >/dev/null
ensure_agent "$HELM" 'NanoClaw Helm Executor' true
HELM_AGENT_ID=$ENSURED_AGENT_ID
onecli_cli agents set-secret-mode --id "$HELM_AGENT_ID" --mode selective >/dev/null
ensure_agent "$BREAKGLASS" 'NanoClaw Break-glass Executor' true
BREAKGLASS_AGENT_ID=$ENSURED_AGENT_ID
onecli_cli agents set-secret-mode --id "$BREAKGLASS_AGENT_ID" --mode selective >/dev/null
AGENTS=$(onecli_cli agents list)
# An agent in "all" mode would be injected the writer, helm and break-glass tokens the moment they are stored.
OPEN_AGENTS=$(jq -r '[.data[] | select(.secretMode != "selective") | .identifier] | join(" ")' <<<"$AGENTS")
[[ -z "$OPEN_AGENTS" ]] || todo "switch these OneCLI agents to selective secret mode first: $OPEN_AGENTS"
printf '%s\n' 'selective OneCLI identities and orchestrator write blocks are active'

step '4/6 copy the ServiceAccount tokens into the OneCLI vault'
copy_token() {
  local secret=$1 file=$2 token_b64=
  for _ in $(seq 30); do
    token_b64=$(kubectl get secret -n "$NAMESPACE" "$secret" -o jsonpath='{.data.token}')
    [[ -n "$token_b64" ]] && break
    sleep 1
  done
  [[ -n "$token_b64" ]] || todo "the $secret Secret has no token yet"
  base64 -d <<<"$token_b64" | kubectl exec -i -n "$NAMESPACE" "$LOGIN_POD" -c login -- \
    sh -c "umask 077; cat > $file"
}
SECRET_IDS=()
for i in 0 1 2 3 4; do
  copy_token "$(basename "${TOKEN_FILES[$i]}" .token)-token" "${TOKEN_FILES[$i]}"
  SECRET_IDS[$i]=$(upsert_generic_secret "${SECRET_NAMES[$i]}" "${TOKEN_FILES[$i]}" "$API_HOST" 'Bearer {value}') \
    || todo "could not create or rotate OneCLI secret ${SECRET_NAMES[$i]}"
done
kubectl exec -n "$NAMESPACE" "$LOGIN_POD" -c login -- rm -f "${TOKEN_FILES[@]}"

GITEA_POD=$(kubectl get pod -n "$GITEA_NAMESPACE" -l app.kubernetes.io/name=gitea \
  --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')
GITEA_DB_POD=$(kubectl get pod -n "$GITEA_NAMESPACE" -l app.kubernetes.io/name=postgresql \
  --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')
[[ -n "$GITEA_POD" && -n "$GITEA_DB_POD" ]] || todo 'the Gitea application or database pod is absent'
if ! kubectl exec -n "$GITEA_NAMESPACE" "$GITEA_POD" -c gitea -- gitea admin user list \
  | awk -v user="$GITEA_USER" '$2 == user { found=1 } END { exit !found }'; then
  kubectl exec -n "$GITEA_NAMESPACE" "$GITEA_POD" -c gitea -- gitea admin user create \
    --username "$GITEA_USER" --email "$GITEA_USER@claw.jopdorp.nl" --random-password \
    --must-change-password=false >/dev/null
fi
kubectl exec -i -n "$GITEA_NAMESPACE" "$GITEA_DB_POD" -- sh -c \
  'PGPASSWORD=$(cat "$POSTGRES_PASSWORD_FILE") /opt/bitnami/postgresql/bin/psql -v ON_ERROR_STOP=1 \
    -U "$POSTGRES_USER" -d "$POSTGRES_DATABASE"' >/dev/null <<SQL
INSERT INTO access (user_id, repo_id, mode)
SELECT u.id, r.id, 1 FROM public.user u JOIN repository r ON r.owner_name = 'cluster'
WHERE u.name = '$GITEA_USER' AND r.name = '$GITEA_REPOSITORY'
ON CONFLICT (user_id, repo_id) DO UPDATE SET mode = 1;
DELETE FROM access_token WHERE uid = (SELECT id FROM public.user WHERE name = '$GITEA_USER')
  AND name = '$GITEA_TOKEN_NAME';
SQL
kubectl exec -n "$GITEA_NAMESPACE" "$GITEA_POD" -c gitea -- gitea admin user generate-access-token \
  --username "$GITEA_USER" --token-name "$GITEA_TOKEN_NAME" --scopes read:repository --raw \
  | kubectl exec -i -n "$NAMESPACE" "$LOGIN_POD" -c login -- sh -c \
      "umask 077; cat > $GITEA_TOKEN_FILE"
GITEA_SECRET_IDS=()
for i in 0 1; do
  GITEA_SECRET_IDS[$i]=$(upsert_generic_secret "${GITEA_SECRET_NAMES[$i]}" \
    "$GITEA_TOKEN_FILE" "${GITEA_HOSTS[$i]}" 'token {value}') \
    || todo "could not create or rotate the ${GITEA_HOSTS[$i]} Gitea credential"
done
kubectl exec -n "$NAMESPACE" "$LOGIN_POD" -c login -- rm -f "$GITEA_TOKEN_FILE"

# The agents hold only the read-only reader, never another API token (older runs' included); each host identity holds exactly its own.
READER_AGENT_IDS=$(jq -r --arg ids "$ORCHESTRATOR_GROUP $INVESTIGATOR_GROUP $VERIFIER_GROUP" \
  '.data[] | select(.identifier | IN($ids | split(" ")[])) | .id' <<<"$AGENTS" | tr '\n' ' ')
API_SECRET_IDS=$(onecli_cli secrets list | jq -c --arg host "$API_HOST" --arg read "${SECRET_IDS[0]}" \
  '[.data[] | select(.hostPattern == $host and .id != $read) | .id]')
for agent in $(jq -r '.data[].id' <<<"$AGENTS"); do
  [[ " $EXECUTOR_AGENT_ID $ANNOTATOR_AGENT_ID $HELM_AGENT_ID $BREAKGLASS_AGENT_ID " == *" $agent "* ]] && continue
  current=$(onecli_cli agents secrets --id "$agent" | jq -c '.data | unique')
  wanted=$(jq -c --argjson api "$API_SECRET_IDS" --arg read "${SECRET_IDS[0]}" --arg add "$([[ " $READER_AGENT_IDS " == *" $agent "* ]] && echo 1)" \
    '[(. - $api)[], (if $add == "1" then $read else empty end)] | unique' <<<"$current")
  [[ "$wanted" == "$current" ]] \
    || onecli_cli agents set-secrets --id "$agent" --secret-ids "$(jq -r 'join(",")' <<<"$wanted")" >/dev/null
done
onecli_cli agents secrets --id "$PRIMARY_AGENT_ID" | jq -e --arg id "${SECRET_IDS[0]}" '.data | index($id)' >/dev/null
for agent in "$PRIMARY_AGENT_ID" "$INVESTIGATOR_AGENT_ID" "$VERIFIER_AGENT_ID"; do
  current=$(onecli_cli agents secrets --id "$agent" | jq -c '.data | unique')
  wanted=$(jq -c --arg one "${GITEA_SECRET_IDS[0]}" --arg two "${GITEA_SECRET_IDS[1]}" \
    '[.[], $one, $two] | unique' <<<"$current")
  onecli_cli agents set-secrets --id "$agent" --secret-ids "$(jq -r 'join(",")' <<<"$wanted")" >/dev/null
done
for pair in "$EXECUTOR_AGENT_ID:1" "$ANNOTATOR_AGENT_ID:2" "$HELM_AGENT_ID:3" "$BREAKGLASS_AGENT_ID:4"; do
  agent=${pair%:*} id=${SECRET_IDS[${pair#*:}]}
  onecli_cli agents set-secrets --id "$agent" --secret-ids "$id" >/dev/null
  onecli_cli agents secrets --id "$agent" | jq -e --arg id "$id" '.data == [$id]' >/dev/null
done
printf '%s\n' 'stored and assigned the Kubernetes and Gitea credentials; values were not printed'

step '5/6 merge the runtime config atomically into the state PVC'
# Chart sources the host has seen, as hints: any release works once a plan names its chart repo, and the host re-verifies it every time.
HELM_RELEASES='{
  "vaultwarden/vaultwarden": {"chart": "vaultwarden", "repo": "https://guerzon.github.io/vaultwarden", "file": "kubernetes/helm-charts/vaultwarden-values.yaml"},
  "gitea/gitea": {"chart": "gitea", "repo": "https://dl.gitea.com/charts/", "file": "kubernetes/helm-charts/gitea-values.yaml"},
  "nextcloud/nextcloud": {"chart": "nextcloud", "repo": "https://nextcloud.github.io/helm/", "file": "kubernetes/helm-charts/nextcloud-values.yaml"},
  "excalidraw/excalidraw": {"chart": "excalidraw", "repo": "https://pmoscode-helm.github.io/excalidraw/", "file": "kubernetes/helm-charts/excalidraw-values.yaml"},
  "wiki-js/wiki-js": {"chart": "wiki", "repo": "https://charts.js.wiki", "file": "kubernetes/helm-charts/wiki-js-values.yaml"},
  "logging/vlogs": {"chart": "victoria-logs-single", "repo": "https://victoriametrics.github.io/helm-charts/", "file": "kubernetes/helm-charts/victoria-logs-values.yaml"},
  "mail/docker-mailserver": {"chart": "docker-mailserver", "repo": "https://docker-mailserver.github.io/docker-mailserver-helm", "file": "kubernetes/helm-charts/docker-mailserver-values.yaml"},
  "logging/fluent-bit": {"chart": "fluent-bit", "repo": "https://fluent.github.io/helm-charts", "file": "kubernetes/helm-charts/fluent-bit-values.yaml"},
  "trivy-operator/trivy-operator": {"chart": "trivy-operator", "repo": "https://aquasecurity.github.io/helm-charts/", "file": "kubernetes/helm-charts/trivy-operator-values.yaml"},
  "longhorn-system/longhorn": {"chart": "longhorn", "repo": "https://charts.longhorn.io", "file": "kubernetes/helm-charts/longhorn-values.yaml"}
}'
CURRENT_CONFIG=$(kubectl exec -n "$NAMESPACE" "deploy/$ORCHESTRATOR" -c orchestrator -- \
  sh -c 'cat /opt/nanoclaw/data/kubernetes-remediation.json 2>/dev/null || echo {}')
jq -n \
  --argjson current "$CURRENT_CONFIG" \
  --arg agentGroupId "$ORCHESTRATOR_GROUP" \
  --arg matrixApproverUserId "$APPROVER" \
  --arg apiServer "$API_SERVER" \
  --arg executorOneCliAgent "$EXECUTOR" \
  --arg annotatorOneCliAgent "$ANNOTATOR" \
  --arg falcoBearerFile /run/nanoclaw/falco/bearer \
  --arg helmOneCliAgent "$HELM" \
  --arg breakGlassOneCliAgent "$BREAKGLASS" \
  --argjson helmReleases "$HELM_RELEASES" \
  --arg imageRegistry gitea.claw.jopdorp.nl/cluster \
  --arg registryPullSecret gitea-registry-push \
  '$current * {agentGroupId:$agentGroupId,matrixApproverUserId:$matrixApproverUserId,apiServer:$apiServer,
    executorOneCliAgent:$executorOneCliAgent,annotatorOneCliAgent:$annotatorOneCliAgent,
    falcoBearerFile:$falcoBearerFile,
    helmOneCliAgent:$helmOneCliAgent,breakGlassOneCliAgent:$breakGlassOneCliAgent,helmReleases:$helmReleases,
    imageRegistry:$imageRegistry,registryPullSecret:$registryPullSecret,
    t1:(($current.t1 // []) + ["nextcloud","mail","gitea"] | unique)}' \
  | kubectl exec -i -n "$NAMESPACE" "deploy/$ORCHESTRATOR" -c orchestrator -- \
      sh -c 'set -eu; umask 077; file=/opt/nanoclaw/data/kubernetes-remediation.json; cat > "$file.tmp"; mv "$file.tmp" "$file"'
kubectl exec -n "$NAMESPACE" "deploy/$ORCHESTRATOR" -c orchestrator -- \
  cat /opt/nanoclaw/data/kubernetes-remediation.json \
  | jq -e --arg group "$ORCHESTRATOR_GROUP" --arg approver "$APPROVER" \
      '.agentGroupId == $group and .matrixApproverUserId == $approver and (.t1 | length) > 0' >/dev/null
printf '%s\n' 'runtime config is present with its T1 list'

step '6/6 restart the orchestrator and confirm remediation is enabled'
kubectl rollout restart -n "$NAMESPACE" "deploy/$ORCHESTRATOR" >/dev/null
kubectl rollout status -n "$NAMESPACE" "deploy/$ORCHESTRATOR" --timeout=5m >/dev/null
NEW_POD=$(kubectl get pods -n "$NAMESPACE" -l app=nanoclaw-remediator-orchestrator \
  --sort-by=.metadata.creationTimestamp -o name | tail -n 1)
START_LOG=$(kubectl logs -n "$NAMESPACE" "$NEW_POD" -c orchestrator --tail=300)
if grep -Fq 'Kubernetes remediation disabled' <<<"$START_LOG"; then
  fail 'the restarted orchestrator still reports Kubernetes remediation disabled'
fi
printf 'confirmed %s no longer logs "Kubernetes remediation disabled"\n' "${NEW_POD#pod/}"

cat <<'EOF'

Trigger exactly one safe proposal with:
kubectl --kubeconfig=/home/jopdorp/.kube/mini-pc.fresh exec -n nanoclaw-remediator deploy/nanoclaw-remediator-orchestrator -c orchestrator -- sh -c 'curl -fsS -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer $(cat /run/nanoclaw/falco/bearer)" -H "Content-Type: application/json" --data '\''{"time":"2026-10-21T00:00:00Z","rule":"NanoClaw safe smoke test","priority":"Notice","output_fields":{"k8s.ns.name":"gitea","k8s.pod.name":"nanoclaw-nonexistent-smoke-test"}}'\'' http://127.0.0.1:3000/webhook/kubernetes-falco'
Low-risk plans apply on their own and are reported to matrix:@jopdorp:matrix.org; the rest wait for approval in Matrix.
EOF
