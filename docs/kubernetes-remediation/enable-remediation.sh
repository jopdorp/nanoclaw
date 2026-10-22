#!/usr/bin/env bash
set -euo pipefail

export KUBECONFIG=/home/jopdorp/.kube/mini-pc.fresh

ROOT=/home/jopdorp/development/nanoclaw-v2
DOCS="$ROOT/docs/kubernetes-remediation"
NAMESPACE=nanoclaw-remediator
ORCHESTRATOR=nanoclaw-remediator-orchestrator
ORCHESTRATOR_GROUP=ag-4be55056-f0a3-4991-a83e-a347b75de07d
INVESTIGATOR_GROUP=ag-491b4ac2-4451-47dc-8d4e-6872dbe66ac5
VERIFIER_GROUP=ag-e95b148c-8c90-4247-b6d1-0b75db805138
APPROVER='matrix:@jopdorp:matrix.org'
API_SERVER=https://192.168.1.11:6443
API_HOST=192.168.1.11
EXECUTOR=nanoclaw-remediation-executor
ANNOTATOR=nanoclaw-remediation-annotator
READ_SECRET=nanoclaw-remediator-kubernetes
APPROVER_SECRET=nanoclaw-remediation-approver-kubernetes
LOGIN_JOB=nanoclaw-provider-login
LOGIN_POD=
CREATED_LOGIN_JOB=0
TOKEN_FILES=(/tmp/nanoclaw-remediator.token /tmp/nanoclaw-remediation-approver.token)

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
      rm -f "${TOKEN_FILES[@]}" >/dev/null 2>&1 || true
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

step 'precheck: prove the latest Investigator turn used working DeepSeek routing'
GROUPS=$(ncl groups list --json --limit 100000)
for group_id in "$ORCHESTRATOR_GROUP" "$INVESTIGATOR_GROUP" "$VERIFIER_GROUP"; do
  jq -e --arg id "$group_id" '.data[] | select(.id == $id)' <<<"$GROUPS" >/dev/null \
    || todo "agent group $group_id is absent; update the pinned IDs before enabling remediation"
done

INVESTIGATOR_POD=$(kubectl get pods -n "$NAMESPACE" -l "nanoclaw-group=$INVESTIGATOR_GROUP" \
  --sort-by=.metadata.creationTimestamp -o name | tail -n 1)
DEEPSEEK_STATUS='not proven: no Investigator session pod exists'
if [[ -n "$INVESTIGATOR_POD" ]]; then
  INVESTIGATOR_LOG=$(kubectl logs -n "$NAMESPACE" "$INVESTIGATOR_POD" -c agent --tail=1000 2>&1 || true)
  LAST_SIGNAL=$(grep -E '\[poll-loop\] (Result:|Error:)|\[agent-runner\] Fatal|Failed to authenticate|API Error:' \
    <<<"$INVESTIGATOR_LOG" | tail -n 1 || true)
  if [[ "$LAST_SIGNAL" == *'[poll-loop] Result:'* ]] \
    && ! grep -Eqi 'error|fail|401|403|no credentials|unauthorized|authentication' <<<"$LAST_SIGNAL"; then
    DEEPSEEK_STATUS="proven by the latest successful Investigator result in ${INVESTIGATOR_POD#pod/}"
  elif [[ -n "$LAST_SIGNAL" ]]; then
    DEEPSEEK_STATUS="not proven: the latest Investigator turn in ${INVESTIGATOR_POD#pod/} ended in an error"
  else
    DEEPSEEK_STATUS="not proven: ${INVESTIGATOR_POD#pod/} has no completed turn"
  fi
fi
printf 'DeepSeek routing: %s\n' "$DEEPSEEK_STATUS"
if [[ "$DEEPSEEK_STATUS" != proven* && "${FORCE:-0}" != 1 ]]; then
  printf '%s\n' 'WARNING: gateway-config.yaml keeps launch blocked until deepseek-routing-proven.' >&2
  fail 're-run with FORCE=1 only if you intentionally accept this unresolved launch gate'
fi
if [[ "$DEEPSEEK_STATUS" != proven* ]]; then
  printf '%s\n' 'WARNING: FORCE=1 accepted; DeepSeek routing remains an unresolved production gate.' >&2
fi

step '1/6 apply the approval-controller identity and admission policies idempotently'
kubectl apply -f "$DOCS/approval-controller-rbac.yaml" >/dev/null
kubectl apply --server-side -f "$DOCS/approval-controller-policy.yaml" >/dev/null
printf '%s\n' 'approval-controller RBAC and policies are present'

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

upsert_kubernetes_secret() {
  local name=$1 token_file=$2
  kubectl exec -i -n "$NAMESPACE" "$LOGIN_POD" -c login -- \
    node - "$name" "$token_file" <<'NODE'
const fs = require('node:fs');

const [name, file] = process.argv.slice(2);
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
const injectionConfig = { headerName: 'Authorization', valueFormat: 'Bearer {value}' };
const existing = matches[0];
if (existing && (
  existing.type !== 'generic' ||
  existing.hostPattern !== '192.168.1.11' ||
  existing.pathPattern ||
  (existing.valueSource && existing.valueSource !== 'inline') ||
  (existing.opRef !== undefined && existing.opRef !== null)
)) throw new Error(`Existing OneCLI secret ${name} has unexpected metadata`);
const payload = { value: token, hostPattern: '192.168.1.11', injectionConfig };
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

ensure_block_rule() {
  local method=$1 name="nanoclaw-remediator-kubernetes-block-${1,,}" rules count id
  rules=$(onecli_cli rules list)
  count=$(jq -r --arg name "$name" '[.data[] | select(.name == $name)] | length' <<<"$rules")
  (( count <= 1 )) || todo "multiple OneCLI rules are named $name"
  if (( count == 0 )); then
    onecli_cli rules create --name "$name" --host-pattern "$API_HOST" --action block \
      --method "$method" --agent-id "$PRIMARY_AGENT_ID" --enabled >/dev/null
    printf 'created orchestrator block rule for %s\n' "$method"
  else
    id=$(jq -er --arg name "$name" '.data[] | select(.name == $name) | .id' <<<"$rules")
    onecli_cli rules update --id "$id" --name "$name" --host-pattern "$API_HOST" --action block \
      --method "$method" --agent-id "$PRIMARY_AGENT_ID" --enabled >/dev/null
    printf 'confirmed orchestrator block rule for %s\n' "$method"
  fi
}
ensure_agent "$ORCHESTRATOR_GROUP" 'Kubernetes Remediator' false
PRIMARY_AGENT_ID=$ENSURED_AGENT_ID
for method in POST PUT PATCH DELETE; do ensure_block_rule "$method"; done

PRIMARY_PROVIDER_IDS=$(onecli_cli agents secrets --id "$PRIMARY_AGENT_ID" \
  | jq -r --arg codex "$CODEX_SECRET_ID" '[.data[], $codex] | unique | join(",")')
onecli_cli agents set-secrets --id "$PRIMARY_AGENT_ID" --secret-ids "$PRIMARY_PROVIDER_IDS" >/dev/null
ensure_agent "$EXECUTOR" 'NanoClaw Remediation Executor' true
EXECUTOR_AGENT_ID=$ENSURED_AGENT_ID
onecli_cli agents set-secret-mode --id "$EXECUTOR_AGENT_ID" --mode selective >/dev/null
ensure_agent "$ANNOTATOR" 'NanoClaw Remediation Annotator' true
ANNOTATOR_AGENT_ID=$ENSURED_AGENT_ID
onecli_cli agents set-secret-mode --id "$ANNOTATOR_AGENT_ID" --mode selective >/dev/null
AGENTS=$(onecli_cli agents list)
for id in "$PRIMARY_AGENT_ID" "$EXECUTOR_AGENT_ID" "$ANNOTATOR_AGENT_ID"; do
  jq -e --arg id "$id" '.data[] | select(.id == $id and .secretMode == "selective")' <<<"$AGENTS" >/dev/null \
    || fail "OneCLI agent $id is not in selective secret mode"
done
printf '%s\n' 'selective OneCLI identities and orchestrator write blocks are active'

step '4/6 rotate one-hour TokenRequest credentials in the OneCLI vault'
kubectl create token -n "$NAMESPACE" nanoclaw-remediator --duration=1h \
  | kubectl exec -i -n "$NAMESPACE" "$LOGIN_POD" -c login -- \
      sh -c 'umask 077; cat > /tmp/nanoclaw-remediator.token'
kubectl create token -n "$NAMESPACE" nanoclaw-remediation-approver --duration=1h \
  | kubectl exec -i -n "$NAMESPACE" "$LOGIN_POD" -c login -- \
      sh -c 'umask 077; cat > /tmp/nanoclaw-remediation-approver.token'
printf '%s\n' 'created fresh one-hour tokens without printing their values'

READ_SECRET_ID=$(upsert_kubernetes_secret "$READ_SECRET" "${TOKEN_FILES[0]}") \
  || todo "could not create or rotate OneCLI secret $READ_SECRET"
APPROVER_SECRET_ID=$(upsert_kubernetes_secret "$APPROVER_SECRET" "${TOKEN_FILES[1]}") \
  || todo "could not create or rotate OneCLI secret $APPROVER_SECRET"
kubectl exec -n "$NAMESPACE" "$LOGIN_POD" -c login -- rm -f "${TOKEN_FILES[@]}"

PRIMARY_SECRET_IDS=$(onecli_cli agents secrets --id "$PRIMARY_AGENT_ID" \
  | jq -r --arg read "$READ_SECRET_ID" '[.data[], $read] | unique | join(",")')
onecli_cli agents set-secrets --id "$PRIMARY_AGENT_ID" --secret-ids "$PRIMARY_SECRET_IDS" >/dev/null
onecli_cli agents set-secrets --id "$EXECUTOR_AGENT_ID" --secret-ids "$READ_SECRET_ID" >/dev/null
onecli_cli agents set-secrets --id "$ANNOTATOR_AGENT_ID" --secret-ids "$APPROVER_SECRET_ID" >/dev/null
onecli_cli agents secrets --id "$PRIMARY_AGENT_ID" | jq -e --arg id "$READ_SECRET_ID" '.data | index($id)' >/dev/null
onecli_cli agents secrets --id "$EXECUTOR_AGENT_ID" | jq -e --arg id "$READ_SECRET_ID" '.data == [$id]' >/dev/null
onecli_cli agents secrets --id "$ANNOTATOR_AGENT_ID" | jq -e --arg id "$APPROVER_SECRET_ID" '.data == [$id]' >/dev/null
printf '%s\n' 'stored and assigned both Kubernetes credentials; values were not printed'
printf '%s\n' 'WARNING: these TokenRequest credentials expire after one hour; production still requires the reviewed refresher.'

step '5/6 write the approval-required runtime config atomically into the state PVC'
jq -n \
  --arg agentGroupId "$ORCHESTRATOR_GROUP" \
  --arg matrixApproverUserId "$APPROVER" \
  --arg apiServer "$API_SERVER" \
  --arg executorOneCliAgent "$EXECUTOR" \
  --arg annotatorOneCliAgent "$ANNOTATOR" \
  --arg falcoBearerFile /run/nanoclaw/falco/bearer \
  '{agentGroupId:$agentGroupId,matrixApproverUserId:$matrixApproverUserId,apiServer:$apiServer,
    executorOneCliAgent:$executorOneCliAgent,annotatorOneCliAgent:$annotatorOneCliAgent,
    falcoBearerFile:$falcoBearerFile,approvalRequired:true}' \
  | kubectl exec -i -n "$NAMESPACE" "deploy/$ORCHESTRATOR" -c orchestrator -- \
      sh -c 'set -eu; umask 077; file=/opt/nanoclaw/data/kubernetes-remediation.json; cat > "$file.tmp"; mv "$file.tmp" "$file"'
kubectl exec -n "$NAMESPACE" "deploy/$ORCHESTRATOR" -c orchestrator -- \
  cat /opt/nanoclaw/data/kubernetes-remediation.json \
  | jq -e --arg group "$ORCHESTRATOR_GROUP" --arg approver "$APPROVER" \
      '.agentGroupId == $group and .matrixApproverUserId == $approver and .approvalRequired == true' >/dev/null
printf '%s\n' 'runtime config is present with approvalRequired=true'

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
Nothing is applied unless matrix:@jopdorp:matrix.org explicitly approves it in Matrix.
EOF
