#!/usr/bin/env bash
set -euo pipefail

export KUBECONFIG=~/.kube/mini-pc.fresh

ROOT=/home/jopdorp/development/nanoclaw-v2
DOCS="$ROOT/docs/kubernetes-remediation"
NAMESPACE=nanoclaw-remediator
ORCHESTRATOR=nanoclaw-remediator-orchestrator
SYNAPSE_NAMESPACE=openclaw-private
SYNAPSE_SERVICE=matrix-synapse
SYNAPSE_CONFIG=/data/homeserver.yaml
REGISTRY=registry.prophet.jopdorp.nl/nanoclaw
BOT_LOCALPART=nanoclaw-remediator
OWNER_MATRIX_ID=@jopdorp:matrix.org
ROOM_LOCALPART=nanoclaw-remediation
TMP_DIR=$(mktemp -d)
PORT_FORWARD_PID=

# Teardown: kubectl delete namespace nanoclaw-remediator

cleanup() {
  if [[ -n "$PORT_FORWARD_PID" ]]; then
    kill "$PORT_FORWARD_PID" 2>/dev/null || true
    wait "$PORT_FORWARD_PID" 2>/dev/null || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT
chmod 700 "$TMP_DIR"

step() { printf '\n==> %s\n' "$*"; }
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

ncl() {
  kubectl exec -n "$NAMESPACE" "deploy/$ORCHESTRATOR" -- env HOME=/tmp node_modules/.bin/tsx src/cli/client.ts "$@"
}

ensure_patch_lines() {
  local patch=$1 file= line
  while IFS= read -r line; do
    case "$line" in
      '+++ b/'*) file=${line#+++ b/} ;;
      '+++'*|'---'*) ;;
      '+'*) line=${line#+}; grep -qxF -- "$line" "$file" || printf '%s\n' "$line" >>"$file" ;;
    esac
  done <"$patch"
}
apply_patch_once() {
  local patch=$1
  if git apply --reverse --check "$patch" >/dev/null 2>&1; then
    printf 'already applied: %s\n' "${patch#$ROOT/}"
  else
    git apply --check "$patch"
    git apply "$patch"
  fi
}

repo_digest() {
  local tag=$1 repo=$2 digest
  digest=$(docker image inspect "$tag" --format '{{range .RepoDigests}}{{println .}}{{end}}' \
    | awk -v repo="$repo" 'index($0, repo "@sha256:") == 1 { print; exit }')
  [[ "$digest" =~ ^${repo}@sha256:[0-9a-f]{64}$ ]] || fail "could not resolve pushed digest for $tag"
  printf '%s' "$digest"
}

prune_registry_tags() (
  local host=${REGISTRY%%/*} namespace=${REGISTRY#*/} auth repo image current tag digest config created
  local work="$TMP_DIR/registry-prune" headers manifest blob tags rows keep_file delete_file count
  auth=$(jq -er --arg host "$host" '.auths[$host].auth // .auths["https://" + $host].auth // empty' ~/.docker/config.json)
  auth=$(printf '%s' "$auth" | base64 -d)
  mkdir -p "$work"

  for entry in "remediation-agent $AGENT_IMAGE" "remediation-host $HOST_IMAGE"; do
    read -r repo image <<<"$entry"
    current=${image##*@}
    rows="$work/$repo.rows"
    tags="$work/$repo.tags"
    keep_file="$work/$repo.keep"
    delete_file="$work/$repo.delete"
    : >"$rows"
    curl -fsS -u "$auth" "https://$host/v2/$namespace/$repo/tags/list" >"$tags" || return 1
    while IFS= read -r tag; do
      headers="$work/$repo.headers"
      manifest="$work/$repo.manifest"
      blob="$work/$repo.blob"
      curl -fsS -u "$auth" -I \
        -H 'Accept: application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json' \
        "https://$host/v2/$namespace/$repo/manifests/$tag" >"$headers" || return 1
      digest=$(awk 'BEGIN { IGNORECASE=1 } /^Docker-Content-Digest:/ { sub("\r$", "", $2); print $2; exit }' "$headers")
      [[ -n "$digest" ]] || return 1
      curl -fsS -u "$auth" \
        -H 'Accept: application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json' \
        "https://$host/v2/$namespace/$repo/manifests/$tag" >"$manifest" || return 1
      config=$(jq -r '.config.digest // empty' "$manifest")
      created=
      if [[ -n "$config" ]]; then
        curl -fsS -u "$auth" "https://$host/v2/$namespace/$repo/blobs/$config" >"$blob" || return 1
        created=$(jq -r '.created // empty' "$blob")
      fi
      printf '%s\t%s\t%s\n' "${created:-0000}" "$tag" "$digest" >>"$rows"
    done < <(jq -r '.tags[]?' "$tags")

    { printf '%s\n' "$current"; sort -r "$rows" | head -n 2 | cut -f3; } | sort -u >"$keep_file"
    awk -F '\t' 'NR == FNR { keep[$1]; next } !($3 in keep) { print $2 "\t" $3 }' \
      "$keep_file" "$rows" >"$delete_file"
    count=$(wc -l <"$delete_file")
    if [[ "${PRUNE_DRY_RUN:-}" = 1 ]]; then
      while IFS=$'\t' read -r tag digest; do
        printf 'would prune %s:%s (%s)\n' "$repo" "$tag" "$digest"
      done <"$delete_file"
    else
      cut -f2 "$delete_file" | sort -u | while IFS= read -r digest; do
        [[ -z "$digest" ]] || curl -fsS -u "$auth" -X DELETE \
          "https://$host/v2/$namespace/$repo/manifests/$digest" >/dev/null || return 1
      done
    fi
    printf 'pruned %s tags from %s/%s\n' "$count" "$namespace" "$repo"
  done
  # The registry needs registry garbage-collect to reclaim blobs; Orfie runs it.
)

matrix_call() {
  local method=$1 path=$2 body=${3:-} output=$4
  local args=(-sS -o "$output" -w '%{http_code}' -X "$method" "http://127.0.0.1:18008$path")
  [[ -f "$TMP_DIR/matrix-auth.conf" ]] && args+=(--config "$TMP_DIR/matrix-auth.conf")
  [[ -n "$body" ]] && args+=(-H 'Content-Type: application/json' --data-binary "@$body")
  curl "${args[@]}"
}

store_matrix_credentials() {
  local token=$1 password=$2 patch_file="$TMP_DIR/secret-patch.json"
  jq -n \
    --arg token "$(printf '%s' "$token" | base64 | tr -d '\n')" \
    --arg password "$(printf '%s' "$password" | base64 | tr -d '\n')" \
    '{data:{"matrix-access-token":$token,"matrix-password":$password}}' >"$patch_file"
  chmod 600 "$patch_file"
  kubectl patch secret -n "$NAMESPACE" nanoclaw-runtime --type merge --patch-file "$patch_file" >/dev/null
}

write_group_file() {
  local folder=$1 destination=$2 source=$3
  kubectl exec -n "$NAMESPACE" "deploy/$ORCHESTRATOR" -- \
    mkdir -p "/opt/nanoclaw/groups/$folder/$(dirname "$destination")"
  kubectl exec -i -n "$NAMESPACE" "deploy/$ORCHESTRATOR" -- \
    sh -c "umask 077; cat > '/opt/nanoclaw/groups/$folder/$destination'" <"$source"
}

cd "$ROOT"

step '1/6 install Matrix adapter, rebuild immutable images, and redeploy'
test "$(kubectl config current-context)" = default || fail 'KUBECONFIG is not on context default'
test "$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')" = https://192.168.1.11:6443 \
  || fail 'KUBECONFIG does not point at HOME (https://192.168.1.11:6443)'

if [[ "${ONLY_REDEPLOY:-}" != 1 ]] && kubectl exec -n "$NAMESPACE" "deploy/$ORCHESTRATOR" -- \
  test -e /opt/nanoclaw/data/kubernetes-remediation.json 2>/dev/null; then
  fail 'remediation runtime config already exists; remove/disable it before this no-finding phase'
fi

# src/channels/matrix.ts is ours (reply-to support); never overwrite it from upstream.
grep -qxF "import './matrix.js';" src/channels/index.ts \
  || printf "import './matrix.js';\n" >>src/channels/index.ts
install -Dm0644 .claude/skills/add-matrix/patches/@beeper__chat-adapter-matrix@0.2.0.patch \
  patches/@beeper__chat-adapter-matrix@0.2.0.patch
pnpm pkg set 'pnpm.patchedDependencies[@beeper/chat-adapter-matrix@0.2.0]=patches/@beeper__chat-adapter-matrix@0.2.0.patch'
pnpm add --save-exact @beeper/chat-adapter-matrix@0.2.0
for file in \
  src/providers/index.ts \
  src/provider-contracts/index.ts \
  container/agent-runner/src/providers/index.ts \
  container/agent-runner/src/provider-contracts/index.ts; do
  grep -qxF "import './claude-remediation.review.js';" "$file" \
    || printf "import './claude-remediation.review.js';\n" >>"$file"
done
ensure_patch_lines "$DOCS/enable-remediation-review.patch"
pnpm run build
node --input-type=module -e 'await import("@beeper/chat-adapter-matrix")'
pnpm exec vitest run src/channels/matrix-registration.test.ts

GIT_COMMIT=$(git rev-parse --verify HEAD)
GIT_TREE=$(git rev-parse --verify 'HEAD^{tree}')
[[ "$GIT_COMMIT" =~ ^[0-9a-f]{40}$ && "$GIT_TREE" =~ ^[0-9a-f]{40}$ ]] \
  || fail 'real GIT_COMMIT/GIT_TREE provenance could not be resolved'
MATRIX_BUILD_ID=$(sha256sum src/channels/matrix.ts src/drivers/kubernetes-driver.ts src/modules/kubernetes-remediation/*.ts src/gateway-providers/onecli.ts src/gateway-providers/onecli-chatgpt-stub.ts container/agent-runner/src/mcp-tools/kubernetes-remediation.review.ts package.json pnpm-lock.yaml container/Dockerfile "$DOCS/host.Dockerfile" \
  | sha256sum | cut -c1-12)
TAG_SUFFIX="phase2-matrix-${GIT_COMMIT:0:12}-$MATRIX_BUILD_ID"
AGENT_TAG="$REGISTRY/remediation-agent:$TAG_SUFFIX"
HOST_TAG="$REGISTRY/remediation-host:$TAG_SUFFIX"

if docker manifest inspect "$AGENT_TAG" >/dev/null 2>&1; then
  printf 'already pushed: %s\n' "$AGENT_TAG"
  docker pull "$AGENT_TAG" >/dev/null
else
  docker build --build-arg "GIT_COMMIT=$GIT_COMMIT" --build-arg "GIT_TREE=$GIT_TREE" \
    -f container/Dockerfile -t "$AGENT_TAG" container
  docker push "$AGENT_TAG"
fi
AGENT_IMAGE=$(repo_digest "$AGENT_TAG" "$REGISTRY/remediation-agent")

if docker manifest inspect "$HOST_TAG" >/dev/null 2>&1; then
  printf 'already pushed: %s\n' "$HOST_TAG"
  docker pull "$HOST_TAG" >/dev/null
else
  docker build --build-arg "AGENT_IMAGE=$AGENT_IMAGE" --build-arg "GIT_COMMIT=$GIT_COMMIT" \
    --build-arg "GIT_TREE=$GIT_TREE" -f "$DOCS/host.Dockerfile" -t "$HOST_TAG" .
  docker push "$HOST_TAG"
fi
HOST_IMAGE=$(repo_digest "$HOST_TAG" "$REGISTRY/remediation-host")

sed -E -i \
  "s#registry\.prophet\.jopdorp\.nl/nanoclaw/remediation-agent@sha256:[0-9a-f]{64}#$AGENT_IMAGE#g; s#registry\.prophet\.jopdorp\.nl/nanoclaw/remediation-host@sha256:[0-9a-f]{64}#$HOST_IMAGE#g" \
  "$DOCS/in-cluster-runtime.review.yaml"
grep -qF "$AGENT_IMAGE" "$DOCS/in-cluster-runtime.review.yaml" || fail 'agent digest update failed'
grep -qF "$HOST_IMAGE" "$DOCS/in-cluster-runtime.review.yaml" || fail 'host digest update failed'
# Session Jobs pin the RWO state volume to the old host node; recycle them so the new host can attach.
kubectl -n "$NAMESPACE" delete job -l nanoclaw-group-folder --ignore-not-found >/dev/null
kubectl apply -f "$DOCS/in-cluster-runtime.review.yaml"
kubectl rollout status -n "$NAMESPACE" "deploy/$ORCHESTRATOR" --timeout=5m
prune_registry_tags || printf 'WARNING: registry tag pruning failed\n' >&2

[[ "${ONLY_REDEPLOY:-}" = 1 ]] && { printf 'ONLY_REDEPLOY: images rebuilt and orchestrator redeployed; skipping setup steps 2-6.\n'; exit 0; }
step '2/6 register/reuse the non-admin Matrix bot and wire its token'
SERVER_NAME=$(kubectl exec -n "$SYNAPSE_NAMESPACE" "deploy/$SYNAPSE_SERVICE" -- \
  python3 -c "import yaml; print(yaml.safe_load(open('$SYNAPSE_CONFIG'))['server_name'])")
[[ -n "$SERVER_NAME" ]] || fail 'could not read Synapse server_name'
BOT_MATRIX_ID="@$BOT_LOCALPART:$SERVER_NAME"

kubectl exec -n "$SYNAPSE_NAMESPACE" "deploy/$SYNAPSE_SERVICE" -- \
  python3 -c "import yaml; assert yaml.safe_load(open('$SYNAPSE_CONFIG')).get('registration_shared_secret')" \
  >/dev/null || fail 'Synapse registration_shared_secret is unavailable'

kubectl port-forward -n "$SYNAPSE_NAMESPACE" "service/$SYNAPSE_SERVICE" 18008:8008 \
  >"$TMP_DIR/port-forward.log" 2>&1 &
PORT_FORWARD_PID=$!
for _ in $(seq 1 30); do
  curl -fsS http://127.0.0.1:18008/_matrix/client/versions >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS http://127.0.0.1:18008/_matrix/client/versions >/dev/null \
  || fail "Synapse port-forward failed: $(tr '\n' ' ' <"$TMP_DIR/port-forward.log")"

MATRIX_TOKEN=$(kubectl get secret -n "$NAMESPACE" nanoclaw-runtime \
  -o jsonpath='{.data.matrix-access-token}' 2>/dev/null | base64 -d 2>/dev/null || true)
MATRIX_PASSWORD=$(kubectl get secret -n "$NAMESPACE" nanoclaw-runtime \
  -o jsonpath='{.data.matrix-password}' 2>/dev/null | base64 -d 2>/dev/null || true)

TOKEN_VALID=false
TOKEN_CHANGED=false
if [[ -n "$MATRIX_TOKEN" ]]; then
  printf 'header = "Authorization: Bearer %s"\n' "$MATRIX_TOKEN" >"$TMP_DIR/matrix-auth.conf"
  chmod 600 "$TMP_DIR/matrix-auth.conf"
  HTTP=$(matrix_call GET /_matrix/client/v3/account/whoami '' "$TMP_DIR/whoami.json")
  if [[ "$HTTP" = 200 ]] && [[ $(jq -r '.user_id // empty' "$TMP_DIR/whoami.json") = "$BOT_MATRIX_ID" ]]; then
    TOKEN_VALID=true
  fi
fi

if [[ "$TOKEN_VALID" != true ]]; then
  PROFILE_PATH="/_matrix/client/v3/profile/$(printf '%s' "$BOT_MATRIX_ID" | jq -sRr @uri)"
  rm -f "$TMP_DIR/matrix-auth.conf"
  HTTP=$(matrix_call GET "$PROFILE_PATH" '' "$TMP_DIR/profile.json")
  if [[ "$HTTP" = 404 ]]; then
    MATRIX_PASSWORD=$(openssl rand -base64 36 | tr -d '\n')
    printf '%s\n%s\n' "$MATRIX_PASSWORD" "$MATRIX_PASSWORD" | \
      kubectl exec -i -n "$SYNAPSE_NAMESPACE" "deploy/$SYNAPSE_SERVICE" -- \
        register_new_matrix_user -c "$SYNAPSE_CONFIG" -u "$BOT_LOCALPART" --no-admin http://127.0.0.1:8008 \
        >/dev/null
  elif [[ "$HTTP" != 200 ]]; then
    fail "could not determine whether $BOT_MATRIX_ID exists (HTTP $HTTP: $(jq -c . "$TMP_DIR/profile.json" 2>/dev/null || true))"
  elif [[ -z "$MATRIX_PASSWORD" ]]; then
    fail "$BOT_MATRIX_ID already exists but no reusable matrix-password is stored in secret nanoclaw-runtime"
  fi

  jq -n --arg user "$BOT_LOCALPART" --arg password "$MATRIX_PASSWORD" \
    '{type:"m.login.password",identifier:{type:"m.id.user",user:$user},password:$password}' \
    >"$TMP_DIR/login.json"
  chmod 600 "$TMP_DIR/login.json"
  HTTP=$(matrix_call POST /_matrix/client/v3/login "$TMP_DIR/login.json" "$TMP_DIR/login-response.json")
  [[ "$HTTP" = 200 ]] || fail "Matrix bot login failed (HTTP $HTTP)"
  MATRIX_TOKEN=$(jq -r '.access_token // empty' "$TMP_DIR/login-response.json")
  [[ -n "$MATRIX_TOKEN" ]] || fail 'Matrix login returned no access token'
  store_matrix_credentials "$MATRIX_TOKEN" "$MATRIX_PASSWORD"
  TOKEN_CHANGED=true
  printf 'header = "Authorization: Bearer %s"\n' "$MATRIX_TOKEN" >"$TMP_DIR/matrix-auth.conf"
  chmod 600 "$TMP_DIR/matrix-auth.conf"
fi

kubectl set env -n "$NAMESPACE" "deploy/$ORCHESTRATOR" \
  MATRIX_BASE_URL="http://$SYNAPSE_SERVICE.$SYNAPSE_NAMESPACE.svc:8008" \
  MATRIX_USER_ID="$BOT_MATRIX_ID" MATRIX_BOT_USERNAME='NanoClaw Remediator' \
  MATRIX_INVITE_AUTOJOIN=true MATRIX_INVITE_AUTOJOIN_ALLOWLIST="$OWNER_MATRIX_ID" >/dev/null
if [[ "$TOKEN_CHANGED" = true ]]; then
  kubectl rollout restart -n "$NAMESPACE" "deploy/$ORCHESTRATOR" >/dev/null
fi
kubectl rollout status -n "$NAMESPACE" "deploy/$ORCHESTRATOR" --timeout=5m

step '3/6 federation pre-check (fail closed before invitation)'
OWNER_PROFILE="/_matrix/client/v3/profile/$(printf '%s' "$OWNER_MATRIX_ID" | jq -sRr @uri)"
rm -f "$TMP_DIR/matrix-auth.conf"
HTTP=$(matrix_call GET "$OWNER_PROFILE" '' "$TMP_DIR/owner-profile.json")
if [[ "$HTTP" != 200 ]]; then
  printf 'FEDERATION PRE-CHECK FAILED: in-cluster Synapse cannot resolve %s through federation (HTTP %s: %s).\n' \
    "$OWNER_MATRIX_ID" "$HTTP" "$(jq -c . "$TMP_DIR/owner-profile.json" 2>/dev/null || tr '\n' ' ' <"$TMP_DIR/owner-profile.json")" >&2
  printf 'Fallback: use an account on the %s homeserver instead of %s.\n' "$SERVER_NAME" "$OWNER_MATRIX_ID" >&2
  exit 1
fi

FEDERATION_REPORT="$TMP_DIR/federation-report.json"
HTTP=$(curl -sS -o "$FEDERATION_REPORT" -w '%{http_code}' \
  "https://federationtester.matrix.org/api/report?server_name=$(printf '%s' "$SERVER_NAME" | jq -sRr @uri)")
if [[ "$HTTP" != 200 ]] || ! jq -e '.FederationOK == true' "$FEDERATION_REPORT" >/dev/null 2>&1; then
  printf 'FEDERATION PRE-CHECK FAILED: matrix.org-side public federation cannot reach %s (HTTP %s: %s).\n' \
    "$SERVER_NAME" "$HTTP" "$(jq -c '{FederationOK,ConnectionReports,Errors}' "$FEDERATION_REPORT" 2>/dev/null || tr '\n' ' ' <"$FEDERATION_REPORT")" >&2
  printf 'Fallback: use an account on the %s homeserver instead of %s.\n' "$SERVER_NAME" "$OWNER_MATRIX_ID" >&2
  exit 1
fi
printf 'federation is reachable in both directions\n'

step '4/6 create/reuse the room, invite the owner, and post the online marker'
printf 'header = "Authorization: Bearer %s"\n' "$MATRIX_TOKEN" >"$TMP_DIR/matrix-auth.conf"
chmod 600 "$TMP_DIR/matrix-auth.conf"
ROOM_ALIAS="#$ROOM_LOCALPART:$SERVER_NAME"
ALIAS_PATH="/_matrix/client/v3/directory/room/$(printf '%s' "$ROOM_ALIAS" | jq -sRr @uri)"
HTTP=$(matrix_call GET "$ALIAS_PATH" '' "$TMP_DIR/room-alias.json")
if [[ "$HTTP" = 200 ]]; then
  ROOM_ID=$(jq -r '.room_id // empty' "$TMP_DIR/room-alias.json")
elif [[ "$HTTP" = 404 ]]; then
  jq -n --arg alias "$ROOM_LOCALPART" \
    '{room_alias_name:$alias,name:"NanoClaw Kubernetes Remediation",topic:"HOME k3s remediation approvals",preset:"private_chat",is_direct:false}' \
    >"$TMP_DIR/create-room.json"
  HTTP=$(matrix_call POST /_matrix/client/v3/createRoom "$TMP_DIR/create-room.json" "$TMP_DIR/create-room-response.json")
  [[ "$HTTP" = 200 ]] || fail "Matrix room creation failed (HTTP $HTTP)"
  ROOM_ID=$(jq -r '.room_id // empty' "$TMP_DIR/create-room-response.json")
else
  fail "Matrix room lookup failed (HTTP $HTTP)"
fi
[[ -n "$ROOM_ID" ]] || fail 'Matrix room ID is empty'

ENCODED_ROOM=$(printf '%s' "$ROOM_ID" | jq -sRr @uri)
ENCODED_OWNER=$(printf '%s' "$OWNER_MATRIX_ID" | jq -sRr @uri)
HTTP=$(matrix_call GET "/_matrix/client/v3/rooms/$ENCODED_ROOM/state/m.room.member/$ENCODED_OWNER" '' "$TMP_DIR/member.json")
MEMBERSHIP=$(jq -r '.membership // empty' "$TMP_DIR/member.json" 2>/dev/null || true)
if [[ "$MEMBERSHIP" != invite && "$MEMBERSHIP" != join ]]; then
  jq -n --arg user_id "$OWNER_MATRIX_ID" '{user_id:$user_id}' >"$TMP_DIR/invite.json"
  HTTP=$(matrix_call POST "/_matrix/client/v3/rooms/$ENCODED_ROOM/invite" "$TMP_DIR/invite.json" "$TMP_DIR/invite-response.json")
  [[ "$HTTP" = 200 ]] || fail "Matrix invite failed (HTTP $HTTP: $(jq -c . "$TMP_DIR/invite-response.json" 2>/dev/null || true))"
fi

jq -n '{msgtype:"m.text",body:"bot online"}' >"$TMP_DIR/bot-online.json"
HTTP=$(matrix_call PUT "/_matrix/client/v3/rooms/$ENCODED_ROOM/send/m.room.message/phase2-bot-online" \
  "$TMP_DIR/bot-online.json" "$TMP_DIR/bot-online-response.json")
[[ "$HTTP" = 200 ]] || fail "Matrix test message failed (HTTP $HTTP)"

step '5/6 instantiate Codex/Sol primary plus gateway-routed DeepSeek subagents'
PRIMARY_JSON=$(ncl groups create --folder kubernetes-remediator --name 'Kubernetes Remediator' --json)
PRIMARY_ID=$(jq -r '.id // empty' <<<"$PRIMARY_JSON")
INVESTIGATOR_JSON=$(ncl groups create --folder kubernetes-remediation-investigator --name 'Kubernetes Remediation Investigator' --json)
INVESTIGATOR_ID=$(jq -r '.id // empty' <<<"$INVESTIGATOR_JSON")
VERIFIER_JSON=$(ncl groups create --folder kubernetes-remediation-verifier --name 'Kubernetes Remediation Verifier' --json)
VERIFIER_ID=$(jq -r '.id // empty' <<<"$VERIFIER_JSON")
[[ -n "$PRIMARY_ID" && -n "$INVESTIGATOR_ID" && -n "$VERIFIER_ID" ]] || fail 'agent group creation returned an empty ID'

ncl groups config update --id "$PRIMARY_ID" --provider codex --model gpt-5.6-sol --effort high --cli-scope disabled >/dev/null
ncl groups config update --id "$INVESTIGATOR_ID" --provider claude-remediation --model deepseek-chat --effort xhigh --cli-scope disabled >/dev/null
ncl groups config update --id "$VERIFIER_ID" --provider claude-remediation --model deepseek-chat --effort xhigh --cli-scope disabled >/dev/null

cat "$DOCS/agent-group/CLAUDE.md" "$DOCS/agent-group/approvals.md" >"$TMP_DIR/orfie.md"
write_group_file kubernetes-remediator instructions.prepend.md "$TMP_DIR/orfie.md"
write_group_file kubernetes-remediator kubeconfig.gateway.yaml "$DOCS/kubeconfig.gateway.yaml"
sed '1,/^---$/d' "$DOCS/agent-group/.claude/agents/remediation-investigator.md" >"$TMP_DIR/investigator.md"
sed '1,/^---$/d' "$DOCS/agent-group/.claude/agents/remediation-verifier.md" >"$TMP_DIR/verifier.md"
write_group_file kubernetes-remediation-investigator instructions.prepend.md "$TMP_DIR/investigator.md"
write_group_file kubernetes-remediation-verifier instructions.prepend.md "$TMP_DIR/verifier.md"

DESTINATIONS=$(ncl destinations list --agent-group-id "$PRIMARY_ID" --json)
jq -e --arg n remediation-investigator '.[] | select(.local_name == $n)' <<<"$DESTINATIONS" >/dev/null \
  || ncl destinations add --agent-group-id "$PRIMARY_ID" --local-name remediation-investigator \
    --target-type agent --target-id "$INVESTIGATOR_ID" >/dev/null
jq -e --arg n remediation-verifier '.[] | select(.local_name == $n)' <<<"$DESTINATIONS" >/dev/null \
  || ncl destinations add --agent-group-id "$PRIMARY_ID" --local-name remediation-verifier \
    --target-type agent --target-id "$VERIFIER_ID" >/dev/null

USER_ID="matrix:$OWNER_MATRIX_ID"
ncl users create --id "$USER_ID" --kind matrix --display-name jopdorp >/dev/null
ncl members add --user "$USER_ID" --group "$PRIMARY_ID" >/dev/null
ROLES=$(ncl roles list --json)
jq -e --arg u "$USER_ID" --arg g "$PRIMARY_ID" '.[] | select(.user_id == $u and .role == "admin" and .agent_group_id == $g)' <<<"$ROLES" >/dev/null \
  || ncl roles grant --user "$USER_ID" --role admin --group "$PRIMARY_ID" >/dev/null
ncl messaging-groups create --channel-type matrix --platform-id "$ROOM_ID" --instance matrix \
  --name 'NanoClaw Kubernetes Remediation' --is-group 1 --unknown-sender-policy strict >/dev/null
ncl wirings create --channel-type matrix --platform-id "$ROOM_ID" --instance matrix \
  --agent-group-id "$PRIMARY_ID" --engage-mode pattern --engage-pattern '.' \
  --sender-scope known --ignored-message-policy drop --session-mode shared >/dev/null
ncl groups restart --id "$PRIMARY_ID" >/dev/null

step '6/6 create a harmless session and prove one Codex round-trip'
ROUND_TRIP=false
for SESSION_ID in $(ncl sessions list --agent-group-id "$PRIMARY_ID" --json | jq -r '.[].id'); do
  if ncl sessions history "$SESSION_ID" --limit 20 --json \
    | jq -e '.[] | select(.direction == "out" and ((.text // "") | contains("CODEX_PROVIDER_OK")))' >/dev/null; then
    ROUND_TRIP=true
    break
  fi
done
if [[ "$ROUND_TRIP" != true ]]; then
  ncl messaging-groups send --channel-type matrix --platform-id "$ROOM_ID" --instance matrix \
    --sender-id "$USER_ID" --sender jopdorp \
    --text 'Provider smoke test only. Do not inspect Kubernetes and do not invoke any remediation tool. Reply exactly CODEX_PROVIDER_OK.' >/dev/null
fi
for _ in $(seq 1 60); do
  [[ "$ROUND_TRIP" = true ]] && break
  SESSION_ID=$(ncl sessions list --agent-group-id "$PRIMARY_ID" --json \
    | jq -r 'sort_by(.created_at) | last | .id // empty')
  if [[ -n "$SESSION_ID" ]] && ncl sessions history "$SESSION_ID" --limit 20 --json \
    | jq -e '.[] | select(.direction == "out" and ((.text // "") | contains("CODEX_PROVIDER_OK")))' >/dev/null; then
    ROUND_TRIP=true
    break
  fi
  sleep 5
done
[[ "$ROUND_TRIP" = true ]] || fail 'Codex provider round-trip did not return CODEX_PROVIDER_OK within five minutes'

printf '\nSTOP: no remediation runtime config was created, no finding was triggered, and no target namespace was changed.\n'
printf 'Element: accept the invite to "%s", confirm the "bot online" message and the CODEX_PROVIDER_OK reply, and verify the sender is %s.\n' \
  'NanoClaw Kubernetes Remediation' "$BOT_MATRIX_ID"
printf '%s\n' 'Later, after explicitly enabling the reviewed remediation runtime, trigger the one safe test finding with:'
printf '%s\n' "kubectl --kubeconfig=$KUBECONFIG exec -n $NAMESPACE deploy/$ORCHESTRATOR -- sh -c 'curl -fsS -o /dev/null -w \"%{http_code}\\n\" -H \"Authorization: Bearer \$(cat /run/nanoclaw/falco/bearer)\" -H \"Content-Type: application/json\" --data '\"'\"'{\"time\":\"2026-10-21T00:00:00Z\",\"rule\":\"NanoClaw safe smoke test\",\"priority\":\"Notice\",\"output_fields\":{\"k8s.ns.name\":\"gitea\",\"k8s.pod.name\":\"nanoclaw-nonexistent-smoke-test\"}}'\"'\"' http://127.0.0.1:3000/webhook/kubernetes-falco'"
