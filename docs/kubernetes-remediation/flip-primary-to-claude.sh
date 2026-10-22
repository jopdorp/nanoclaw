#!/bin/sh
# Moves Orfie's primary onto Claude Opus (subscription) through the OneCLI gateway.
# Reads the `claude setup-token` value on stdin, so it never lands in argv or on disk outside the pod's tmp.
#   claude setup-token        # on the workstation, copy the sk-ant-oat01-... it prints
#   docs/kubernetes-remediation/flip-primary-to-claude.sh   # paste it, then Ctrl-D
# Rollback: ncl groups config update --id ag-4be55056-f0a3-4991-a83e-a347b75de07d --provider codex --model gpt-5.6-sol, then ncl groups restart.
set -eu
group=ag-4be55056-f0a3-4991-a83e-a347b75de07d
onecli_agent=97cdad24-6fef-4269-a360-a2e9849863cd
kubernetes_reader=e76e2899-a0ea-4118-a832-ca39af949079
codex=308af5a2-a898-4e9b-bf88-37f470f32207

kubectl -n nanoclaw-remediator exec -i deploy/nanoclaw-remediator-orchestrator -c orchestrator -- sh -euc '
f=$(mktemp); trap "rm -f $f" EXIT
tr -d "[:space:]" > "$f"
grep -q "^sk-ant-oat" "$f" || { echo "not a claude setup-token" >&2; exit 1; }
onecli secrets create --name "Claude subscription" --type anthropic --file "$f" --host-pattern api.anthropic.com >/dev/null
claude=$(onecli secrets list --fields id,name | node -e "let s=\"\";process.stdin.on(\"data\",d=>s+=d).on(\"end\",()=>console.log(JSON.parse(s).find(x=>x.name===\"Claude subscription\").id))")
# Never hand the primary the DeepSeek secret: OneCLI picks one anthropic-type secret per agent.
onecli agents set-secrets --id '"$onecli_agent"' --secret-ids '"$kubernetes_reader,$codex"',$claude >/dev/null
ncl() { env HOME=/tmp node_modules/.bin/tsx src/cli/client.ts "$@"; }
ncl groups config update --id '"$group"' --provider claude --model opus --effort high >/dev/null
ncl groups restart --id '"$group"'
'
