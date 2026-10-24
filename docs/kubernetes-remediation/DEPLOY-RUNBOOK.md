# HOME k3s in-cluster remediation bot deploy runbook

Nothing in this bundle has been applied. Commands target HOME only. Stop at every failed checkpoint; never substitute a host Docker socket, DinD, a raw provider credential in a pod, or a long-lived admin kubeconfig.

## 1. [operator=me] Pin HOME and review the inert Approach 1 bundle

```bash
cd /home/jopdorp/development/nanoclaw-v2
export KUBECONFIG=/home/jopdorp/.kube/mini-pc.public
test "$(kubectl config current-context)" = default
test "$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')" = https://k8s.jegor.nl:6447
git apply --check docs/kubernetes-remediation/enable-provider-review.patch
git apply --check docs/kubernetes-remediation/enable-remediation-review.patch
test -f .claude/skills/add-k8s-driver/SKILL.md
pnpm exec vitest run src/drivers/conformance.test.ts --config .claude/skills/add-k8s-driver/conformance.vitest.ts
pnpm exec vitest run src/modules/kubernetes-remediation
pnpm run typecheck
```

Checkpoint: `home-k3s-rbac.yaml` and `admission-policy.yaml` are unchanged. Review the three new in-cluster manifests, supplemental session admission policy, images, and `MODEL-ROUTING.md`.

## 2. [operator=me] Produce immutable images; install Codex before building

The in-tree `/add-codex` and `/add-k8s-driver` payloads are installed. The session image is `registry.prophet.jopdorp.nl/nanoclaw/remediation-agent@sha256:4b97fd92ab66bf34f933e7b6e2f09036bc14c30341c39a2a62b6be86715a6de9`; the host/login image is `registry.prophet.jopdorp.nl/nanoclaw/remediation-host@sha256:bf19fbf5b353451d44dab74c38ea01b6c658b10049d1a07b73efabbf5657df2d`. OneCLI 1.42.0 and Postgres 18 Alpine are pinned in their manifest by digest.

Checkpoint: `rg 'registry.invalid|sha256:0{64}|:[^ @]+$' docs/kubernetes-remediation/*in-cluster*.yaml docs/kubernetes-remediation/provider-login-job.review.yaml` returns nothing. Prove the OneCLI and Postgres images start as the manifest UIDs under restricted PSA in disposable k3s; this is unverified on HOME.

## 3. [operator=me] Validate, then apply namespace/RBAC/admission

```bash
for F in home-k3s-rbac.yaml approval-controller-rbac.yaml admission-policy.yaml approval-controller-policy.yaml session-admission-policy.review.yaml in-cluster-runtime.review.yaml onecli-in-cluster.review.yaml provider-login-job.review.yaml; do kubectl apply --dry-run=client --validate=false -f "docs/kubernetes-remediation/$F" >/dev/null || exit; done
kubectl diff -f docs/kubernetes-remediation/home-k3s-rbac.yaml
kubectl apply -f docs/kubernetes-remediation/home-k3s-rbac.yaml
kubectl apply -f docs/kubernetes-remediation/approval-controller-rbac.yaml
kubectl apply --server-side -f docs/kubernetes-remediation/admission-policy.yaml
kubectl apply --server-side -f docs/kubernetes-remediation/approval-controller-policy.yaml
kubectl apply --server-side -f docs/kubernetes-remediation/session-admission-policy.review.yaml
```

Checkpoint: rerun the existing adversarial CEL/RBAC suite on disposable k3s first. HOME is not the policy test cluster.

## 4. [operator=me] Create runtime Secrets and start only OneCLI

Create a write deploy key on Gitea's `cluster/k8s.jegor.nl` from a fresh `ssh-keygen -t ed25519 -N '' -f id_ed25519`, then pin Gitea's host key with `ssh-keyscan -p 2222 gitea-ssh.gitea.svc.cluster.local > known_hosts` from a pod, checked against `/data/ssh/gitea.rsa.pub` in the gitea pod.
TODO: push-mirror `cluster/k8s.jegor.nl` to `github.com/jopdorp/k8s.jegor.nl` once there is a GitHub PAT for it.
Store both as `kubectl create secret generic -n nanoclaw-remediator orfie-git-deploy-key --from-file=id_ed25519 --from-file=known_hosts`, and shred the local files.
The orchestrator mounts it read-only at `/run/nanoclaw/git` for the Helm path's `git push`; without it helm-values plans fail before any upgrade.

Create `onecli-runtime` with strong `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`, `DATABASE_URL`, `NEXTAUTH_SECRET`, and `SECRET_ENCRYPTION_KEY`. Create `nanoclaw-runtime` with `onecli-api-key`, `matrix-access-token`, `falco-webhook-bearer`, and `alert-webhook-bearer`. `nanoclaw-dotenv`'s `.env` carries the `MATRIX_*` keys plus `EMAIL_INSTANCES=claw,orfie,dmarc` and per mailbox `EMAIL_<NAME>_{ADDRESS,PASSWORD,IMAP_HOST,IMAP_PORT,SMTP_HOST,SMTP_PORT}` (claw from `hermes/hermes-secrets`, orfie's password is the one its mailbox was created with; dmarc gets no SMTP keys, so it stays read-only, and its password is `mail/mail-dmarc`); use private temporary files or stdin, not shell arguments, and delete the inputs. Then:

```bash
kubectl apply -f docs/kubernetes-remediation/onecli-in-cluster.review.yaml
kubectl rollout status -n nanoclaw-remediator deploy/onecli-postgres
kubectl rollout status -n nanoclaw-remediator deploy/onecli
kubectl port-forward -n nanoclaw-remediator service/onecli 10254:10254 10255:10255
```

Checkpoint: `http://127.0.0.1:10254/v1/health` is healthy through the port-forward; no Ingress, LoadBalancer, NodePort, host port, or Docker socket exists.

## 5. [user] Perform the two one-time interactive provider logins

The operator applies the disposable Job and waits; the user owns both terminal/browser handoffs:

```bash
kubectl apply -f docs/kubernetes-remediation/provider-login-job.review.yaml
kubectl wait -n nanoclaw-remediator --for=condition=Ready pod -l job-name=nanoclaw-provider-login --timeout=120s
kubectl exec -it -n nanoclaw-remediator job/nanoclaw-provider-login -- onecli config set api-host http://onecli.nanoclaw-remediator.svc:10254
kubectl exec -it -n nanoclaw-remediator job/nanoclaw-provider-login -- bash .claude/skills/add-onecli/scripts/register-claude-token.sh
kubectl exec -it -n nanoclaw-remediator job/nanoclaw-provider-login -- pnpm exec tsx setup/index.ts --step provider-auth codex
kubectl delete -n nanoclaw-remediator job/nanoclaw-provider-login
```

For Claude, open the printed `claude setup-token` URL on the workstation. For Codex choose device pairing, open the printed URL, and enter its code. Each script writes directly to OneCLI, then deletes its pod-local capture/throwaway `CODEX_HOME`; never paste either credential into a Kubernetes Secret. Checkpoint: OneCLI lists `Anthropic` and `Codex`, and the setup Job is gone. Pinned OneCLI needs manual Codex re-login after expiry.

## 6. [operator=me] Create isolated gateway identities and smoke-only Kubernetes grants

From the disposable setup Job or a workstation CLI pointed through the port-forward, create/reuse the remediator group, Codex reviewer, executor, and annotator OneCLI agents; use selective secret mode. Assign Anthropic plus the read-only Kubernetes credential only to the orchestrator group, Codex only to the reviewer, the remediator credential to the executor, and the approver credential to the annotator. Retain the existing agent-side POST/PUT/PATCH/DELETE block rules.

For a bounded smoke test only, import one-hour `kubectl create token` results for `nanoclaw-remediator` and `nanoclaw-remediation-approver`. Do not start production until a reviewed refresher rotates TokenRequest credentials inside OneCLI without exposing them to session pods; OneCLI 1.42.0 does not provide that integration here.

## 7. [operator=me] Activate review code, start the orchestrator, and create groups

Apply `/add-k8s-driver`, then activate the bot-specific review code:

```bash
git apply docs/kubernetes-remediation/enable-provider-review.patch
git apply docs/kubernetes-remediation/enable-remediation-review.patch
pnpm run typecheck && pnpm run build
kubectl apply -f docs/kubernetes-remediation/in-cluster-runtime.review.yaml
kubectl rollout status -n nanoclaw-remediator deploy/nanoclaw-remediator-orchestrator
kubectl exec -n nanoclaw-remediator deploy/nanoclaw-remediator-orchestrator -- pnpm ncl groups create --folder kubernetes-remediator --name 'Kubernetes Remediator'
kubectl exec -n nanoclaw-remediator deploy/nanoclaw-remediator-orchestrator -- pnpm ncl groups create --folder kubernetes-remediation-reviewer --name 'Kubernetes Remediation Reviewer'
```

Install the reviewed `CLAUDE.md`, settings/agent files, reviewer `AGENTS.md`, and credential-free kubeconfig into their PVC-backed group folders. Set the first group to `claude-remediation`/Opus/high and the second to `codex`/high; add an agent destination named `codex-reviewer` from orchestrator group ID to reviewer group ID with `pnpm ncl destinations add --agent-group-id ... --local-name codex-reviewer --target-type agent --target-id ...`.

Render `data/kubernetes-remediation.json` from `gateway-config.yaml` using the real orchestrator group ID, approver Matrix ID, executor/annotator OneCLI identifiers, HOME API URL, and `/run/nanoclaw/falco/bearer`; copy it into the PVC-backed data directory and restart the Deployment. Until that file exists, the review module logs that remediation is disabled and registers no triggers or approvals.

Checkpoint: a wake creates one suspended Job, `start()` unsuspends it, and completion/deletion leaves no pod. The pod uses `nanoclaw-session`, has no token mount, runs non-root with RuntimeDefault seccomp, drops all capabilities, uses only PVC subpaths/emptyDir, and can egress only DNS plus OneCLI.

## 8. [operator=me] Adapt Matrix, Trivy, and Falco to Services

Create the existing non-admin Matrix bot on `matrix-synapse.openclaw-private.svc:8008`, keep the one-user approval mapping, and point NanoClaw at that ClusterIP Service. Trivy watchers already use the in-cluster orchestrator path through OneCLI; preserve watch bookmarks, 410 re-list, and UID/resourceVersion dedupe. Apply the pinned Falcosidekick values only after diffing its existing SMTP settings: its authenticated webhook is now `http://nanoclaw-remediator.nanoclaw-remediator.svc:3000/webhook/kubernetes-falco`.

Checkpoint: unauthenticated Falco POST is `401`, malformed is `400`, oversized is `413`, authenticated smoke is `202`; Trivy list/watch reaches both report APIs. No external reverse proxy or ingress is added.

## 9. [operator=me] Prove provider isolation and Matrix approval-to-apply

Run one no-tools turn in each group. Confirm Claude reports Opus, Codex reports its selected model, both proxy through OneCLI, and neither session pod contains a real token. Then run the existing approve, reject, expiry, replay, wrong-user, target-drift, and restart-orphan tests against a low-risk Lane A no-op plan. The annotator adds/removes the approval annotation; the executor alone applies; the agent only proposes.

## 10. [operator=me] Production gate

Do not leave the Deployment running until immutable images, non-root OneCLI, Codex provider wiring, both interactive logins, provider expiry behavior, TokenRequest refresh, Matrix E2E/account recovery, Falco header serialization, restart cleanup, approval replay/drift tests, and Longhorn backup/restore of NanoClaw plus OneCLI/Postgres all pass. Keep `home-k3s-rbac.yaml` and `admission-policy.yaml` owned by their original reviewers.

## 11. [operator=me] Shared memory

Orfie and its helpers reach `shared-mind` (k8s.jegor.nl `kubernetes/nanoclaw-remediator/{qdrant,embedder}.yaml`) through the stdio bridge `phase2-deploy.sh` adds to each group. The image is `shared-mind.Dockerfile` built over a qmem checkout at the commit Fable's local qmem runs, and the base EmbeddingGemma weights are copied once from `~/.local/share/qmem/embeddinggemma` to `/data/embeddinggemma` on the `qmem-encoder` PVC, so embeddings match Fable's copy exactly. Seed and sync it with `qmem sync`.

## 12. [operator=me] Self-upgrade from main

`self-upgrade.yaml` deploys the host from Gitea `cluster/orfie` main inside the cluster, in `orfie-ci`, which the host's identities cannot write to. Every five minutes `orfie-ci-poll` compares main with `deployed_sha` in ConfigMap `orfie-ci-state`, builds the agent and host images with kaniko (the host build runs the module tests), and `orfie-ci-deploy` patches only the image digests, waits for Ready and otherwise rolls back to `previous_*` and adds the sha to `bad_shas`. Both outcomes post one line to the DM room as `@orfie-ci`.

One-time secrets, then `kubectl apply -f self-upgrade.yaml`: `gitea-repo-read` (copy of `security/gitea-repo-read`), `orfie-ci-registry-push` (copy of `security/gitea-registry-push`), `orfie-ci-matrix` (keys `token`, `password` of `@orfie-ci`, registered like step 2 of `phase2-deploy.sh` and invited into the DM room).

Roll back by hand from the recorded digests, through the same guarded Job:

```bash
kubectl -n orfie-ci get configmap orfie-ci-state -o yaml
kubectl -n orfie-ci create job manual-roll --from=cronjob/orfie-ci-deploy --dry-run=client -o yaml \
  | kubectl set env --local -f - -o yaml GIT_COMMIT=<sha> SUBJECT='a manual rollback' \
      HOST_IMAGE=<previous_host_digest> AGENT_IMAGE=<previous_agent_digest> \
  | kubectl -n orfie-ci create -f -
```

If that Job cannot run, patch the same three images and `CONTAINER_IMAGE` on `deploy/nanoclaw-remediator-orchestrator` with admin credentials. Retry a bad sha by removing it from `bad_shas`. Suspend `cronjob/orfie-ci-poll` before deploying an unpushed tree with `phase2-deploy.sh`, or the next poll puts main back.
