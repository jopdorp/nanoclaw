# Provider routing verification

## Required shape

- Codex/Sol (`gpt-5.6-sol`) is the remediation orchestrator.
- DeepSeek handles bounded investigation and verification subagent work; Codex reviews every result and alone owns the final Matrix proposal.
- The orchestrator receives only OneCLI proxy configuration and Codex's non-secret sentinel `auth.json`. DeepSeek credentials remain gateway-managed; raw provider material never enters a pod.

`/add-codex` installs the primary provider. DeepSeek delegation stays disabled until its gateway route is proven through OneCLI; failure falls closed to Codex-only operation, never direct provider egress.

## One-time interactive login

OneCLI cannot manufacture the Codex subscription credential through NanoClaw's non-interactive connection API. Apply `provider-login-job.review.yaml`, then the user attaches a TTY.

Inside that disposable pod, `pnpm exec tsx setup/index.ts --step provider-auth codex` runs device pairing under a throwaway `CODEX_HOME`, imports `auth.json` into OneCLI, and deletes the temporary copy. The user opens the printed URL on their workstation; `kubectl port-forward service/onecli 10254:10254` provides the local OneCLI UI/API endpoint when required. Delete the Job immediately after the probe passes.

## Go-live proof

Run one no-tools Codex turn and one bounded DeepSeek delegation, then inspect the session pod: both must traverse `onecli.nanoclaw-remediator.svc:10255` and the pod must contain no raw token. Expire/revoke each route once and prove the gateway fails closed. Pinned OneCLI 1.42.0 requires manual ChatGPT reauthentication after expiry; automatic Codex refresh is unverified.
