# Kubernetes remediation review bundle

Nothing here is active. `home-k3s-rbac.yaml` and `admission-policy.yaml` are consumed unchanged from their owners. Activation requires the provider and remediation review patches, the separate `/add-k8s-driver` skill, and explicit human application of the runbook's manifests.

| Artifact                                                           | Purpose                                                                          |
| ------------------------------------------------------------------ | -------------------------------------------------------------------------------- |
| `agent-group/`, `agent-group-config.json`                          | Opus orchestrator, lane policy, and recovery caps                                |
| `codex-reviewer/`, `codex-reviewer-agent-group-config.json`        | Separate Codex review group reached through the existing agent-to-agent path     |
| `kubeconfig.gateway.yaml`, `gateway-config.yaml`                   | Credential-free kubeconfig and isolated OneCLI identities/secret references      |
| `in-cluster-runtime.review.yaml`                                   | Orchestrator Deployment, state PVC, session SAs/RBAC, Service, and egress policy |
| `onecli-in-cluster.review.yaml`, `provider-login-job.review.yaml`  | In-cluster gateway/database and disposable interactive-login Job                 |
| `session-admission-policy.review.yaml`                             | Job-creator guard supplementing restricted PSA                                   |
| `approval-controller-rbac.yaml`, `approval-controller-policy.yaml` | Separate annotation/binding identity plus approval-required and field guards     |
| `falcosidekick-values.review.yaml`                                 | Authenticated webhook values shape; bearer remains a runtime secret              |
| `trust-boundary.md`                                                | Exact annotation, token, approval, replay, and Lane C boundary                   |
| `DEPLOY-RUNBOOK.md`                                                | Ordered human deployment and safe smoke test                                     |
| `MODEL-ROUTING.md`                                                 | Verified SDK/gateway capability result and launch blocker                        |
| `enable-*-review.patch`                                            | Explicit provider and remediation activation gates                               |

Bot code lives in `src/modules/kubernetes-remediation/`, `src/{providers,provider-contracts}/claude-remediation.review.ts`, and the corresponding `container/agent-runner/src/` review files. The generic session driver lives separately in `.claude/skills/add-k8s-driver/`. The shared raw webhook server is reused through `src/webhook-server.ts:107`; Matrix clicks use `src/modules/approvals/primitive.ts:237` and `src/modules/approvals/response-handler.ts:60`.

Launch is blocked until digest-pinned in-cluster images exist, `/add-codex` is applied, OneCLI 1.42.0 is proven to run non-root, both interactive subscription logins pass, and TokenRequest refresh replaces smoke-test target-cluster tokens. See `MODEL-ROUTING.md` and `DEPLOY-RUNBOOK.md`.
