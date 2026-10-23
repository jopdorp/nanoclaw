# Remediation trust boundary

The agent container has a credential-free kubeconfig and the OneCLI identity matching its agent-group ID. OneCLI holds the `nanoclaw-remediator` TokenRequest token and injects it only at `kubernetes.default.svc:443`; four agent-scoped block rules deny `POST`, `PUT`, `PATCH`, and `DELETE`. Editing the kubeconfig cannot move the token to another host. The agent can read and can emit only a typed proposal system action.

The same gateway boundary holds the user's Claude subscription and Codex/ChatGPT credentials. Claude receives only `ANTHROPIC_AUTH_TOKEN=gateway-managed`; Codex receives only its sentinel auth stub. They run as separate agent groups through one in-cluster OneCLI Service, so no cross-provider model routing occurs inside a Claude SDK session. This path stays disabled until `MODEL-ROUTING.md`'s two interactive-login probes pass.

The existing NanoClaw approvals module owns the Matrix card. It binds the card to one namespaced Matrix user, atomically claims the pending row, and invokes the remediation handler once. The handler reparses the closed schema, checks the canonical SHA-256, expiry, UID, resourceVersion, lane, image repository/digest, and recovery cap.

Only the orchestrator Deployment has the `nanoclaw-remediation-executor` and `nanoclaw-remediation-annotator` OneCLI identities. The executor receives the remediator SA token at the gateway and performs the approved patch/delete. The annotator receives a different SA token and may set/remove `remediation.nanoclaw.io/approval-id` and create/remove only the temporary reviewed storage-delete binding. `approval-controller-policy.yaml` field-restricts this identity and makes the annotation mandatory for every remediator workload write. Neither identity, token, nor Falco bearer is mounted in a session pod.

The agent is unable to set the approval annotation three independent ways: its OneCLI identity blocks every mutating HTTP method; its RBAC has no PV/PVC patch and the base admission policy rejects workload-object annotation changes by the remediator SA; and the annotation method exists only on the host-side annotator client. The annotation is added after target revalidation for every non-Lane-C write, the resulting resourceVersion is used for the apply, and it is removed in `finally`. A storage delete also gets a plan-named temporary binding which is removed in `finally`.

An approved Lane C plan is applied by the host with the separate `nanoclaw-breakglass` identity, which no agent holds, with zero automatic recovery. Lane A recovery is an orchestrator state machine, not an agent loop: same UID only, ten-minute/plan deadline, and at most the operation-specific cap already shown on the approval card.

Files remain inert because no review file is imported by a live barrel. The provider-only activation patch carries no remediation runtime; the second patch activates the MCP proposal tool and host module only after the later runbook gate.

On every orchestrator start, the annotator first removes all plan-named temporary bindings and all stale approval annotations. Any reconciliation failure aborts module startup before triggers and approvals are registered.
