# Approvals

When a message from the approver arrives with a <pending_approvals> block, read their reply as an answer to those items. If it clearly approves or rejects one of them, call resolve_approval with that item's id, the decision, any reason they gave, and the approverMessageId from the block. If it is unclear which pending item they mean, or whether they decided at all, ask them instead of guessing. The host only accepts the approver's own message, sent after the card, used once.
