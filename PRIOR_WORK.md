# Prior work, and what is new here

Most of Wirebound is known engineering, and we credit it. The new part is narrow.

## What is new

A request-time human approval, frozen as a digest, is enforced against the **wire output of an untrusted, unmodified third-party connector**. The enforcement point is a relay that holds the only provider credentials and parses HTTPS email API traffic and SMTP: envelope recipients including a hidden Bcc, a content digest, and attachment hashes. Ambiguous provider results fold into the same protocol as UNKNOWN, with no resend. It is evaluated on a replay of a real malicious connector (postmark-mcp, 2025) and on the real official connector, unmodified.

## The closest work

| Work | What it binds or checks | Relation |
|---|---|---|
| CTA / CommitGate, arXiv [2607.10487](https://arxiv.org/abs/2607.10487) | The protected sink checks that the sink request equals the licensed effect `(effect id, target, operation, payload digest)`; single-use, expiring grants; Lean proofs | **The most general formal statement of the same idea.** Wirebound is effectively such a sink for email, in front of a third-party provider, with a credential-holding relay and ambiguous-ack handling, which CTA lists as out of scope |
| ASU, arXiv [2610.21063](https://arxiv.org/abs/2610.21063) | A passkey signs a canonical effect descriptor; the gateway holds the executor credentials and executes the descriptor itself | It removes the untrusted tool. Wirebound keeps the third-party connector and mediates its traffic |
| Microsoft Agent Governance Toolkit, [ADR-0030](https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/adr/0030-action-bound-approval-protocol.md) | An RFC 8785 SHA-256 digest of operation, agent, target and parameters, rechecked just before execution | Request binding. Nothing checks what the tool emits afterwards, which is the gap the real-connector table shows |
| Nuvrail ([agens-field/nuvrail](https://github.com/agens-field/nuvrail)) | An SMTP proxy that holds credentials and stages mail for human approval | Approves the staged message itself. SMTP only; no digest-bound prior approval, expiry or UNKNOWN state |
| EffectGate ([Miniks040506/EffectGate](https://github.com/Miniks040506/EffectGate)) | An MCP proxy with an intent digest; "verify, don't retry" | Prior art for the UNKNOWN state, at the MCP layer rather than at egress |
| Google AP2; Auth0 CIBA + RAR | Signed mandates or `authorization_details`, verified by the counterparty or resource server | Effect binding works when the counterparty takes part. Email providers don't, so the relay stands in for them |
| Approval laundering, arXiv [2609.28586](https://arxiv.org/abs/2609.28586) | The approval names an invocation but not its transitive effects; the fix is a source-backed prediction of those effects | The same problem. Wirebound mediates the effect instead of predicting it |
| MCP confirmation measurement, arXiv [2611.02527](https://arxiv.org/abs/2611.02527) | About 90% of destructive MCP tools have no server-side confirmation; 32 of 41 hosts have no default approval | Motivation |
| Pipelock ([pipelab-org/pipelock](https://github.com/pipelab-org/pipelock)) | Egress proxy, TLS interception, DLP, signed receipts | Same plumbing; scans for patterns instead of comparing with an approval |
| Exchange / Purview DLP | Outgoing rules on To, Cc and Bcc, content and attachments; "forward the message for approval" | Moderation of outgoing mail is long established. What is missing is binding to one specific prior approval of one agent request |

## Classical principles

- **Anderson (1972), the reference monitor:** always invoked, tamper-proof, verifiable.
- **Saltzer and Schroeder (1975):** complete mediation, fail-safe defaults, least privilege.
- **Landrock and Pedersen (1998), "WYSIWYS? — What you see is what you sign?":** what is approved must equal what is executed.
- **Weigold et al., ZTIC (TRUST 2008):** a trusted device terminates the TLS connection, parses the critical fields and asks the user to approve them. Wirebound mirrors this from the server side.
- **A. Gutmann (UCL PhD, 2020):** the secure creation and verification of user instructions.

## Incident sources

- [Snyk blog](https://snyk.io/blog/malicious-mcp-server-on-npm-postmark-mcp-harvests-emails/) and [advisory SNYK-JS-POSTMARKMCP-13052679](https://security.snyk.io/vuln/SNYK-JS-POSTMARKMCP-13052679)
- [OSV MAL-2025-47604](https://osv.dev/vulnerability/MAL-2025-47604)
- [Postmark's notice](https://postmarkapp.com/blog/information-regarding-malicious-postmark-mcp-package)
- Koi Security's original report
