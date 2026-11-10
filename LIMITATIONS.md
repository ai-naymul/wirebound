# Limitations

## What is implemented, tested and theoretical

| | Status |
|---|---|
| Postmark-compatible `/email` and `/email/batch`, enforced per message | Implemented, tested (protocol suite, real connector) |
| SMTP submission with envelope-derived Bcc | Implemented, tested with the mock connector (benign sends B21–B24, unit tests). **Not yet tested with a real third-party SMTP connector.** |
| Session-bound, digest-bound, single-use, expiring approvals | Implemented, tested (F8, unit tests, 16-way concurrency test) |
| UNKNOWN state with no resend after an ambiguous result | Implemented, tested with an injected fault (F6.5). Reconciliation against Mailpit by Message-ID is implemented; it is exercised manually, not by the suite. |
| Connector isolation | macOS Seatbelt (`sandbox-exec`) profile, tested by F7. Seatbelt is deprecated by Apple; on Linux, network namespaces or containers would play this role. |
| Template sends (`/email/withTemplate`, `/email/batchWithTemplates`) | **Refused.** The rendered content cannot be compared with an approval without rendering it in the relay. |
| Custom headers | **Refused** in v1. Routing headers (Bcc, Reply-To, …) are always refused. |
| Live LLM agents (GPT and Claude through their CLIs) | **Not yet run.** This is the next update to this repository. |
| Other providers (Resend, Mailgun) and other effect types (payments, HTTP APIs, Git) | Theoretical. The design generalises; the code is email-only. |

## Measurement caveats

- **The baselines use a permissive provider model.** In passthrough mode the relay behaves like a provider that does what it is asked: it reads keys case-insensitively, lets the last duplicate key win, and honours a Bcc in `Headers`. Some F4 baseline harms depend on that model. A real provider might reject some of those payloads itself. Real Postmark was not contacted.
- **Not preregistered.** The attack families and benign cases were written before the first measurement. After the first run, four things were fixed:
  1. Trailing CRLF normalisation for SMTP bodies, which caused 4 false blocks.
  2. Session binding of approvals. Without it, a resend could consume a leftover identical approval from an earlier case.
  3. The scorer, which ignored HTML and attachment hashes.
  4. A harness bug in F8.5.

  The tables are from the corrected code. The changes are in the commit history.
- **Small numbers.** 72 suite cases and 12 real-connector cases. Zero observed harms is a bounded result for these cases, not a proof for all inputs.
- **Lab CA.** In the lab the relay serves `api.postmarkapp.com`, and the connector trusts it through a lab CA. In a real deployment the relay would hold the real provider credential, and the connector would be pointed at it by configuration or by internal DNS.

## Things the relay deliberately does not judge

- Whether the approved message is a good idea.
- Covert content inside an approved body.
- Who the recipients forward it to.

Tracking settings (`TrackOpens`, `TrackLinks`), `Tag` and `Metadata` are recorded but are not part of the approval digest. The official connector always turns tracking on.
