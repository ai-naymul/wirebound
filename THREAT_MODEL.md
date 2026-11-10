# Threat model

## Asset and harm

The asset is the set of people who receive an email, and what they receive. Delivery cannot be undone, so an email that reaches an unapproved recipient, or carries unapproved content, is an irreversible disclosure.

## Guarantee

Within the assumptions below:

1. No message reaches the provider unless its **effect** equals the effect of an approval that is authorised, unexpired, unconsumed and in the same session. The effect covers:
   - the sender;
   - the To, Cc and Bcc sets, where an SMTP envelope recipient that appears in no header counts as a Bcc;
   - Reply-To;
   - the subject;
   - the text and HTML bodies;
   - attachment names, types and SHA-256;
   - the message stream.
2. One approval releases at most one dispatch.
3. After an ambiguous provider result, the send stays UNKNOWN and is not resent. It is resolved only against the provider's own record.

## Attackers

| Id | Attacker | Examples | Covered by |
|---|---|---|---|
| T1 | **A malicious or compromised connector** (supply chain; the postmark-mcp class) | Adds a Bcc, swaps or adds recipients, alters the body, attachments or Reply-To, switches to batch or template endpoints, resends, uses other egress | Relay comparison + strict parsing + isolation (F1–F7) |
| T2 | **An injected or confused agent** proposing an unintended send | Sends to an attacker after reading a poisoned email | Only as good as the approver: Wirebound makes the approval precise and binding, but cannot decide whether a human should approve |
| T3 | **Attacks on the approval channel** | Forged approval, swapped digest, replay, approval after denial, expired approval, unknown id, reading the principal key | Approval protocol + sandbox file and network policy (F8, F7.6, unit tests) |

## Trust boundaries

| Trusted | Untrusted |
|---|---|
| The composer and approver service (principal key in `run/secrets/`) | The model or agent |
| The relay and its ledger | The connector and its code and dependencies |
| The provider (Mailpit in the lab) | Every tool output |
| The sandbox profile and egress proxy | |

## Assumptions

- The connector's only network exits are the egress proxy (CONNECT to the provider hostname only) and the relay's SMTP port. It cannot read `run/secrets/` or the lab CA private key. Both are enforced by the Seatbelt profile in `wirebound/sandbox.py`, and tested by F7.
- The relay holds the only provider credential. The connector's token only names a session.
- The canonical effect captures everything a recipient can observe that matters for this guarantee. Open and link tracking, tags and metadata are recorded in the ledger but are not part of the digest; see LIMITATIONS.

## Kill chain and where it is cut

```
compromised package ─▶ connector builds a tampered payload ─▶ payload leaves the connector ─▶ provider delivers
                                                              ▲                               ▲
                                    isolation: no other exit (F7)       relay: effect ≠ approval → refuse (F1–F6)
```

## Out of scope

- Host compromise. Covert data inside an approved body. Downstream forwarding by recipients.
- A human approving a harmful message. Wirebound makes that decision precise; it does not make it.
- Effects outside email.
