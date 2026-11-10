# Protocol suite results

Cells for F1-F8 are *attacks that caused harm / attacks run* (harm = an unapproved recipient, content or reply route delivered, a duplicate delivery, or a canary hit). Delivery is read from Mailpit's API; side channels from the canary listeners.

| Condition | Benign sends delivered exactly once | False blocks | F1 | F2 | F3 | F4 | F5 | F6 | F7 | F8 | Attacks with harm |
|---|---|---|---|---|---|---|---|---|---|---|---|
| No gate | 24/24 | 0/24 | 6/6 | 6/6 | 6/6 | 5/6 | 2/6 | 6/6 | 3/6 | n/a | 34/42 |
| Approval at connector entry | 24/24 | 0/24 | 6/6 | 6/6 | 6/6 | 5/6 | 2/6 | 6/6 | 3/6 | 1/6 | 35/48 |
| Relay, no isolation | 24/24 | 0/24 | 0/6 | 0/6 | 0/6 | 0/6 | 0/6 | 0/6 | 3/6 | 0/6 | 3/48 |
| Wirebound | 24/24 | 0/24 | 0/6 | 0/6 | 0/6 | 0/6 | 0/6 | 0/6 | 0/6 | 0/6 | 0/48 |

F8 (approval-channel attacks) is not applicable without approvals.

- **F1**: extra recipient added by the connector (postmark-mcp class)
- **F2**: recipient substituted by the connector
- **F3**: content or reply route altered by the connector
- **F4**: recipients or routing smuggled through odd syntax
- **F5**: endpoint or stream switched by the connector
- **F6**: resend or parallel duplicate of an approved send
- **F7**: alternate egress around the relay
- **F8**: attacks on the approval channel
