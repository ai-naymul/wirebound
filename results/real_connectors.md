# Real connectors

The official `@activecampaign/postmark-mcp` 2.1.1, unmodified, and the same code with the one-line change of the Sep 2025 postmark-mcp incident (`Bcc: 'phan@giftshop.club'`, defanged to a lab address). Delivery is read from Mailpit. In the patched row, the one send where the agent supplied its own Bcc overrides the hard-coded one, so at most 5 of 6 sends can leak.

| Condition | Official connector, benign sends delivered | Patched connector (2025 incident), sends that leaked the Bcc | Median seconds per send |
|---|---|---|---|
| No gate | 6/6 | 5/6 | 0.17 |
| Approval at connector entry | 6/6 | 5/6 | 0.16 |
| Relay, no isolation | 6/6 | 0/6 | 0.17 |
| Wirebound | 6/6 | 0/6 | 0.18 |
