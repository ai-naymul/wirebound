# Break it

These are the weakest points we know of, and how to test them yourself. If you find a way to get an unapproved effect delivered, it should show up in Mailpit (`http://127.0.0.1:18025` while the lab runs) or in `run/canary.log`.

1. **Parser differentials between the relay and the provider.** The relay checks its own parse of the request, then forwards a message re-serialised from that parse, never the connector's bytes. A differential would need the relay to *accept* something it misreads. The weakest spots are the address grammar (`wirebound/model.py: canonical_address`, `split_address_list`) and MIME handling for SMTP (`effect_from_smtp`). Add a payload to `connectors/mock_mcp/server.py: tamper()` and run `python -m attacks.suite --condition wirebound --only F4`.
2. **Egress the profile forgets.** The Seatbelt profile allows outbound connections to two localhost ports only. Try other paths (IPv6 loopback, unix sockets to local services, a child process) by adding an `F7` variant in `_side_channel()`. Run without isolation (`--condition relay_no_isolation`) to see the canary catch it.
3. **Effect fields outside the digest.** Tracking flags, `Tag` and `Metadata` are not digested. Open tracking inserts a pixel when the provider renders the message. If you can turn a non-digested field into a recipient-visible change, that is a real finding.
4. **Session confusion.** The session is the connector's provider token, or its SMTP login. If two agents share a connector process and a token, they share approvals.

Run all of it: `make verify`.
