# Reference contracts for the existing NTLM builder

This is test coverage within the approved Go-reference initiative. It changes no
authentication source, provider global, dependency, collector default or graph.
The owner subsequently approved the per-login EPA isolation fix. Its source
changes and later checks are recorded in
[the isolation record](2026-10-29-ntlm-probe-isolation.md).

`tests/test_ntlm_reference_contracts.py` verifies the pinned Go/MS-NLMP NTOWFv2
and NT proof vectors through impacket 0.13.1, which supplies these primitives to
the shared builder. It checks session-key length and deterministic integrity
calculation. It also calls the actual common builder to verify transmitted MIC,
negotiate/authenticate message types, service and channel-binding fields, and
UTF-16 account/domain values with their case preserved.

The synthetic server challenge follows the Go minimal challenge, with the DNS
field required by impacket's service-binding support. Tests advertise the same
Windows version as the actual SQL login. They parse the returned authenticate
message and independently calculate its MIC over the final wire fields. No
target is contacted and no tokens are saved. Fixed public text/password examples
are reference data, not actual credentials.

The channel-binding coverage calls the actual SQL `tls-unique` helper; existing
LDAP tests independently check `tls-server-end-point` against a real local test
certificate. This verifies the two reference formats without claiming SQL TLS
1.3 support: SQL retains its documented TLS 1.2 boundary. Crypto remains in the
existing provider. Reimplementing authentication or testing only fake messages
would add maintenance or leave the real integration boundary unverified.

The first six NTLM checks and eight LDAP framing/binding checks passed together
(14 tests), with Ruff clean. UTF-16 examples were then expanded to retain the
reference's public strings and uppercase/lowercase distinction; the later
checkpoint passed all 17 NTLM/LDAP checks with Ruff clean; its actual evidence is
`.tmp/q29-mapped-common-results.xml`. SQL's execution auditor verified the mapped
common selectors alongside the collector's separate report. Complete case-accounting and
credential/proxy/live-profile acceptance remain unfinished.

Run in the declared common environment with a fresh short Windows pytest path:

```powershell
uv run pytest tests/test_ntlm_reference_contracts.py tests/test_ldap_kerberos.py -q --junitxml=.\verification\ntlm-results.xml
```

SQL's `function-mappings.json` points to these common test selectors explicitly.
Their existence is not treated as execution: complete reference acceptance needs
the common result report as well as the collector's report. Normal users need
no changed command or new permission for this test-only work.

Suggested owner commit after reviewing the new test data and source mappings:

```powershell
git add tests/test_ntlm_reference_contracts.py docs/changes/2026-10-29-ntlm-reference-contracts.md
git commit -m "Verify shared NTLM messages against pinned reference contracts"
```

No staging, commits, pushes or publication were performed.
