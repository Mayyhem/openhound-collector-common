# Keep the EPA probe inside its own login

The owner approved [the proposal](2026-10-29-ntlm-probe-isolation-proposal.md)
on October 29, 2026. This change is implemented locally; it is not a published
release or completion of the larger SQL initiative.

## Problem and selected solution

The missing-service EPA probe previously changed impacket's process-wide
`TEST_CASE` flag. An ordinary login overlapping that probe could lose its own
service name, and restoring overlapping saved values could leave the flag on.
The deterministic offline proof reproduced both outcomes without a network
connection. Locking this helper alone would not protect WMI, HTTP or other
direct provider callers. A child process is unnecessary for editing an owned
message and conflicts with the owner's selected in-process approach.

[`clients/mssql.py::login_epa`](../../src/openhound_collector_common/clients/mssql.py)
now passes `omit_target_service` to
[`clients/auth.py::ntlm_type3`](../../src/openhound_collector_common/clients/auth.py).
It never reads, changes or restores the global test flag. Ordinary calls use
the existing provider message unchanged before the existing integrity-check
step. Only the special probe edits its own message.

The provider first makes its normal NTLMv2 response. The adapter reads its
16-byte proof, 28-byte client-challenge header and following named fields.
It rejects an unexpected layout instead of silently dropping unknown bytes.
It removes only the target-service field. The timestamp, random client challenge,
channel binding, server names and other fields stay intact, including fields
the collector does not interpret. This also avoids the old test flag's unrelated
zero-timestamp behavior.

Impacket's existing NTOWFv2/HMAC functions calculate the new proof and session
base key. With negotiated key exchange, its existing session-key function
encrypts the original random exported key with the new base key. Without key
exchange, the new base key is the exported key. Common calculates the message
integrity check last over the final negotiate, server challenge and authenticate
messages. No cryptographic primitive, authentication stack, provider source
change or process was introduced.

The boundary was checked against
[impacket 0.13.1](https://github.com/fortra/impacket/blob/impacket_0_13_1/impacket/ntlm.py)
and Microsoft's
[client-challenge layout](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/aee311d6-21a7-4470-92a5-c4ecb022a87b).
There are no new dependencies. Both MSSQL and CMBP use this helper; adopt the
fix in both through the already planned reviewed common release. There are no
new collector options, defaults, schemas or graph rules. Published dependency
floors remain unchanged until the owner publishes an actual release.

The required hash-form check also exposed an existing provider-input mismatch:
the NTLM call received hexadecimal text instead of bytes. The owner separately
approved [the bounded conversion](2026-10-29-ntlm-hash-input-proposal.md).
`ntlm_type3` now decodes its LM/NT values immediately before the provider call.
It retains the provider's empty-string password sentinel, rejects malformed
hexadecimal input and wrong hash lengths without printing the supplied value,
and rejects a missing NT portion. The shared `split_hashes` function and its
Kerberos callers still receive text. Moving this conversion into that shared
splitter was rejected because those other callers use a different contract.

## Verification

`tests/test_ntlm_reference_contracts.py` now exercises the real EPA login and
provider with an offline transport. Events force the previously failing overlap,
including a provider exception. An unrelated direct provider login and an
ordinary SQL login keep their service name, and the global remains unchanged.
A pre-existing enabled provider test setting is also left unchanged.

Message checks cover key exchange on/off, server timestamp present/absent,
channel binding present/absent, preservation of opaque fields and the original
client nonce, independently calculated proof/session keys/MIC, and encrypted
session-key recovery. Ordinary messages match the unmodified provider byte for
byte under controlled test randomness. Anonymous non-NTLMv2 results and unknown
provider trailers fail visibly. No authentication packets are saved.

At this boundary, common passed **522 tests**, with one expected Python-version
skip; Ruff and mypy passed (64 source files). MSSQL's affected worker/network/
method and complete reference selection passed **623 tests**. CMBP's EPA, HTTP
auth, AD credential and WMI selection passed **46 tests**. Actual JUnit evidence
is in the private `.tmp/q29-ntlm-{common,sql,sccm}-results.xml` files.

Read-only lab checks in both collector environments passed on
`ps1-db.mayyhem.com:1433`: a known-account password baseline, a missing-service
login overlapping an ordinary `SELECT 1`, and an unchanged provider global.
CMBP's actual adapter still returned EPA `Off`. DNS destinations were checked
against the authorized lab subnets before authentication. No server settings,
accounts or services changed. Safe reports are `ntlm-isolation-sql-lab.json` and
`ntlm-isolation-sccm-lab.json` in the private feature task folder.

After the additional hash-input approval and fix, the full common suite passed
**535 tests** with the same expected Python-version skip; Ruff and mypy remained
clean. New tests compare both bare NT and LM:NT messages with equivalent password
messages, with/without service binding and key exchange. The bytes and keys match
exactly under controlled randomness. Invalid-input errors and logs do not reveal
the supplied text, and the Kerberos-facing splitter still returns text.
The affected SQL command/worker/network selection passed **26 tests**, and the
same **46 CMBP tests** passed after this final code change. Later evidence is
`.tmp/q29-ntlm-hash-{common,sql,sccm}-results.xml`.

Both collector environments also passed actual password and hash baseline
logins, concurrent ordinary reads and missing-service logins. CMBP's actual EPA
adapter returned `Off` with both password and hash input. Safe reports are
`ntlm-isolation-hash-{sql,sccm}-lab.json` and `ntlm-hash-sccm-adapter-lab.json`
in the private feature folder. The full EPA settings matrix is not claimed here.
Graph stages were not changed by this fix, so no additional cached graph rerun
was needed. Full all-tool feature acceptance remains unfinished.

## Manual checks and owner review

From common's declared environment, use a fresh short pytest temporary path on
Windows (the original shared system temporary directory is unsuitable here):

```powershell
uv run --locked pytest tests/test_ntlm_reference_contracts.py tests/test_authentication_diagnostics.py -q --basetemp=C:\Users\domainadmin\.tmp\ntlm-review-01
uv run --locked ruff check --no-cache src tests
uv run --locked mypy src/openhound_collector_common
```

For live confirmation, an ordinary explicit-password collection against
`ps1-db.mayyhem.com:1433` uses the fixed helper automatically. There is no special
user switch. The retained offline concurrency check is the reliable way to force
the exact bad overlap; a live run alone cannot prove thread isolation.

Suggested owner commit after reviewing these files together with the pending
shared changes on which they depend:

```powershell
git add src/openhound_collector_common/clients/auth.py src/openhound_collector_common/clients/mssql.py tests/test_ntlm_reference_contracts.py README.md docs/changes/2026-10-29-ntlm-probe-isolation-proposal.md docs/changes/2026-10-29-ntlm-probe-isolation.md docs/changes/2026-10-29-ntlm-reference-contracts.md docs/changes/2026-10-29-ntlm-hash-input-proposal.md
git commit -m "Isolate EPA login messages and decode NTLM hash inputs"
```

The change removes shared authentication interference while preserving the
provider's other message fields and verifies both consumers. No staging,
commits, pushes or publication were performed; no push is recommended before
the full shared release review.
