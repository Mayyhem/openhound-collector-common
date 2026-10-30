# Keep each explicit Kerberos identity local to its connection

> Historical record: the owner approved in-process AD/WMI on October 27, 2026. Process-specific designs and verification below are superseded. Current WMI uses whole-read host isolation and cancellation requests with visible Windows timeout overruns; the Windows LDAP fallback uses the native API. See the current in-process WMI/LDAP change record in openhound-collector-common.

## Problem and selected solution

The earlier SQL/LDAP ticket paths changed `KRB5CCNAME`, a process-wide setting.
Concurrent readers could therefore select another reader's cache. Windows'
integrated LDAP provider also does not select a supplied MIT cache that way.
Some paths treated the first supplied credential as a TGT even when it belonged
to a different service. The approved feature-completion work requires explicit
cache/keytab inputs, matching identities and exact endpoint ports.

`clients/kerberos.py` now owns bounded input parsing and one selected identity.
It reuses impacket 0.13.1, already a dependency, for formats, keys and Kerberos
traffic. Supported sources are base64 KRB-CRED, MIT cache versions 3/4 and MIT
keytab version 2. Files/decoded inputs are bounded at 16 MiB. A cache must have
one client identity; supplied username/realm hints must match it. Keytabs may
contain several identities, but an ambiguous selection requires username/realm.
Legal deleted-entry holes are skipped before the pinned keytab parser.

Keytab selection uses the newest key version and prefers AES-256, AES-128, then
RC4 among that version's supported keys. A guarded TGT acquisition remembers
failure, preventing concurrent consumers from submitting a rejected key again.
`prepare` acquires a keytab TGT before collectors start parallel readers. Owned
workers receive a ticket snapshot privately, instead of re-reading a replaced
cache file or independently submitting that key. Loaded tickets are matched to
the complete requested SPN, including its port and any specified realm.
Expired/unrelated service tickets are not substituted for the requested service
or treated as a TGT. No temporary credential file or OS cache environment change
is needed. This implementation does not read `krb5.conf`.

## Protocol boundaries and failures

- `clients/mssql.py` supplies the exact selected TGS directly to
  `kerberosLogin(useCache=False)`. Supplying only a TGT would let the provider
  derive a different SPN and discard the caller's port/name selection.
- `clients/ldap_kerberos.py` binds a real ldap3 connection with GSS-SPNEGO.
  Existing custom ports, Entry objects, attributes and paging are retained.
  TLS uses the connection certificate's channel binding. Plain LDAP uses the
  pinned impacket provider's GSS signing/encryption and a bounded framing
  wrapper which handles fragmented TCP reads. It does not implement a second
  LDAP search engine or a second Kerberos encryption stack.
- Optional WMI process isolation, complete-object reads and private setup are
  described in [the worker record](2026-10-26-native-wmi-worker.md). Definite
  password/identity rejection stops the owned worker rather than resubmitting
  the same credential for its next query.
- `logging/authentication.py` suppresses provider authentication packet/key
  debug dumps for the calling thread, restoring its filters even on failure.
  Such newly generated secrets cannot be redacted just by matching the original
  password. Safe failure outcomes remain visible; supplied WMI secrets are
  redacted before error text crosses the private pipe.
- KDC acquisition errors expose a numeric provider reason when available,
  without copying credential bytes or full authentication packets.

`AdClient` now offers an optional `on_query` outcome callback. Bind failures,
query rejection, unfinished reads and unexpected server truncation have unknown
counts and safe failure categories. A successful empty read still has count
zero. The explicitly limited first-match helper finishes its generator before
returning. Definite credential rejection is remembered by that client. Default
consumers keep their existing query interface; saving outcomes remains opt-in.

The first full command exposed a PTR-less DC. `dc_hostname_for_address` in
`discovery/dns.py` now checks published AD SRV names and their forward addresses
using the active run's resolver. It accepts only a hostname for the selected DC
IP. It does not guess a name, select another DC, or bypass selected DNS/proxy
settings. This fallback applies to explicit Kerberos inside a selected network
session. Other consumers can supply a DC hostname directly. Network settings
and the selected resolver remain active until every owned worker stops.

The alternative of global cache environment changes was rejected because it
cannot isolate simultaneous identities and is ineffective for this Windows
file-authentication path. Replacing ldap3 would lose established paging/Entry
behavior and impacket's LDAP constructor does not support the collector's
custom-port boundary. No new dependency, graph/schema or core change is added.

## Verification and practical limits

Final grouped feature checkpoint: **371 common tests passed**, with one
Python-version skip; Ruff and mypy passed for all 49 source files. **296 SQL
tests passed**, with one unavailable-live-artifact skip; Ruff and mypy passed
for its 52 source files. The earlier numbers below preserve how the newly
discovered DNS/outcome gaps were checked, without replacing final results.

CMBP's real ticket-authenticated discovery-only collect/prepare/convert command
also returned 0 and emitted nine nodes/ten relationships, with ZIP bytes matching
loose files. It used the normal DC hostname, changed no settings and retained
CMBP's WMI default. This is a bounded live consumer check, not the complete SCCM
integration matrix.

Official CPython 3.13.15 checkpoints: the common suite passed 358 tests with one
Python-version skip before the final DNS/LDAP-outcome additions. Their focused
selection passed 30 tests. The earlier SQL checkpoint passed 295 tests with one
unavailable-live-artifact skip; the new LDAP/SQL outcome selection passed 21.
SCCM's affected unchanged consumer selection passed 52 checks, followed by 15
LDAP consumer checks after the outcome additions. Ruff and mypy passed at
those checkpoints. Final grouped feature results are recorded in the collector
feature record; these checkpoints do not establish whole-plan acceptance.

Offline tests use real synthetic MIT encoders/parsers for both cache versions,
all supported key types, identity ambiguity/mismatch, deleted keytab holes,
expiry, exact ports, concurrent sources, one rejected-key submission, immutable
worker snapshots, safe errors and no environment mutation. LDAP tests cover
real AES reply verification, modified ciphertext, fragmented/truncated/oversized
frames, outbound sequence numbers, certificate binding and safe query outcomes.

Authorized read-only live checks passed current-user/password/hash/cache/ticket
and prepared RC4-keytab WMI on ps1-db, plus complete SCCM administrator objects
on ps1-sms. Cache and prepared-keytab reads passed SQL, LDAPS and signed LDAP.
The actual cache-file collector command completed all stages with 7,240 saved
rows, 48 completed reads and zero failed reads. Its 193 nodes/583 relationships
and four ZIP members were audited. Per-kind timestamps differ between live runs;
Kerberos-only collection also intentionally omits the NTLM-only EPA probe and
unmeasured strict-encryption property. The exact report keeps those differences
visible. No lab settings were changed and derived live credentials were temporary.

AES keytab formats/selection are covered offline; the live keytab check used
RC4. Python 3.14, the full permissions/transport matrix, complete query/target
deadlines, native AD fallback and remaining feature-plan work are unfinished.
SCCM's owned-WMI default remains unchanged; see its separate adoption proposal.

Manual checks use the SQL README's `--ccache`/`--keytab` examples with existing
credential files. Supply `--dc dc.mayyhem.com` if a consumer does not use the
shared selected network session and its DC has no PTR. Invalid/conflicting files
must be rejected before cleanup. Run the organized credential, LDAP and WMI tests
through the declared isolated project environment.

Provider/spec references: [impacket 0.13.1](https://github.com/fortra/impacket/tree/impacket_0_13_1),
[MIT cache format](https://web.mit.edu/kerberos/krb5-latest/doc/formats/ccache_file_format.html),
[MIT keytab format](https://web.mit.edu/kerberos/krb5-latest/doc/formats/keytab_file_format.html),
[TLS endpoint channel binding](https://www.rfc-editor.org/rfc/rfc5929),
[Kerberos GSS tokens](https://www.rfc-editor.org/rfc/rfc4121), and
[AD SASL authentication](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/989e0748-0953-455d-9d37-d08dfbf3998b).

Suggested owner commit after review:

```powershell
git add -- src/openhound_collector_common/clients/kerberos.py src/openhound_collector_common/clients/ldap_kerberos.py src/openhound_collector_common/clients/auth.py src/openhound_collector_common/clients/ad.py src/openhound_collector_common/clients/mssql.py src/openhound_collector_common/clients/wmi.py src/openhound_collector_common/clients/native_wmi.py src/openhound_collector_common/logging/authentication.py src/openhound_collector_common/discovery/network.py src/openhound_collector_common/discovery/dns.py tests/kerberos_fixtures.py tests/test_kerberos_credentials.py tests/test_ldap_kerberos.py tests/test_authentication_diagnostics.py tests/test_ldap_query_outcomes.py tests/test_dc_hostname.py tests/test_native_wmi_worker.py tests/native_wmi_helpers.py README.md docs/changes/2026-10-26-explicit-credentials.md docs/changes/2026-10-26-explicit-wmi-worker-proposal.md docs/changes/2026-10-26-native-wmi-worker.md
git commit -m "Isolate explicit Kerberos identities and owned WMI readers"
```

No Git actions or publication were performed. Review shared consumers and use
the owner's one planned shared-library release before updating published floors.
