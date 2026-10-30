# In-process WMI and Windows LDAP

The owner approved this design on October 27, 2026, after lab checks established
that both can run in process but native Windows operations can exceed a selected
stop time. This replaces the earlier owned WMI process decisions; no AD process
was implemented. The full MSSQL feature-completion initiative remains open.

## Why this design

The owner prefers collection inside the invoking process. The previous WMI
process boundary allowed a confirmed local stop but added startup, serialization
and separate provider state. In-process reads are simpler to inspect and keep
normal Python values and selected credentials directly in memory. Their tradeoff
is explicit: cancellation is a request, and a Windows provider can delay final
exit while finishing its call and cleanup.

An offline check proved that impacket 0.13.1's hostname-only connection map can
replace one client's credentials with another's. The new whole-read host lease
in `clients/wmi_session.py` covers authentication, namespace selection, result
iteration, complete-object reads and cleanup. A login-only lock was rejected
because later calls read that same map again. Waiting for a host counts toward
an opted-in read budget. A second client on the same thread fails visibly rather
than deadlocking behind its own unfinished read. Idle lock entries are removed.

`clients/operations.py` monitors an opted-in read every 50 milliseconds. It can
request native Windows call cancellation or close available owned Python sockets.
The caller remains responsible for the read and actual cleanup on its own thread.
The monitor never joins a Windows COM apartment, kills a thread or marks it
finished prematurely. Late cancellation cannot affect a later use of the thread.

`clients/wmi.py` closes explicit connections after each streamed or complete-object
read. It uses finite result waits and forward-only query results. No idle provider
keepalive thread is needed between these short-lived sessions. A local cleanup
failure retains host ownership and raises `ClientCleanupError`; silently releasing
an uncleared credential map would reintroduce the defect. Native WMI objects stay
on their connecting thread through release. Selected current-user Windows WMI
rejects a Python SOCKS proxy, since native networking is outside that boundary.

MSSQL opts in with `ReadControl` and saves failed/partial query outcomes.
ConfigManBearPig imports the same raw backends and delegates complete-object reads
to their protected method, retaining its existing credential ladder and timeout
policy. SQL graph rules and all graph schemas are unchanged. OpenHound core is
untouched. No new dependency is required for WMI.

The Windows LDAP fallback now uses the Windows LDAP API through standard-library
`ctypes`, not an AD process or ADO. Normal ldap3 remains first. Only eligible
current-user failures before any rows can select native reads; explicit/rejected
identities, proxies, unsupported platforms and partially returned searches do
not switch. MSSQL opts in for discovery and enrichment with a 30-second read
stop-request budget. Native paging copies raw bytes into the same existing AD
converter, including missing-value placeholders. It retains the last page when
the native API returns end-of-search together with its records. Unsupported
extra controls/ranged attributes and entries above 16 MiB fail visibly.

The Windows status helper covers DCOM codes, native HRESULTs, automation wrappers
and SSPI errors wrapped by ldap3. Definite rejected, disabled, locked or expired
identities stop subsequent submissions. Object-level access denial remains a
separate permission outcome. Per-client guards prevent overlapping reads from
replacing an active native handle; raw provider use and cleanup stay on the
thread that acquired the host lease.

## Evidence and remaining work

The private investigation report and scripts are under the feature task directory
`C:\Users\domainadmin\.tmp\openhound-feature-completion-09fec00bb20d4f8f986d393183f0fdda`.
Healthy AD returned 14 lab computers; WMI returned an operating-system record.
Cancelling a controlled WMI result wait returned and cleaned up in about 8 ms.
An unavailable-host connection overran cancellation by about six seconds. Direct
Windows LDAP returned a timeout after four seconds with a two-second per-round-trip
setting. These are measured cases, not advertised maximum delays.

The final grouped replacement checkpoint passed 403 common tests with one
Python-version skip, Ruff and mypy (52 source files). SQL passed 289 unit/real
empty end-to-end checks with one unavailable-artifact skip, Ruff and mypy (52
source files). SCCM passed all 36 affected WMI/local-WMI/AD checks, plus Ruff and
mypy for its WMI adapter. The closing group includes account-rejection wrappers,
overlapping clients, cleanup after an already stopped/expired target, native
cleanup exceptions, and enabling cancellation after an explicit preconnect.

Live in-process WMI passed current-user, password, hash, ticket, cache and prepared
keytab query/complete-object/namespace reopening, plus SMS Provider lazy permissions.
The actual SCCM adapter passed current-user and password SMS Provider reads,
complete permissions and namespace reopening. Native LDAP matched normal LDAP
for all 14 lab computers with page size two and the requested identity attributes;
SPNs, SID lookup and successful empty searches also matched. A silent peer returned
a failed native read with confirmed cleanup after about four seconds with a
two-second request. The real MSSQL collect/prepare/convert command, forcing only
the normal LDAP bind to fail, returned 0 and matched the accepted graph exactly:
193 nodes, 583 edges, zero record differences after explicit per-kind `last_seen`
allowances, and four ZIP members byte-identical to the loose graph files.

These results cover this replacement package. Official Python 3.14 and the full
permission/profile matrix, shared scheduling/collection controls and the remaining
feature plan are still required. Do not cite process-worker checks as evidence
for this replacement.

To verify manually once installed from the reviewed shared-library change, run:

```powershell
openhound collect mssql .\inprocess-sql --targets ps1-db.mayyhem.com:1433 --domain mayyhem.com --dc 10.10.10.100 --wmi-timeout 10 --skip-linked-servers --run-all --clean --no-color
```

Compare saved target/query outcomes and the graph with the previous accepted lab
output. For CMBP, exercise its SMS Provider WMI path, including administrator/role
complete-object properties, and compare the graph with collection held constant.
Do not change a lab service or permission to force a particular fallback.

No staging, commit, push or shared release has been performed. The shared change
depends on other pending approved helpers, so commit the coherent shared-library
feature set after owner review rather than separating this adapter from them.
Suggested title: `Complete shared collection services and in-process Windows reads`.
For the collector adapters: `Use in-process Windows discovery with safe WMI sessions`.

Review commands (do not automatically stage unrelated SCCM changes):

```powershell
git -C C:\Users\domainadmin\openhound-collector-common diff
git -C C:\Users\domainadmin\openhound-mssql diff
git -C C:\Users\domainadmin\ConfigManBearPig diff -- src/openhound_sccm/clients/wmi.py tests/wmi_client_test.py README.md ARCHITECTURE.md docs/proposals/2026-10-26-owned-wmi-worker.md
```

After all shared helpers and their consumer changes are reviewed and the common
release is coordinated, owner-only staging/commit commands are:

```powershell
git -C C:\Users\domainadmin\openhound-collector-common add -- README.md src tests docs
git -C C:\Users\domainadmin\openhound-collector-common commit -m "Complete shared collection services and in-process Windows reads"
git -C C:\Users\domainadmin\openhound-mssql add -- README.md ARCHITECTURE.md src tests docs
git -C C:\Users\domainadmin\openhound-mssql commit -m "Complete MSSQL collection features and in-process Windows discovery"
git -C C:\Users\domainadmin\ConfigManBearPig add -- src/openhound_sccm/clients/wmi.py tests/wmi_client_test.py README.md ARCHITECTURE.md docs/proposals/2026-10-26-owned-wmi-worker.md
git -C C:\Users\domainadmin\ConfigManBearPig commit -m "Isolate same-host WMI sessions through complete-object cleanup"
```

The owner must inspect the complete staged diff before each commit; the broad
common/MSSQL commands intentionally include their interdependent pending feature
work. SCCM documentation includes other pending approved changes and also needs
manual review. No push or publication is performed by the developer.

## Sources

- [Microsoft call cancellation](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cocancelcall)
- [Enable cancellation before synchronous calls](https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-coenablecallcancellation)
- [Finite WMI enumeration waits](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wmi/141623d4-a170-4b09-8fea-3cb8f78fbbfe)
- [Windows LDAP authentication and per-round-trip timeout](https://learn.microsoft.com/en-us/windows/win32/api/winldap/nf-winldap-ldap_bind_s)
- [Windows account error codes](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--1300-1699-)
- [Expired/locked-account error codes](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--1700-3999-)
