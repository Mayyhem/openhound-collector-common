# SQL and LDAP read limits

## Problem and selection

A receive timeout only measures an idle socket. A slow server can keep a read
alive by returning a few bytes at a time. A future timeout only stops the caller
waiting; its worker keeps running. Both allow a target to keep authenticating,
reading or writing after the command appears finished.

The approved collection-controls plan calls for owned connection interruption,
per-read and per-target budgets, complete-record retention and actual cleanup.
This change extends the existing in-process `ReadControl` to SQL and normal
Python LDAP. No process, thread termination, new dependency or OpenHound core
change is introduced. Other consumers select the controls explicitly; SCCM's
SQL/LDAP timeout defaults remain unchanged.

## Implementation

[clients/operations.py](../../src/openhound_collector_common/clients/operations.py)
monitors monotonic time and the caller's stop event every 50 milliseconds.
`check()` refuses a new request or row after the shared target deadline or stop.
An already-expired target raises `ReadStoppedError` before starting another read.
Cleanup remains allowed after a stop, and failed cleanup stays fatal.

[clients/mssql.py](../../src/openhound_collector_common/clients/mssql.py) accepts
`MssqlConnection(read_control=...)` and `detect_epa(..., read_control=...)`.
Connection work combines the existing connection deadline with the target/read
budget. Queries and EPA probes monitor only their client's socket. A stopped
query closes the connection and refuses further reads. An interrupted login does
not try another connection strategy or EPA probe. Cleanup before socket creation
does not attempt to disconnect impacket's unopened socket placeholder.
`query(..., timeout_seconds=...)` selects a distinct read budget while retaining
the target deadline and stop event.

[clients/ad.py](../../src/openhound_collector_common/clients/ad.py) accepts
`AdClient(..., read_control=...)`. A complete paged search has one budget across
binding, all pages and result copying. The constructor is told not to bind
automatically, so the client can retain ownership before open, optional StartTLS,
bind and server-info reads. A direct `bind()` also monitors the whole profile
sequence. Failed or stopped binds release the opening connection and cannot
continue authentication through another profile. Native fallback is refused
after cancellation or failed cleanup. The existing Windows fallback has its own
native handle controls, using the same target deadline and stop event.

Python's timed receive wait on this Windows host did not wake after socket
`shutdown` alone, even though that call succeeded. The owned Python socket must
also be closed. Both monitors do that; the reading thread still performs provider
cleanup. A known LDAP transport error while sending unbind is acceptable only
after a requested stop and confirmation that the owned socket is already closed.
An unrelated cleanup error is still fatal. Native WLDAP handles are borrowed
from Windows and are never closed as Python sockets by this helper.

MSSQL supplies the service policy in its collector:

| Setting | Default and meaning |
|---|---|
| `--query-timeout` | 30 seconds per ordinary SQL read. |
| `--linked-timeout` | 300 seconds for the complete linked-server SQL batch, including its remote probes. |
| `--ldap-timeout` | 30 seconds for a complete LDAP search. |
| `--target-timeout` | 600 seconds across a target's collection work; each client also sees the remaining target budget. |
| Existing connection/WMI settings | Keep 15-second SQL connection and 30-second WMI defaults, tightened by the target budget. |

The worker copies runtime settings before assigning its own deadline, retaining
already-prepared credential inputs. It does not change process-wide credential
state. A stopped SQL/LDAP read passes through the local query/SID helpers;
the target's complete saved rows remain, its state becomes `stopped`, and other
targets continue. Failed cleanup remains a run failure. The six configured time
budgets are saved through explicit non-secret run settings. Invalid nonpositive
budgets and negative worker counts are rejected before cleanup or collection.

Native provider startup, Windows authentication and cleanup may return late;
their overrun is visible and the command waits. Existing DNS/KDC setup has its
own network controls; completing all resource/setup limits remains part of the
larger initiative. These controls do not claim a guaranteed final-exit time.
File/memory guards and complete scratch accounting remain separate unfinished
work. No graph kind, edge traversal rule or graph property changes here.

## Evidence and manual verification

The shared boundary checkpoint passed 420 tests with one Python-version skip;
SQL's full unit selection passed 293 with one unavailable-artifact skip; the
affected SCCM selection passed 104. Additional socket-start/cleanup cases are
checked separately after the final guard adjustment. Common and SQL lint/type
checks passed; common checks 57 source files and SQL checks 52.

Actual lab commands ran complete collect/prepare/convert with normal LDAP and
with an injected eligible normal-provider failure selecting real Windows LDAP.
Each returned 0 with 193 nodes and 583 relationships. Every graph record matched
the accepted baseline after explicit per-kind collection-time allowances; all
four ZIP members matched loose files. Private evidence lives under the feature
task's `read-controls-normal-live.json` and `read-controls-native-live.json`.
The delayed SQL read check uses `WAITFOR` without changing data or configuration.
It stopped a five-second delay in 0.557 seconds with a 0.5-second budget, closed
that session and left a second session able to read. The final shared checkpoint
passed 423 tests with one version skip, including a real ldap3 bind to an owned
silent peer. The final SQL target/outcome selection passed 22 checks, SCCM's
unchanged EPA adapter passed 10, and common/SQL lint and type checks passed.
This is feature evidence, not the full initiative's final acceptance matrix.

In the common repository's declared environment, run the owned-socket checks:

```powershell
uv run pytest tests/test_sql_read_controls.py tests/test_ldap_read_controls.py -q
```

After the reviewed shared release, an authorized lab operator can run:

```powershell
uv run openhound collect mssql .\read-budget-check --targets ps1-db.mayyhem.com:1433 --domain mayyhem.com --dc 10.10.10.100 --query-timeout 30 --ldap-timeout 30 --linked-timeout 300 --target-timeout 600 --workers 2 --run-all --clean
Get-Content .\read-budget-check\collection-status.json
```

Use fault tests rather than exhausting real memory/disk or changing lab policy.
The socket cases verify that unrelated connections remain usable, the last
complete LDAP page survives, late rows are rejected, no subsequent login occurs,
and unexpected cleanup failure remains fatal.

Authoritative references: [ldap3 Connection documentation](https://ldap3.readthedocs.io/en/latest/connection.html)
for manual connection control and receive timeout semantics, and
[ldap3 operation documentation](https://ldap3.readthedocs.io/en/latest/tutorial_operations.html)
for synchronous results. The installed implementation under test is
ldap3 2.10.2rc4 with impacket 0.13.1 on official CPython 3.13.15. Windows timed
receive behavior was established experimentally; a future provider change must
retain the owned-socket regression checks.

## Review and commit suggestions

Suggested message: `Enforce owned SQL and LDAP read budgets`.
Review overlapping earlier feature changes before staging. The owner performs
Git actions; no files have been staged, committed or pushed by the agent.

```powershell
# Common:
git add src/openhound_collector_common/clients/mssql.py src/openhound_collector_common/clients/ad.py src/openhound_collector_common/clients/operations.py src/openhound_collector_common/collection/work_queue.py tests/test_sql_read_controls.py tests/test_ldap_read_controls.py README.md docs/changes/2026-10-27-sql-and-ldap-read-limits.md
git commit -m "Enforce owned SQL and LDAP read budgets"

# MSSQL:
git add src/openhound_mssql/auth.py src/openhound_mssql/main.py src/openhound_mssql/extension.yaml src/openhound_mssql/collection tests/unit/test_collection_outcomes.py tests/unit/test_collection_failure_controls.py README.md ARCHITECTURE.md docs/changes/2026-10-23-feature-completion-status.md
git commit -m "Apply per-read and per-target collection budgets"
```
