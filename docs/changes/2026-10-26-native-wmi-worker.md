# Stoppable current-user WMI reads

> Historical record: the owner approved in-process AD/WMI on October 27, 2026. Process-specific designs and verification below are superseded. Current WMI uses whole-read host isolation and cancellation requests with visible Windows timeout overruns; the Windows LDAP fallback uses the native API. See the current in-process WMI/LDAP change record in openhound-collector-common.

The owner approved the [concrete proposal](2026-10-26-native-wmi-deadline-proposal.md)
on October 26. Native Windows WMI can block inside a provider; cancelling a
Python future does not stop that native call. The opt-in worker puts COM and
its connections in one owned local process so the parent can stop that process
and confirm its exit. The old in-process default remains. The owner subsequently
approved [extending the optional worker to explicit credentials](2026-10-26-explicit-wmi-worker-proposal.md).

## How it works

`clients/native_wmi.py` defines `WmiProcessControl` and `WmiProcessBackend`.
`WmiClient(process_control=...)` selects the worker for current-user or explicit
authentication. Current-user mode inherits the invoking Windows identity;
explicit credentials are sent after startup over the private pipe. No credential is
placed in a command line. A private pipe carries JSON requests and complete
rows, with a 16 MiB message limit and backpressure. Provider objects never
cross that pipe. One client supports sequential reads using the same process;
separate clients can operate concurrently without sharing DCOM's hostname-only
credential maps. The worker keeps only one explicit DCOM namespace connection
open at a time, closing it before a namespace switch. Complete-object GetObject
and Get reads use the same watched boundary. Tagged JSON preserves binary and
nested values without confusing ordinary provider dictionaries with tags.

A watchdog checks the operation/remaining-target deadline and stop request
every 50 ms, including during startup and row transfer. It requests cleanup,
allows 250 ms, then terminates and joins the owned process. A further kill/join
is available if necessary; each forced wait is capped at 500 ms. Failure to
confirm exit raises `WmiProcessCleanupError` and must fail the run. Complete
rows received before a timeout remain partial data. Each WMI query exposes a
non-secret `OperationResult`; its failed count stays unknown rather than zero.
`WmiClient`'s old empty-on-error behavior is unchanged when not opted in.

Native Windows networking cannot follow Python's SOCKS wrapper, so the worker
rejects an active proxy for current-user mode. Explicit DCOM receives the run's
validated DNS/proxy settings inside the child. Native mode resolves a supplied
hostname through the selected DNS service before handing its address to COM.
Provider packet/key debug dumps are suppressed and pipe errors redact supplied
credentials. Stopping a local worker does not promise immediate
cancellation of work in the remote provider. The generic API accepts a target
deadline; MSSQL currently supplies a per-read `--wmi-timeout` (default 30 s).
Broader target budgets remain part of the unfinished collection-controls work.

Keeping a blocked thread was rejected because it could continue after a target
was reported stopped. Replacing COM entirely would add unnecessary provider
complexity. Process ownership belongs beside the shared WMI client so collectors
do not implement competing transport lifecycles. No new dependency is added.

## Verification recorded October 26

- Official CPython 3.13.15: the complete shared suite passed **300 tests**, with
  one deliberate Python-version skip. Ruff and mypy passed at this checkpoint.
- Controlled spawned children covered startup/query/row-transfer stalls,
  backpressure while the caller pauses, partial rows, cancellation, shorter
  target budgets, healthy parallel reads, provider errors, message limits,
  repeated cleanup, and an injected unconfirmed process exit.
- Authorized owner-token WMI read `Win32_OperatingSystem` locally, and exact
  SQL-service plus computer records on `ps1-db.mayyhem.com`. Worker reuse and
  COM cleanup passed. Restricted-token WMI is denied by the lab in both old
  and new paths; that denial is recorded, not counted as success.
- Actual `openhound collect mssql` against ps1-db collected **7,240 raw rows**
  with **37 completed reads, zero failed reads**, including three local-group
  member rows. Collection, fresh-process preprocessing, conversion, and ZIP
  writing completed. Linked-server reads were deliberately disabled for this
  worker check. No lab settings were changed.
- SCCM's unchanged WMI/auth consumer selection passed **37 tests**. SQL's
  worker-facing selection passed **49 tests**, followed by eight focused
  outcome/producer checks. A later SQL offline checkpoint passed 270 tests
  with one unavailable-live-artifact skip.

Python 3.14, remaining transports, resource guards, and complete live-profile
acceptance remain to be checked before claiming the whole plan is complete.

Extension checkpoint: 40 grouped offline WMI/COM/network checks and 46 unchanged
SCCM auth-consumer checks passed. Live ps1-db query, complete-object and namespace
switch checks passed for current-user/password/hash/cache/ticket modes. Live
ps1-sms queries and complete administrator Permissions passed for current-user,
password and cache modes. These checks justify recommending a separate SCCM
adapter; SCCM's default has not changed. The task directory holds the exact
`extended-wmi-lab-results.json` report. No new dependency or schema change.

Manual verification: use the README's `WmiProcessControl` example with a readable
lab namespace under the intended account, confirm a completed outcome, then run
`uv run pytest tests/test_native_wmi_worker.py tests/test_wmi_thread_initialization.py`.
For a lab command use `openhound collect mssql .\wmi-check --targets
ps1-db.mayyhem.com:1433 --domain mayyhem.com --dc 10.10.10.100 --wmi-timeout 10
--skip-linked-servers --no-color` from the collector environment. The real
current-user check needs the owner's Windows token, not the restricted tool token.

Suggested owner commit after review: `Add optional stoppable native WMI reads`.
Include `clients/native_wmi.py`, the WMI client and package documentation,
`tests/native_wmi_helpers.py`, `tests/test_native_wmi_worker.py`, and this record
with its proposal. The agent has not staged, committed, or pushed anything.
