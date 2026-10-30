# Owner decision: isolate explicit-credential WMI sessions

> Historical record: the owner approved in-process AD/WMI on October 27, 2026. Process-specific designs and verification below are superseded. Current WMI uses whole-read host isolation and cancellation requests with visible Windows timeout overruns; the Windows LDAP fallback uses the native API. See the current in-process WMI/LDAP change record in openhound-collector-common.

Status: the owner approved extending the WMI worker on October 26, 2026.
Implementation and grouped feature verification are complete. The owner also asked
to be told if SCCM should adopt it; the recommendation is to prepare a bounded
SCCM adapter with its own checks and review before changing that default.

The final common checkpoint passed 371 tests with one Python-version skip;
Ruff and mypy passed. Live WMI password/hash/ticket/cache/prepared-keytab and
current-user reads, SCCM complete objects and the actual SQL cache-file command
passed. See [the worker record](2026-10-26-native-wmi-worker.md) and
[explicit credentials](2026-10-26-explicit-credentials.md). The whole feature
initiative and native Windows AD fallback remain unfinished.

## What the credential review found

The installed impacket DCOM provider stores active connections in class-wide
`DCOMConnection.PORTMAPS`, keyed only by target hostname. Creating another
connection to that name replaces the entry. `get_dce_rpc` and later interface
creation read the shared entry, including its credentials. Therefore two WMI
clients for the same host can use the second client's identity. The provider's
own class comment expects one connection per target.

An offline check used the real provider constructors and replaced only their
network transport with a controlled fake. The first client initially read its
own identity; after creating the second, the first read the second identity,
and both resolved the same provider object. All socket connections were refused.
No real account, target connection, or lab setting was used or changed.

The reproduction is in the task directory as
`dcom_credential_isolation_check.py`. It also matters for namespace connections:
the existing backend retains more than one connection for the same target.

## Recommended change

Extend the approved optional owned WMI worker to cover explicit password,
hash, and Kerberos reads as well as current-user native WMI. Each opted-in
client's local process then owns its provider's global DCOM state, namespace
connections, authentication, queries, and cleanup. Two clients can reach the
same host without sharing that provider state.

MSSQL would opt into this worker for all WMI authentication modes and use the
same per-read/remaining-target budget. Other consumers, including SCCM's
current default, would remain unchanged. This is generic WMI transport/lifetime
behavior in common; SQL collection and graph rules stay in the collector.
No new dependency, schema change, core edit, or lab configuration is needed.

Spawn arguments would contain no credential values. The parent would send
the selected explicit credential fields or file selection over the private
local pipe after startup. Loaded identities must still match the selected
username/realm. Requests remain bounded and validated; authentication data is
never written to run settings, graph records, filenames, or diagnostics.
The child inherits the invoking Windows account. Closing or timing out a read
must confirm that owned child has exited; unconfirmed cleanup remains fatal.

## Alternative

Serialize an entire explicit-WMI session per hostname with a shared lease.
That avoids the credential replacement but prevents parallel sessions to one
host and requires every namespace/query/cleanup path to obey the same lease.
It also leaves the provider's other process-wide timer/interface state shared.
Keeping only a lock around login would be insufficient: later interface calls
read the shared credentials again. Replacing the DCOM implementation would add
considerable code and would abandon the installed provider unnecessarily.

## Why this requires another decision

The [approved native-worker proposal](2026-10-26-native-wmi-deadline-proposal.md)
explicitly says: “Explicit-credential Python backends remain separate and need
their own tested socket/operation limits.” This recommendation expands that
decision to address the provider-state conflict discovered during the approved
credential work. The shared-library proposal review rule also applies.

## Acceptance checks

Use the same-host/two-identity case with controlled providers; prove every
request and result belongs to its own identity. Include separate namespaces,
concurrent healthy/stalled clients, timeout during login/query/result transfer,
partial complete rows, cancellation, and confirmed process cleanup. Check
that command lines, saved reports, and debug/error output contain no secrets.
Exercise authorized live password/hash and Kerberos WMI alongside current-user
WMI on the lab host, then rerun SCCM's unchanged default checks. This does not
claim that closing the local worker immediately cancels remote provider work.
