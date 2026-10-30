# Owner decision: a stoppable native WMI worker

> Historical record: the owner approved in-process AD/WMI on October 27, 2026. Process-specific designs and verification below are superseded. Current WMI uses whole-read host isolation and cancellation requests with visible Windows timeout overruns; the Windows LDAP fallback uses the native API. See the current in-process WMI/LDAP change record in openhound-collector-common.

Status: approved by the owner on October 26, 2026 and implemented. The
[implementation record](2026-10-26-native-wmi-worker.md) documents passing Python
3.13 checks and the remaining Python 3.14/final acceptance work. The original
proposal below records the decision.

## Problem

The approved collection-controls plan requires an actual operation deadline,
not a timeout that abandons a still-running thread. The current native backend
calls `SWbemLocator.ConnectServer` and synchronous `ExecQuery`, then enumerates
COM results. A timer in the collector cannot close the Windows-owned RPC socket
as it can for the Python SQL/socket clients. The completed COM thread-initialization
fix addresses correctness of thread ownership, not cancellation of blocked calls.

Microsoft documents `wbemConnectFlagUseMaxWait` as a two-minute connection limit,
not an arbitrary caller-selected deadline. Asynchronous query callbacks do not
bound the preceding connection call or prove that every stuck provider can be
cancelled before the collector reports its target finished.

## Proposed change and placement

Add an optional positive finite native-operation deadline to common's `WmiClient`.
When selected for current-user Windows WMI, run the native backend in one
run-owned child process per WMI client. That process owns its COM initialization,
connections, queries, and cleanup. Keep the existing in-process behavior when
the option is absent, preserving other consumers until they explicitly adopt it.
Explicit-credential Python backends remain separate and need their own tested
socket/operation limits.

Use a small explicit request/result format over a local pipe. Stream complete
rows with backpressure; do not send COM objects or collect an unbounded result
list for transfer. Do not put credentials in command arguments, filenames, or
logs. The native worker inherits the invoking user's Windows identity. It has
no separate DLT writer and cannot keep changing the saved bucket after it stops.

On expiry or stop request, request normal cleanup, then terminate and join only
that owned child if it remains stuck. Do not report its target stopped until
the process is confirmed gone. If cleanup cannot be confirmed, fail the run
explicitly. Already saved complete rows remain partial evidence. Stopping the
local process does not promise immediate cancellation of work inside a remote
Windows provider; document that practical limit.

This belongs in common because common owns WMI authentication and transport and
both collectors use it. Putting process management in MSSQL would duplicate the
client boundary. Add the worker under `clients/`, focused tests under `tests/`,
and README documentation. No OpenHound core change or new dependency is needed.
MSSQL will opt in using the shorter operation/remaining-target budget. SCCM
retains its present default unless a separately reviewed adapter selects it.

## Alternatives

Waiting on a future while leaving its thread running violates the approved
plan. The fixed two-minute Windows connection flag cannot enforce a shorter
operator budget. Replacing the whole native stack with a new COM implementation
adds provider-specific complexity without demonstrating reliable cancellation.
Removing current-user support would discard an approved collection feature.

## Verification before adoption

Use a controlled child that stalls during startup, query, and result transfer;
confirm process exit and no later rows after timeout/stop. Test partial rows,
broken pipes, parent interruption, repeated close, rejected budgets, and bounded
row transfer. Exercise real current-user local and authorized-lab remote WMI on
Windows with official Python 3.13/3.14, including a healthy target alongside the
stalling child. Retest SCCM's unchanged default and the existing explicit-credential
backend. Do not advertise a hard native deadline until those checks pass.

Sources inspected October 26, 2026:

- [Microsoft: WbemConnectOptionsEnum](https://learn.microsoft.com/en-us/windows/win32/api/wbemdisp/ne-wbemdisp-wbemconnectoptionsenum)
- [Microsoft: ConnectServer](https://learn.microsoft.com/en-us/windows/win32/wmisdk/swbemlocator-connectserver)
- [Microsoft: ExecQueryAsync](https://learn.microsoft.com/en-us/windows/win32/wmisdk/swbemservices-execqueryasync)
- Current common `clients/wmi.py`, `_PyWin32Backend._services_for`, `query`, and `stream`.
