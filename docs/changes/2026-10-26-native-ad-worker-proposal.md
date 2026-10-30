# Owner decision: bounded native Windows AD discovery fallback

> Historical record: the owner approved in-process AD/WMI on October 27, 2026. Process-specific designs and verification below are superseded. Current WMI uses whole-read host isolation and cancellation requests with visible Windows timeout overruns; the Windows LDAP fallback uses the native API. See the current in-process WMI/LDAP change record in openhound-collector-common.

Status: not adopted. On October 27, 2026 the owner chose to keep directory
and WMI reads in process, so no separate AD worker process was built. The
Windows directory fallback was implemented in process instead; see
`2026-10-27-inprocess-wmi-and-ldap.md`. This record is kept as history.

## Problem and decision requested

The approved feature plan includes an optional Windows AD discovery fallback
through existing pywin32 facilities. It also requires an owner decision before
using an owned process when a native operation cannot reliably stop in-process.
The owned-process decisions so far cover WMI, including explicit WMI credentials;
they do not cover a Windows AD provider or changes to the WMI worker internals.

Windows' ADSI ADO provider exposes search time limits and a client search timeout,
but these are not a demonstrated cancellation guarantee across provider creation,
connection/authentication, query execution, result iteration and cleanup. A timed
Python future does not stop a thread blocked in such a COM call. No existing
passing check establishes that complete in-process guarantee here. The proposal
therefore does not claim the native API has already failed a live cancellation
test; it chooses a boundary whose owned process can be stopped and reaped.

Approve an optional owned native AD worker in common, reusing the approved WMI
ownership/deadline/row-transfer machinery. MSSQL would opt in only for eligible
current-user Windows discovery/enrichment failures. SCCM's default remains
unchanged. No new dependency, schema change, OpenHound core edit, account change
or lab configuration change is proposed.

## Concrete implementation scope

1. Move only the existing worker's generic private process ownership, watched
   operation, bounded JSON/binary row transfer and confirmed cleanup machinery
   into a small common internal module. Preserve the public WMI classes and
   their authentication/query/complete-object behavior through their adapter.
   Both adapters must use the same tested stop/reap implementation.
2. Add a Windows-only AD adapter using pywin32 `ADODB.Connection`, the Windows
   `ADsDSOObject` provider and an ADO command's LDAP dialect. Initialize COM on
   the owned worker thread and release recordsets, commands and connections
   before balancing initialization. Use the current invoking identity only;
   accept no explicit password/hash/ticket source through this fallback.
3. Pin searches to the selected DC and optional port. Resolve its destination
   through the chosen Python resolver before entering native networking. Require
   signed/encrypted native binds; disable referral chasing, page results, turn
   off whole-result caching, and retain explicit size/search limits. Do not use
   a serverless ADSI path which could select an unrelated DC. Reject SOCKS:
   native Windows authentication/networking is outside Python's proxy boundary.
4. Keep shared `AdClient.paged_search`'s input/output contract. Decode binary
   SIDs/GUIDs and multi-value attributes into the same returned shapes, using
   the existing attribute conversion policy at an explicit boundary. Support
   discovery, first-match and SID/name lookups needed by MSSQL. Reject an
   unsupported search control visibly rather than silently dropping it.
5. Opt in only after an eligible integrated-authentication/transport failure,
   before any search rows were yielded. Never use it after rejected, disabled,
   locked or expired credentials, with an explicit credential selection, on
   non-Windows, or under SOCKS. Record the selected backend and failed/partial
   outcome. Do not retry a failed page after returning part of a result.
6. Apply the shorter LDAP-read/remaining-target deadline to startup, connection,
   query and transfer. Stop only the owned worker on expiry/cancellation, keep
   complete rows already received and require confirmed exit. Failure to confirm
   cleanup fails the owning run. Do not promise immediate remote cancellation.

Native AD implementation belongs in common because authentication, native call
lifetime, row transfer and directory paging are reusable transport behavior.
SQL discovery filters, graph rules, target policy and the opt-in stay in MSSQL.
Existing common consumers and CMBP gain no implicit fallback/default change.

## Alternatives and tradeoffs

Keeping ADSI in a thread with provider timeouts is smaller, but would leave the
complete stop/cleanup guarantee unproven and could leave a live worker after a
target was reported stopped. A second independent process/watchdog implementation
would duplicate the WMI lifecycle and make future fixes diverge. Shelling out to
PowerShell or another authentication tool is excluded by the approved plan.
Omitting the fallback leaves an approved feature unfinished; that is the
alternative owner decision if a separate worker is not desired.

Costs are one owned process per active native fallback client, startup time and
pipe transfer, plus a carefully bounded extraction of the existing WMI internals.
Raw data and graph writes remain in the parent. No worker can independently
publish collection files after a completed/stopped run.

## Acceptance evidence required before completion

- Prove WMI lifecycle behavior is retained with its existing grouped checks.
- Controlled AD providers: blocked initialization/bind/query/iteration, full
  pipes, paused consumers, short target budgets, cancellation, complete partial
  rows, no abandoned process and fatal unconfirmed cleanup.
- Selection cases: integrated transport failure qualifies; invalid credentials,
  explicit file/password/hash selection, proxy, unsupported platform/control and
  partly returned pages never switch identities/providers.
- More than one page, zero rows, binary SID/GUID and multi-value attributes,
  selected DC/port, disabled referrals and matching LDAP returned records.
- Authorized current-user lab reads through the actual native provider, comparing
  observations with normal LDAP while holding requested filters/attributes fixed.
  No lab settings may be changed to force a pass. Use controlled eligible failures
  when normal LDAP works, clearly distinguishing injected selection from live
  provider behavior. Check SCCM's unchanged consumers and document exact limits.

Update common/MSSQL README, architecture, status and feature verification records
with actual results. The owner will review and perform all Git/release actions.

## Sources and approval rule

Microsoft documents [ADO searches, authentication and timeout properties](https://learn.microsoft.com/en-us/windows/win32/adsi/searching-with-activex-data-objects-ado),
[paged large results](https://learn.microsoft.com/en-us/windows/win32/adsi/retrieving-large-results-sets)
and [the LDAP query dialect](https://learn.microsoft.com/en-us/windows/win32/adsi/ldap-dialect).
These describe provider controls, not a Python thread cancellation mechanism.

The collector plan's collection-controls section says: “If that cannot be
achieved in-process, stop that work package for an owner decision about the
backend/guarantee.” Root `AGENTS.md` also requires owner review and approval of
a proposal before shared-library edits. This proposal expands the earlier
WMI-specific process decisions, so that approval is required before its code.
