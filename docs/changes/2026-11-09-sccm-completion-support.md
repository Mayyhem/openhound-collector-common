# Shared support for SCCM completion

The owner approved three bounded shared changes in CMBP's completion proposal.
Development uses this local checkout; no package publication is performed here.

## Protection measurements must be conclusive

`clients/mssql.py:_classify_binding` previously interpreted any bogus-binding
result without an untrusted-domain flag as protection being Off. A transport
failure has no such flag, so a timeout could establish an incorrect vulnerability.
The missing-binding branch had the equivalent risk of producing Allowed.

The classifier now requires a recognized completed authentication outcome at
each required probe. Success or the existing plain login-failed response permits
the existing Off/Allowed decision; an untrusted-domain response follows the
existing rejection decision. Transport failures and unrecognized replies raise
`EPAPrereqError` naming the inconclusive probe without including raw errors or
credentials. Explicit credentials retain Required; current-user SSPI retains its
Allowed/Required ambiguity. Consumers preserve independent host facts and decide
their incomplete-run policy. A fabricated protection result is not an alternative.

## Optional propagation of genuine SQL errors

`dlt/duckdb_safe.py:safe_execute` adds the keyword-only
`raise_on_error=False`. Defaults and missing-source handling stay as before.
Opting in re-raises genuine DuckDB errors after logging. CMBP opts in; another
collector does not acquire a different error policy automatically. Required
prepared tables remain the consumer's responsibility. Changing every consumer's
default or copying the helper into CMBP would broaden the change unnecessarily.

## Independent log-file choices

`logging/files.py:RunFileLogs` adds `write_full=True` and `write_issues=True`.
Both default to the existing outputs. Disabled full logging creates no handler,
spool, target-file directory, or completion callback. Disabled issues logging
uses the diagnostics handler's counting-only mode: warning/error counts continue,
but it performs no record formatting or file writes. Console redaction and handler
restoration remain scoped to the run. The owned-file list excludes disabled
outputs, and repeated cleanup remains safe with any combination.

Attaching handlers and then suppressing their messages would still allocate
unwanted output machinery. Duplicating the logger in CMBP would lose the existing
shared lifecycle and redaction checks. No new dependency is needed.

## Graph-file tests follow numbered parts

The owner approved this additional test-only correction on 2026-11-10 after
Linux testing found a directory-order assumption. `tests/test_graph_files.py`'s
`documents` helper now sorts filenames before reading them. Filesystems do not
promise that part 1 is listed before part 2; the writer already uses numbered,
zero-padded filenames. Sorting lets the existing batch-size and completeness
assertions test those parts consistently on both systems.

The change belongs alongside the shared writer's tests. Sorting only the batch
sizes or dropping the assertion would weaken the check; changing production
graph writing would not correct a test that reads files in arbitrary order.
No runtime code, dependencies, public API, or emitted graph is changed.

## Windows-only boundaries are explicit

The owner approved this three-file correction on 2026-11-10 after Linux's code
checker reported four Windows-only attributes. `logging/console.py` now uses a
direct `sys.platform` condition for its existing Windows console selection.
`clients/operations.py:cancel_windows_call` and
`clients/windows_ldap.py:WindowsLdapClient._interrupt` check the platform before
loading the Windows libraries used to stop a native call or its socket.
Unsupported direct cancellation calls log and raise a clear `RuntimeError`.
Supported Windows calls keep their existing thread/socket ownership and behavior.

These helpers are shared by both collectors, so their platform boundaries belong
here. Explicit checks describe the actual requirement and let the checker select
the correct code for each system. Four ignored-error comments or forcing every
check to use Windows definitions would leave that requirement less clear. Mypy's
[platform-check guidance](https://mypy.readthedocs.io/en/stable/common_issues.html#python-version-and-system-platform-checks)
documents the recognized `sys.platform` conditions; this was verified with the
installed mypy 2.1.0. No new dependency, collector option, graph rule, or OpenHound
core change is introduced.

Six new tests cover Windows and non-Windows selections for terminal color, COM
cancellation, and native LDAP socket cancellation. Inert replacements check the
correct console flags, thread number, and owned socket without a real connection.
The existing console, LDAP paging/cleanup, WMI, and graph-file checks remain in
the affected group. All 91 checks pass on Windows and Linux; Ruff and native mypy
pass on both systems, with 65 source files checked. These checks resolve the four
Linux checker errors, without claiming full SCCM hierarchy/authentication acceptance.

## Verification and effects

The full shared test directory passed on both systems: Windows reported 661
passed and one skipped; Linux reported 660 passed and two skipped. Ruff and native
mypy passed on both systems, with 65 source files checked. New tests cover both inconclusive probe positions,
known Off/Allowed/Required outcomes, SSPI ambiguity, opt-in SQL errors and unchanged
defaults, all four file combinations, counts, no disabled spools/callbacks, and
cleanup. Existing redaction and write-failure tests remain green.

Thirteen relevant SQL collector target/failure tests passed against this local
source. No SQL collector source was edited. CMBP additionally checked real SMB
signing and cached graph equivalence; its optional-field corrections passed the
affected checks. Full SCCM acceptance remains open. Platform installs and live SQL
protection-matrix acceptance remain final checks, not implied by offline tests.

WSL Linux verification used Debian 13.5, system Python 3.13.5, uv 0.12.21,
and the local 0.1.5.dev5 wheel with OpenHound 0.4.2. Imports/help, CMBP's 179
affected checks, unchanged cached graph output, and administrator/ordinary-user
SMB collections passed. Common Ruff passed. The initial full common suite reported
653 passed, two skipped, and the directory-order test failure described above.
The approved corrections pass all 91 affected checks, including the 11 graph-file
tests, and native mypy on Linux and Windows. The full shared suites above were
then run through the updated review guide. Linux used the rebuilt local common
wheel with no source-path redirect; import/help, both SMB lab accounts, and the
unchanged cached graph also passed with that installed wheel. Broader hierarchy
and authentication acceptance remain open.

This work changes the EPA error classification for all consumers intentionally.
The SQL helper and file switches are optional and preserve other consumers'
defaults. Final release requires reviewing both collectors and publishing the
common version before a collector release depends on it. The owner performs all
commit, push, and publication actions.
