# Shared full/issues logs and run cleanup

The approved SQL feature-completion plan promotes ConfigManBearPig's reusable
file logging without changing its console layout or service-specific rules.
MSSQL also needs detailed files independent of console level, safe per-target
logs, and identifiable diagnostics for separate preparation/conversion commands.

`logging/files.py` supplies `DiagnosticFileHandler`, `GroupedFileHandler`, and
`RunFileLogs`. The issues handler retains SCCM's warning/error counters, delayed
file creation, exception tracebacks, and companion debug messages emitted inside
an exception. It copies each record, preserving other handlers' view.

The grouped handler writes each complete formatted/redacted message immediately
to a private spool file. Only file paths are retained for unfinished groups;
there is no growing list of messages or live traceback frames. Target/resource
completion publishes one contiguous labelled section. Close flushes unfinished
groups after normal completion, interruption, or failure. Failed publication
retains redacted spools, reports the error, and makes owning-command cleanup fail.
Successful cleanup removes only its emptied private spool directory.

`RunFileLogs` owns handler attachment, completion callbacks, namespace DEBUG
levels, formatter redaction, and restoration. It can finish the full collection
log while retaining issues for chained stages. Its context manager releases
issues even when collection itself fails. Repeated cleanup is safe. Callers
supply namespaces, run labels, secrets, and an optional formatter/target directory;
common imports neither collector.

The promoted default retains SCCM's ordered-file layout. `GoFileFormatter` adds
redacted tracebacks to MSSQL's opt-in Go layout. Secret field detection covers
camelCase and underscore names. Inline credentials handle passwords containing
`@` and URL schemes. Token processing avoids repeatedly searching large ordinary
messages: the full shared suite, including the one-megabyte spool stress case,
completed in 3.96 seconds after correcting a slow initial implementation.

Keeping unbounded buffers would retain messages and exception frames for a slow
target. Flushing arbitrary fragments early would break completion ordering.
Private spool files preserve ordering with small memory use. Silently dropping
failed writes would hide incomplete diagnostics; the command now fails instead.
No third-party dependency or OpenHound core edit was added.

Verification on official Python 3.13: **278 shared tests passed, one explicit
Python-version skip**; Ruff check/format and mypy (42 source files) passed.
MSSQL's 55-test command/worker/network/stage checkpoint passed, then all 18
command/target checks passed with the added silent/per-target and failure-status
cases. SCCM's 71 affected handler, command, cleanup, stage, and integration-wiring
checks passed. Its adapter lint/type checks passed. These are offline/cached-data
checks, not final live integration acceptance.

Developer commands use the repository's declared uv environment:

```powershell
uv run pytest tests/test_file_logs.py tests/test_console_format.py tests/test_console_policy.py
uv run ruff check src tests
uv run mypy src
```

Review this with the other pending common changes before the owner's single
shared release. Suggested commit message: `Share bounded full/issues logging and scoped cleanup`.

```powershell
git add src/openhound_collector_common/logging/files.py src/openhound_collector_common/logging/console.py tests/test_file_logs.py README.md docs/changes/2026-10-26-shared-file-logs.md
git commit -m "Share bounded full/issues logging and scoped cleanup"
```

The owner performs Git and release actions. No files were staged or committed.
