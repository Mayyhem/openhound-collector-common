# Reusable output cleanup and continuation commands

The approved feature-completion plan promotes the generic part of SCCM's output
cleanup and path hints into common. Each collector retains its artifact list,
warning about retained data, command registration, and exit policy.

`orchestration/artifacts.py::prior_load_packages` counts DLT load records and
reports the oldest write time. This is not a count of previous collections:
one collection can write several packages. `clean_previous_collection` warns
when reusable output remains, or removes only the explicitly supplied direct
child names when cleaning is selected. Logs/reports are never discovered for
deletion. Every resolved target must remain below the named output directory,
and all are checked before the first removal. A failed deletion raises the
visible `OutputCleanupError`; callers must not continue collecting.

`orchestration/commands.py` shares path quoting and two saved-data continuation
commands. Windows hints target PowerShell, preserve familiar simple/space path
display, and quote expansion characters literally. POSIX uses `shlex.quote`.
Nothing runs a shell or reads authentication settings. Existing
`run_end_to_end` and ZIP creation are reused without changing their contract.

Copying SCCM's cleanup into SQL was rejected because it would duplicate boundary
checks and could accidentally apply SCCM's artifact names. Deleting every file
in an output directory would destroy evidence and previous reports. No new
dependency, schema change, framework edit, or shared default change is needed.

## Checks and manual verification

Official CPython 3.13.15: **28** shared cleanup/orchestration tests passed;
Ruff and mypy passed for all 46 shared source files. The checks include retained
logs/reports, load counts, warning-only mode, locked files, invalid names, and
an actual Windows junction outside the named output root. That junction case
also confirms a preceding valid artifact remains untouched when a later target
is unsafe. SCCM's existing cleanup/summary/integration-CLI checks passed **30**
tests without changed expectations.

SQL's complete command/stage checkpoint passed **287 tests**, with one existing
missing-artifact skip. A real current-user ps1-db `--run-all --clean` command
returned 0, retained the earlier 193-node/583-relationship graph with only named
conversion-time allowances, and wrote a byte-matching ZIP. An empty synthetic
collection passed all real stages with networking refused. Python 3.14, broader
profiles, and overall feature acceptance remain unfinished.

Repeat the focused shared checks with:

```powershell
uv run pytest tests/test_output_artifacts.py tests/test_orchestration.py
```

Suggested owner commit after review:

```powershell
git add -- src/openhound_collector_common/orchestration/artifacts.py src/openhound_collector_common/orchestration/commands.py tests/test_output_artifacts.py README.md docs/changes/2026-10-26-output-cleanup-and-continuation.md
git commit -m "Share declared output cleanup and continuation commands"
```

The README also contains earlier pending feature changes; review its full diff.
The agent has not staged, committed, or pushed anything.
