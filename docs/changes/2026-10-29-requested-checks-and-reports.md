# Independent requested checks and readable reports

This implements generic check orchestration and report presentation from the
approved MSSQL feature plan. SQL fixture/profile assertions and the broader Go
reference lifecycle are still in progress. It does not claim completed live
acceptance of that initiative.

## Problem, selected solution and boundaries

CMBP already offered fixture assertions and baseline comparison after conversion.
It combined their returned status codes, but an exception in the first call could
prevent the second call and its report. MSSQL also needed to combine checks with
usable-but-incomplete collection status. Copying the command block would repeat
that failure and its reporting rules.

Common now supplies `integration_testing.validation.run_requested_checks`. Each
caller supplies a name, callback and fresh report path. Every requested callback
is attempted before the result is combined, including after ordinary callback
or report errors. A callback must return integer 0/1 and write a JSON object.
Missing/malformed reports and invalid statuses fail. Existing reports are
preserved and cannot stand in for this run's evidence. Failure reports include
the exception type and a direction to the logs, not its potentially sensitive
message. A failure to write that report remains a failed outcome and does not
prevent another requested check. User interruption still propagates.

Any failed requested check returns 1. Otherwise common preserves the supplied
collection status 0/1/3. Callers only invoke checks when a graph is available;
common does not collect data, decide permissions, set up fixtures, or infer
privilege. The ordinary no-check collection path remains unchanged.

`integration_testing.reports.write_summary_reports` writes the existing case
summary JSON and a matching HTML case table. Text is HTML-escaped. The HTML has
no scripts, external styles, network requests, or credentials. The caller may
add explicit public context such as collector/profile. Report-write errors
propagate. A browser is not launched automatically.

Alternatives considered were keeping independent command copies, accepting a
returned zero without a report, or treating a report exception as informational.
Those either duplicate policy or conceal unexecuted/broken checks. Moving SQL
permission rules or SCCM privilege inference into this runner was rejected:
those remain decisions of their collectors. No dependency was added.

## Consumer behavior

SCCM's `_run_graph_checks` supplies its existing report names, regression policy,
and high/low/auto fixture choice. A false privilege value still runs the low
suite; None means the suite was not requested. It now attempts the suite after a
comparison exception. Fixture results also produce `.html` beside `.json`.
Collection methods, authentication, graph builders and SCCM privilege inference
are unchanged. README and architecture describe these user-visible changes.

SQL's local `integration` adapter uses the same runner for the newly wired
`--compare-to-zip`. It implies `--run-all`, needs no permission profile, and
compares the supplied ZIP baseline with the new graph. As in SCCM, loss of
baseline content fails while the report shows all differences. Strict reference
equivalence still uses `openhound-compare --exact`; the convenient regression
check does not claim identical graphs. Discovery-only collection rejects this
graph-dependent option before cleanup or collection.

SQL reports use the collection's unique run ID and survive cleanup. Passing
comparison preserves collection status 0/3; failed comparison returns 1. A later
resource stop cannot replace that failed status with 3. Its collection-status
file continues to describe collection, distinct from the final command outcome.
An invalid ZIP or missing/broken report also fails. SQL's pending fixture suite
will supply another callback without changing this orchestration contract.

## Verification

Common's full offline checkpoint passed **498 tests with one explicit Python
version skip**, plus Ruff and mypy over 64 source files. New cases exercise
assertion/exception/missing-report/malformed-JSON/invalid-status failures,
incomplete and failed collection precedence, stale reports, report-write failure,
HTML escaping, and failed HTML publication.

SCCM's affected checkpoint passed **32 tests**, including the required metadata,
wiring, converter and fixture files, plus affected-source Ruff and mypy over 63
source files. The combined-status tests now execute the actual adapter rather
than checking only a one-line boolean formula. A comparison exception still
executes the requested fixture callback and produces both report attempts.

SCCM's actual cached collection was prepared and converted in fresh private
output with Python target networking refused. Its 99 nodes/307 relationships
matched the preserved baseline exactly after the existing named per-kind
`last_seen` allowances. Original raw data and graph files were not modified.
Evidence is under `C:\Users\domainadmin\.tmp\q29-sccm-report-check`.

SQL's affected command/resource/metadata checkpoint passed 43 checks before the
additional race test. All ten focused graph-check tests then passed, including
that final resource-stop precedence case. SQL Ruff and mypy passed (56 source
files). Real ZIP controls cover both lost and added nodes, retained status 3,
broken ZIPs, implied stages, failed collection, and discovery-only rejection.

The actual read-only owner-identity ps1-db command collected and converted
successfully (collection status 0, 193 nodes/583 relationships) and correctly
returned **1** for a baseline regression. Saved raw permissions changed from
6,938 to 6,932 rows: six removed and none added. The graph report identifies the
matching `explicitPermissions` shrink on `smsschm_users` in `CM_PS1`. This is
observed saved-data drift; its lab cause is not established. No baseline or gate
was weakened. A same-input graph/ZIP comparison returned 0. Safe evidence is
`comparison-live-raw-audit.json`, `comparison-self-control.json`, and
`comparison-lab-console.txt` under the private task root, with graph/report output
in `.tmp/q29-comparison-lab`. The command used an explicit 99% memory limit to
isolate comparison from unrelated host load; the normal default remains 90%.
No lab object, setting, policy, or service was changed.

## Manual checks and owner review

Run in each declared environment, with fresh short Windows pytest temporary
paths and separate logging directories:

```powershell
# Common
uv run pytest tests/test_requested_checks.py -q
uv run ruff check src tests
uv run mypy src

# SCCM
uv run pytest tests/collect_exit_code_test.py tests/integration_cli_flags_test.py tests/extension_metadata_test.py tests/integration_wiring_test.py tests/convert_pipeline_test.py tests/integration_fixtures_test.py -q

# SQL
uv run pytest tests/unit/test_graph_checks.py tests/unit/test_run_all.py tests/unit/test_resource_limits.py tests/unit/test_command_controls.py tests/test_extension_methods.py -q
uv run openhound collect mssql .\comparison-check -t ps1-db.mayyhem.com:1433 -d mayyhem.com --dc 10.10.10.100 --compare-to-zip .\previous\graph\mssql_collection.zip
```

For SCCM's existing integration run, open the timestamped `.html` results file
locally, or inspect its matching JSON. Requesting both test flags now attempts
both reports even when one input is unreadable. A fresh report path is required;
an old file is preserved and produces failure rather than silent reuse.

Suggested owner commits after reviewing all overlapping changes:

```powershell
# Common
git add src/openhound_collector_common/integration_testing/validation.py src/openhound_collector_common/integration_testing/reports.py tests/test_requested_checks.py README.md docs/changes/2026-10-29-requested-checks-and-reports.md
git commit -m "Attempt independent graph checks and write readable case reports"

# ConfigManBearPig
git add src/openhound_sccm/main.py src/openhound_sccm/integration/__init__.py tests/collect_exit_code_test.py tests/integration_wiring_test.py README.md ARCHITECTURE.md
git commit -m "Preserve both requested checks and add HTML integration results"

# MSSQL
git add src/openhound_mssql/integration/__init__.py src/openhound_mssql/main.py src/openhound_mssql/extension.yaml tests/unit/test_graph_checks.py README.md ARCHITECTURE.md docs/changes/2026-10-23-feature-completion-status.md
git commit -m "Compare completed MSSQL output while retaining truthful run status"
```

The agent performed no staging, commits, pushes, publication or core edits.
One reviewed common release, final consumer dependency floors and ordinary
installation acceptance are still pending.
