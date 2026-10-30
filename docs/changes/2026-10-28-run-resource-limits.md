# Sampled run limits and private temporary files

Implemented October 28–29, 2026 under the approved feature-completion proposal.
This feature is complete at its bounded checkpoint; the overall three-tool
initiative and published-package acceptance remain unfinished.

## Problem and selected approach

The collector accepted a memory setting without enforcing it and lacked a data
size limit. DLT can create large intermediate files before final raw data or a
graph appears. Watching only final output misses that disk usage. Stopping by
killing a worker risks an incomplete JSON document, abandoned credentials or
uncertain native cleanup. Pausing indefinitely makes completion unpredictable.

The owner selected a sampled stop: stop starting work, signal active reads,
retain complete records, join their owners and report incomplete results. Common
owns measurements and file mechanics because they are useful to both collectors;
MSSQL owns artifact choices, saved settings and exit policy. SCCM does not opt in
and keeps its existing limits, locations and graph behavior. Core is unchanged.
No schema changes or new collection helper processes are introduced here.

Hard operating-system memory limits, repeated platform-specific memory readers,
thread termination and deleting completed output were not selected. They either
change process-wide behavior, duplicate supported library work or threaten the
saved evidence. A sampled request can overrun and is described honestly.

## How it works

- [resources.py](../../src/openhound_collector_common/orchestration/resources.py)
  parses positive decimal `B/KB/MB/GB/TB` and binary `KiB/MiB/GiB/TiB` sizes.
  `RunResources` samples at entry, once per second and at explicit boundaries.
  Its non-daemon monitor is joined on exit. A reached limit has a sticky safe
  reason and sets the caller's stop event. Failed measurement/interruption is a
  failure, not a normal partial result. No worker is killed.
- Paths are registered before writes. Unchanged existing files are excluded;
  a changed file counts at full current size. Saved stages explicitly adopt
  their selected existing input. Overlapping roots count once; separate physical
  copies still both occupy disk and count. Linked files/directories are rejected
  during accounting. Only declared artifacts are scanned, not a user home/tree.
- Raw data, DLT state, prepared lookup database, WAL/spills and loose graph parts
  count toward the data budget. Logs and ZIP copies have separate totals. An
  explicit closest-path category handles log spools with no `.log` extension.
  `RunFileLogs.owned_log_paths` exposes only this invocation's paths. Peaks remain
  after temporary files are removed. Reports precede final log flushing, which
  can change the on-disk log size afterward.
- [scratch.py](../../src/openhound_collector_common/orchestration/scratch.py)
  creates a new private child under the selected parent, verifies the parent,
  registers it before writes and removes only that child. A locked Windows file
  raises cleanup failure. Final raw and graph output lives elsewhere. SQL uses
  per-pipeline DLT configuration and per-connection DuckDB spill settings, not a
  late process-wide temporary-directory change. Kerberos inputs stay in memory.
- SQL shares one monitor through `--run-all`. Its pending targets get explicit
  stopped outcomes. DLT finishes accepted batches; preparation checks before
  accepting another input batch. Its owned graph-calculation connection registers
  `interrupt()` only during that operation. A short guard prevents a queued late
  callback from interrupting a later user of the connection. Provider setup and
  cleanup can still overrun; there is no hard final-exit guarantee.
- [graph/files.py](../../src/openhound_collector_common/graph/files.py) publishes
  complete current parts on an intentional resource stop, removes only previous
  parts in its validated ownership manifest and propagates the stop. Ordinary
  model/write failure preserves previous complete output. JSON is never cut off
  to fit a byte limit. The largest ordinary buffered part is eight MiB or 1,000
  records per prefix/entity; one larger record gets a part of its own. The final
  part/batch and concurrent writers can exceed a selected threshold.
- [run.py](../../src/openhound_collector_common/orchestration/run.py) checks before
  a controlled archive, between one-MiB copies and before publication. It writes
  an owned `.zip.tmp`, renames only a complete archive, and removes only its own
  temporary file on failure. Loose files and an older archive remain. A limit
  may prevent a new ZIP; an older ZIP is not evidence of the current run.

SQL's `resource_limits.py` selects artifacts and reads the explicit saved run
description before standalone preparation/conversion. Mixed run/settings metadata
is rejected. `--file-size-limit` and `--memory-threshold` override saved limits;
defaults are `1GB` and system memory `90%`. Preparation also accepts `--temp-dir`.
Standalone conversion counts the selected prepared database as input. Missing
legacy metadata produces a warning and uses explicit/default limits. SQL saves
the safe reason, current and peak measurements in `collection-status.json`.
Usable saved target rows give exit 3 on a limit; no usable rows give 1. Actual
measurement/write/cleanup/stage failures give 1 and take precedence. This is not
a new collection policy in common's generic result records.

## Dependency and provider evidence

The owner approved `psutil` including its compiled component. Common declares
`psutil>=7.2.2` directly; version 7.2.2 was already locked transitively. Only its
direct dependency metadata was added to the existing lock; unrelated pins were
kept. Existing consumers do not start a monitor by importing the package.
Its [BSD 3-Clause license](https://github.com/giampaolo/psutil/blob/release-7.2.2/LICENSE)
is compatible with Apache 2.0; distributed wheels retain the upstream notices.
The locked distributions include Windows, Linux and macOS wheels for the declared
Python range. Actual Python 3.14/platform installation acceptance is still part
of the initiative's final package checks.

The tested environment uses official CPython 3.13.15, psutil 7.2.2, dlt 1.26.0 and
DuckDB 1.5.2. The narrow psutil import boundary converts to `float` and validates
the range before use; its package has no built-in typing marker. The exact
installed DuckDB patch and tool versions are recorded in the isolated validation
project locks. See the [psutil 7.2.2 memory API](https://psutil.io/7.2/#psutil.virtual_memory)
and [DuckDB Python interrupt API](https://duckdb.org/docs/1.5/clients/python/reference/#duckdb.DuckDBPyConnection.interrupt).
DLT's installed `DuckDbCredentials.global_config` supplies per-database settings;
the real DLT checks establish its use with this installed SDK version.

## Validation and manual checks

Common's full suite passed **451 tests**, with one explicit Python-version skip.
SQL's final unit/registration/real empty and saved-bucket stage selection passed
**313 tests**, with one unavailable-old-live-artifact skip. SCCM's affected queue,
stream, graph, split-output and run-all selection passed **42 tests**. These are
bounded feature checks, not all-tools final integration acceptance. Shared and
SQL lint/type checks passed before final documentation/formatting; final command
evidence is tracked in the SQL implementation status.

The new checks inject memory readings rather than exhaust the host. They cover
size units/validation, old/overlapping files, separate log/archive categories,
sticky stops/peaks, measurement/interruption failures, late callbacks, owned
scratch and Windows locked-file cleanup. Graph/ZIP checks parse retained JSON,
preserve unrelated files and an older archive, and reject an unfinished archive.
SQL checks include a real interrupted DuckDB calculation, real DLT batch stop,
pending-target inventory, saved limits/overrides and invalid size before cleanup.
The SDK's own `Collector.resources` table list originally overwrote a same-named
monitor field; the adapter now uses `run_resources`. Regression checks passed.

Live evidence under the task's private work directory:

- The actual 90% guard stopped a live SQL run at 90.9%, retaining 6,301 rows,
  returning 3 and skipping graph stages. `resource-limit-live-stopped.json`
  preserves the status; raw files/logs remain in `.tmp/q28-resource-lab`.
- A separate explicit 99% run completed with 7,246 rows, 47 completed reads,
  zero failed reads, 193 nodes and 583 relationships. Its status records about
  23.6 MB peak data and a completed ZIP. The live exact graph gate correctly
  rejected differences against the older baseline: saved raw permissions contain
  six additional grants and permission ordering changed. No comparison allowance
  was broadened and no lab policy/data was changed by these checks.
- A private copy of the earlier saved raw collection was prepared/converted with
  networking refused. It emitted 193 nodes/583 relationships and **zero exact
  differences** after only the already declared per-kind timestamp allowances.
  `resource-limits-cached-graph-audit.json` records that comparison. The original
  raw collection and graph baseline were not modified.

In each repository's declared environment, use a fresh short `--basetemp` on
Windows and a separate `RUNTIME__LOG_PATH`. Relevant commands:

```powershell
# Common
uv run pytest tests/test_run_resources.py tests/test_graph_files.py -q
uv run ruff check src tests
uv run mypy src

# MSSQL
uv run pytest tests/unit/test_resource_limits.py tests/unit/test_stage_state.py tests/integration/test_empty_run_all.py tests/integration/test_saved_bucket_commands.py -q
uv run ruff check src tests/unit/test_resource_limits.py
uv run mypy src

# SCCM
uv run pytest tests/collect_run_all_test.py tests/convert_split_output_test.py tests/graph_edges_split_test.py tests/graph_mssql_props_test.py tests/pp_engine_test.py tests/pp_work_queue_test.py tests/pp_streams_test.py tests/per_host_phases_streams_test.py -q
```

Authorized lab operators can manually collect and inspect the status:

```powershell
uv run openhound collect mssql .\resource-check --targets ps1-db.mayyhem.com:1433 --domain mayyhem.com --dc 10.10.10.100 --file-size-limit 1GB --memory-threshold 90 --temp-dir C:\Users\domainadmin\.tmp\mssql --run-all --clean
Get-Content .\resource-check\collection-status.json
uv run openhound preprocess mssql .\resource-check .\resource-check\lookup.duckdb --file-size-limit 2GiB --memory-threshold 95
uv run openhound convert mssql .\resource-check\mssql .\resource-check\graph --lookup-file .\resource-check\lookup.duckdb --file-size-limit 2GiB --memory-threshold 95
```

Use the injected fault tests to force limits; do not exhaust real memory/disk.
Partial evidence can omit later collection reads. An interrupted preparation
database is not a completed graph input: repeat preparation before converting.

## Owner review and commit suggestions

Review this together with the earlier shared scheduler/read controls because the
files overlap. Suggested messages: `Add sampled run limits and private scratch`
for common and `Apply resource limits to SQL collection and saved stages` for SQL.
The owner stages/commits manually after reviewing the complete files. No Git
staging, commit, tag, push or release was performed. Examples, run separately in
the named repositories after that review:

```powershell
# Common: these whole files also contain preceding approved initiative changes.
git add src/openhound_collector_common/orchestration src/openhound_collector_common/graph/files.py src/openhound_collector_common/logging/files.py src/openhound_collector_common/collection/outcomes.py src/openhound_collector_common/collection/scheduler.py tests/test_run_resources.py pyproject.toml uv.lock README.md docs/changes/2026-10-28-run-resource-limits.md
git commit -m "Add sampled run limits and private scratch"

# MSSQL: review the complete initiative diff before staging overlapping files.
git add src/openhound_mssql/resource_limits.py src/openhound_mssql/runtime.py src/openhound_mssql/main.py src/openhound_mssql/auth.py src/openhound_mssql/workflow.py src/openhound_mssql/cli_stages.py src/openhound_mssql/convert_pipeline.py src/openhound_mssql/extension.yaml src/openhound_mssql/collection/run.py src/openhound_mssql/collection/status.py tests/unit/test_resource_limits.py tests/unit/test_command_controls.py tests/integration/test_empty_run_all.py tests/integration/test_saved_bucket_commands.py README.md ARCHITECTURE.md docs/changes/2026-10-23-feature-completion-status.md
git commit -m "Apply resource limits to SQL collection and saved stages"
```

No consumer dependency floor is guessed here. The owner reviews and publishes one
combined common release after final consumer acceptance; published version floors,
ordinary installs and the final lock updates follow that release.
