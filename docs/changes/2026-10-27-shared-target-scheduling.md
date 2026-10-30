# Shared target indexes and scheduling

## Problem and approved scope

SCCM and MSSQL both track targets and feed concurrent collection into bounded
output queues. Separate queue and scheduling code lets failure handling drift.
SCCM's old phase runner caught every ordinary exception, including failed client
cleanup, and did not inspect submitted worker results. Its producer thread could
fail while DLT successfully drained an empty stream. That could report success
for an incomplete collection.

The feature-completion plan already approved promoting this reusable machinery
to common and adapting SCCM. Its service rules stay in the collectors. There is
no change to graph kinds, properties, traversal rules or OpenHound core.

## How it works

- [registry.py](../../src/openhound_collector_common/collection/registry.py)
  holds identity and alias indexes under a reentrant lock. The collector holds
  that lock over a complete lookup/merge/register decision. Read-only alias views
  keep a previously queued name usable after a record gains a better name.
  SCCM still decides SID/name equivalence and merges source/site evidence;
  MSSQL still distinguishes host, port and instance. The allowed-target helper
  receives names expanded by the collector and a pre-normalized allow-list.
- [work_queue.py](../../src/openhound_collector_common/collection/work_queue.py)
  tracks pending, active and already-seen targets. A discovering worker submits
  new work before releasing its active slot. Only an empty pending list with no
  active work means normal completion. A stop wakes waiting workers, prevents
  new work and retains the pending targets in `unstarted_targets()`.
- [scheduler.py](../../src/openhound_collector_common/collection/scheduler.py)
  submits one loop per worker, rather than one future per target. Zero workers
  runs on the calling thread. It checks every worker result, calls the completion
  callback before releasing the target slot, and records the first failure.
  Failure notifies the collector immediately so it can cancel blocked output
  writes. All active workers are joined before the first error is raised.
- [engine.py](../../src/openhound_collector_common/collection/engine.py) runs
  caller-defined phases in order. Ordinary per-phase errors still log and allow
  later phases. A `FatalCollectionError`, including `ClientCleanupError` and
  `CollectionStopped`, escapes. Phase generators close on stop or failure.

SCCM's local engine and queue modules are now re-exports. Its main command passes
the bridge's cancellable writer, completion and failure callbacks. A producer
failure is captured on the joined, non-daemon producer thread and raised before
the final principal table or later stages. WMI setup, lazy-object reads and
privileged collection also pass fatal cleanup failures through their ordinary
best-effort error handlers. This is the recommended CMBP correction discovered
during the WMI work; it is included in this approved scheduling adaptation.

MSSQL uses the same scheduler with its local endpoint key and outcome policy.
Its existing positive-worker handling for ordinary unexpected target errors
remains an explicit local decision. Fatal cleanup is never converted to an
ordinary failed-target result.

Queue cancellation does not stop a remote provider. Native calls can overrun a
requested stop; the scheduler waits for them and their cleanup. SCCM's existing
provider timeout policy is preserved. No child process, thread termination,
new external dependency or operating-system setting is introduced.

## Alternatives

Keeping copied schedulers would retain two failure paths to maintain. Moving
SCCM's SID/site rules or SQL's port/instance rules into common would make the
shared layer decide service behavior it cannot establish. Timing out a future
and abandoning its worker would leave authentication and cleanup running after
the command claimed to finish. The small shared queue/index/runner boundary
avoids those problems while leaving the service decisions readable locally.

## Verification and manual checks

The pre-change SCCM queue/engine/stream/wiring/allow-list and real DLT integration
baseline passed all 38 distinct tests. Its first attempt used an overlong Windows
test path; the six integration cases passed in a fresh short test folder.
After migration, 79 affected SCCM tests passed, including actual DLT handling of
a cleanup failure and cancellation of a producer blocked on a full output queue.
MSSQL's 288 existing unit checks passed; its new fatal-cleanup cases cover caller
thread and worker-pool modes. The shared tests cover recursive completion,
fixed future counts, first-failure preservation, queue failure, pending-work
inventory, full-output cancellation, generator cleanup and caller-owned names.
Common's full final checkpoint passed 412 tests with one Python-version skip.
SQL also captures producer interruptions, with a non-daemon joined producer;
an interruption must not leave DLT waiting for a completion marker that will
never arrive. Final SQL case counts are recorded in its feature status document.

Common lint and type checks pass for 57 source files. SQL lint and type checks
pass for 52 source files; the eight affected SCCM source files pass type checks
and their changed files pass lint. A WMI monitor test was changed to wait for its
cancellation event instead of assuming its thread ran during a short sleep.
Validation uses isolated environments and fresh short temporary folders; an
owner-created default pytest folder must not have its permissions widened.

After the reviewed shared release, in each project's declared environment:

```powershell
# Common: focused scheduler checks, followed by the full suite at the boundary.
uv run pytest tests/test_collection_scheduler.py -q
uv run pytest tests -q --basetemp=C:\Users\domainadmin\.tmp\common-scheduling-check

# SCCM: use a NEW short test folder, because pytest replaces --basetemp.
uv run pytest tests/pp_work_queue_test.py tests/pp_engine_test.py tests/per_host_wiring_test.py tests/per_host_failure_test.py tests/per_host_integration_test.py -q --basetemp=C:\Users\domainadmin\.tmp\sccm-scheduling-check

# MSSQL: no live credentials needed for these fault/ownership checks.
uv run pytest tests/unit/test_target_collection.py tests/unit/test_collection_outcomes.py tests/unit/test_collection_failure_controls.py -q
```

For live operator verification, collect one authorized lab endpoint with one and
several workers and inspect `collection-status.json` plus issues logs. SCCM can
use `--computers ps1-sms.mayyhem.com --collection-methods WMI --threads 2`; SQL
can use `--targets ps1-db.mayyhem.com:1433 --workers 2`. This feature has offline
fault injection and actual DLT tests; it does not assert completion of the full
initiative's final live matrix or published-package acceptance.

## Owner review and suggested commit

Suggested message: `Share target scheduling and surface fatal collection failures`.
Review each repository's full pending diff before staging; the files also contain
earlier approved feature work. Nothing has been staged, committed or pushed.

```powershell
# In common, after reviewing the full working diff:
git add src/openhound_collector_common/collection src/openhound_collector_common/clients/operations.py src/openhound_collector_common/dlt/source_bridge.py tests/test_collection_scheduler.py tests/test_wmi_inprocess.py README.md docs/changes/2026-10-27-shared-target-scheduling.md
git commit -m "Share target scheduling and surface fatal collection failures"

# In SCCM, review the overlapping earlier changes before using these paths:
git add src/openhound_sccm/phased_pipeline src/openhound_sccm/context.py src/openhound_sccm/main.py src/openhound_sccm/clients/wmi.py src/openhound_sccm/collectors/privileged.py tests/per_host_failure_test.py tests/per_host_integration_test.py tests/wmi_client_test.py README.md ARCHITECTURE.md
git commit -m "Use shared target scheduling and fail on unconfirmed cleanup"

# In MSSQL:
git add src/openhound_mssql/collection/run.py tests/unit/test_collection_outcomes.py README.md ARCHITECTURE.md docs/changes/2026-10-23-feature-completion-status.md
git commit -m "Use shared scheduling with SQL endpoint identity and failure policy"
```
