# openhound-collector-common

Shared **Python** infrastructure for OpenHound on-prem / Windows-auth
collectors. Factored out of the SCCM extension so collectors (starting with `mssql`) reuse
one implementation of the hard parts instead of copying them.

Current-user and explicit-credential WMI run inside the collector. Optional read
controls request cancellation and wait for actual cleanup; Windows can overrun
the requested time. No native database/auth binary is added: TDS, NTLM, Kerberos, EPA channel
binding, SPNEGO, LDAP, WMI, and SOCKS5 are all done in Python via `impacket` / `ldap3` /
`pywin32` and the stdlib.

The missing-service SQL EPA probe changes only its own NTLM message; it never
changes impacket's process-wide test setting. Concurrent ordinary logins retain
their service names. This working-tree fix benefits both MSSQL and CMBP and is
part of the planned reviewed shared release. See the
[implementation and verification record](docs/changes/2026-10-29-ntlm-probe-isolation.md).
The separately approved hash-input fix decodes LM/NT hexadecimal values only at
the NTLM provider boundary; Kerberos keeps its existing text inputs. Password
and hash logins passed in both consumer environments; full acceptance remains pending.

## Layout (built incrementally)

| Subpackage | Purpose |
|---|---|
| `clients/mssql.py` | TDS + TLS-over-TDS + NTLMv2 (EPA CBT/SPN) + Kerberos + SSPI; EPA detection. TLS-1.2 cap. |
| `clients/auth.py` | Kerberos AP-REQ/SPNEGO + NTLM + current-user SSPI token minting. |
| `clients/ad.py` | LDAP transport×bind waterfall (lockout-safe), SPN search, SID→AD-object resolution. |
| `clients/wmi.py` | WMI over impacket DCOM + pywin32 (`Win32_GroupUser`, `Win32_Service`). |
| `clients/operations.py` | In-process read budgets, stop requests, provider interruption and visible timeout overruns. |
| `clients/kerberos_io.py` | Opt-in owned Kerberos ticket sockets, inherited read budgets and scoped provider restoration; no process or new authentication implementation. |
| `clients/wmi_session.py` | Exclusive same-host explicit WMI sessions through complete result and connection cleanup. |
| `clients/windows_ldap.py` | Optional current-user Windows LDAP fallback, paged native reads, copied raw attributes and owned-handle cleanup. |
| `clients/identity_errors.py` | Definite Windows account-rejection detection, including wrapped SSPI status and WMI automation errors. |
| `clients/credential_guard.py` | One run's shared record that its sign-in details were rejected. Clients check it before signing in and report definite rejections; the first report stops the run. |
| `clients/kerberos.py` | Run-local identity selection from base64 KRB-CRED, MIT cache v3/v4 or keytab v2; exact service/port matching and one guarded keytab TGT acquisition. |
| `clients/ldap_kerberos.py` | Explicit Kerberos bind on a normal ldap3 connection; certificate channel binding over TLS and impacket sealing for plain LDAP. |
| `collection/registry.py` | Shared target indexes, the name-only `matches_allowed_targets`, and `AllowedTargets`: an allowed-target list of names, single addresses and IP ranges that returns an allowed/refused decision with a plain reason. Never looks anything up; callers pass the addresses they found. |
| `discovery/dns.py` | DC/SRV/A discovery + DNS resolver override (proxy-aware). |
| `discovery/network.py` | Run-wide forward/reverse DNS and SOCKS selection, exact socket restoration, and TCP reachability checks. |
| `discovery/domain.py` | Explicit/credential/Windows domain selection and target suffixes verified through LDAP DNS records. |
| `clients/deadline.py` | Opt-in elapsed-time socket deadline shared across connection attempts; interrupts a stalled peer without terminating worker threads. |
| `dlt/progress.py` | Shared `off`, `tqdm`, `log`, and `alive_progress` choices; preserves SCCM's existing tracker behavior. |
| `dlt/source_bridge.py` | push→pull DLT emit-resource bridge for multi-target collection. |
| `collection/records.py` | Explicit safe run settings and a row writer that preserves run/target ownership. The caller defines target identity; neither collector is imported. |
| `collection/methods.py` | Shared comma/case method parsing and phase checks. Each collector owns valid names, dependency rules and defaults. |
| `dlt/duckdb_safe.py` | `_safe`/`_ensure_columns`/`_arr` defenses against dlt column-dropping. |
| `logging/log_context.py` | VERBOSE tier + `[target]`/`[phase]` contextvar tagging. |
| `logging/console.py` | Opt-in Go-style UTC console formatter, ordered detail fields, terminal colors, and secret redaction. Importing it does not change existing logging defaults. |
| `logging/files.py` | Promoted SCCM full/issues handlers and scoped `RunFileLogs` lifecycle. Spools unfinished groups to private files, preserves completion order, supports optional target files, redacts secrets, restores handlers/levels, and reports write failures. |
| `graph/stub_node.py`, `graph/graph_edge.py` | generic edge model + edge-endpoint stub backfill. |
| `graph/evidence.py` | Optional `collectionSource`, `assumed`, and `assumptionBasis` dataclass fields. Keeps ordered unique source tags and requires a reason for an inference; each collector owns its evidence rules. |
| `graph/files.py` | Bounded local graph writer with explicit custom/native source labels, staged publication, and manifests for retiring only its own older parts. No second DLT pipeline or collector-specific routing. |
| `proxy/socks.py` | pure-Python SOCKS5 dialer. |
| `proxy/patch.py` | Scoped Python TCP interception, including DNS clients using `connect_ex`. SOCKS handshakes have one elapsed-time deadline and never retry directly. |
| `orchestration/run.py` | After convert, `run_end_to_end` flat-zips the emitted graph `*.json` into the graph dir (name from `graph_zip_name`, default `<app.name>_collection.zip`), ready for BloodHound File Ingest (loose files kept), and reports it back on `StagePaths.graph_zip` — the archive that was **written**, or `None` if convert emitted no `*.json`. `derive_stage_paths` leaves it `None`, since it runs before anything exists (including on a collector's failure path). |
| `orchestration/artifacts.py`, `orchestration/commands.py` | Inspect previous load packages, warn or clean only caller-named reusable artifacts, retain logs/reports, and print usable continuation paths. Validate resolved deletion boundaries before removing anything. |
| `orchestration/arguments.py` | Suspicious parsed-option hints, with caller-supplied options and sensitive-value rules. Changes no parsing or logging defaults. |
| `orchestration/resources.py`, `orchestration/scratch.py` | Opt-in sampled system-memory and owned-data limits, separate log/ZIP totals, scoped provider interruption and private scratch cleanup. Existing collectors acquire no limits automatically. Uses the approved BSD-licensed psutil memory reader. |
| `integration_testing/` | Collector-agnostic assert-and-diff engine: payload loader (dir or zip), pattern matcher, fixture case runner, schema coverage, property-level comparator, independent requested checks, and HTML/JSON case reports. |

## Consumers

`RunResources(stop_event=..., max_data_bytes=..., memory_threshold=...)` from
`orchestration.resources` samples at entry and once per second. Register explicit
artifact paths before writing; `include_existing=True` deliberately counts a
verified saved input. Unchanged old files are excluded, changed files count at
their full current size, and overlapping paths count once. Explicit path categories
support log spools without filename extensions. `check()` raises on a reached
limit; `check(sample_now=True)` first measures again. A reached limit sets the
caller-owned stop event and retains complete records. A measurement/interruption
failure is a failed run. The monitor thread is joined on exit.

`private_scratch(prefix=..., parent=..., resources=...)` creates and registers a
new private child before work, then removes only that child. Put final output
elsewhere. A locked Windows file makes cleanup fail visibly. The optional
`resources` parameter on `GraphFileWriter` publishes complete current parts on an
intentional stop; ordinary generation errors preserve previous files. The same
option on `zip_graph_output` checks during copying and publishes only a finished
archive, preserving loose files and any previous archive on failure. Use
`interruptible(label, owned_provider_stop)` only with a provider whose stop call
supports a second thread; callbacks cannot outlive that scope.

These are sampled stop requests, so active batches/native calls can overrun.
Logs and ZIP copies have separate size totals and do not consume the data cap.
The memory reader uses `psutil>=7.2.2` (`virtual_memory().percent`), a direct
BSD 3-Clause dependency with prebuilt Windows/Linux/macOS packages. MSSQL opts in;
SCCM keeps its defaults. See [the implementation record](docs/changes/2026-10-28-run-resource-limits.md).

Collectors that stream rows from multiple targets can wrap their bridge in
`TargetRowWriter(bridge, run_id=run_id, target_id=target_id)`. Its `put(table, row)`
copies the row and adds `collection_run_id` and `collection_target_id`, rejecting
conflicting reserved values. `RunDescription(run_id, settings).as_row()` supplies
a flat, versioned row containing JSON settings. Select safe settings explicitly;
never save a whole configuration or authentication object. Register both records
through the collector's normal raw-table resources. SQL graph identities and the
decision about which graph switches to save remain in the SQL collector.

`OperationResult`, `TargetResult`, and `RunResult` record successful empty reads,
failed reads with unknown counts, final target states, and run totals. They
validate inconsistent states but leave exit policy to each collector. Supply
safe operation labels and authored reasons; never store SQL text, credentials,
or raw exception messages in those records. Attach ownership with the existing
row writer. SCCM's exit behavior is unchanged.

An opted-in SQL/LDAP/WMI `ReadOperation` also supplies its remaining time to
nested ticket requests. `clients.kerberos_io.kerberos_exchange` changes only
impacket 0.13.1's module-local socket reference while controlled calls are active;
the ordinary Python socket module remains the existing DNS/SOCKS boundary. Each
thread owns its own ticket sockets. Other calls keep their existing policy, and
the previous provider reference is restored after the last controlled call.
`KerberosCredentials.prepare(..., read_control=...)` can bound keytab preparation
before workers start. No control is imposed on existing consumers by default.

`make_resolver(..., read_control=...)` and `network_session(..., read_control=...)`
bound DNS calls through dnspython's public lifetime setting. `check_tcp_port`
accepts the same opt-in argument and bounds DNS plus all address attempts together.
DNS honors a shorter parent read budget, checks stop requests before/after each
lookup, and finishes an in-flight bounded query rather than closing unowned DNS
sockets. Owned TCP and Kerberos sockets are shut down and closed on a stop.
Cleanup failure remains fatal. See [the setup-limit record](docs/changes/2026-10-29-connection-setup-limits.md).

`StreamBridge(..., strict_tables=True)` makes an unregistered table name an error
instead of the default warning. `bridge.cancel(reason)` releases producers
waiting on full queues and closes empty consumers without another DONE marker;
buffered rows can still drain. Producers receive `CollectionStopped` on a later
write. The caller still owns network-client interruption and worker shutdown:
queue cancellation does not terminate a remote API call.

`collection.work_queue.WorkQueue` and `collection.scheduler.run_jobs` track
queued and active targets, reject duplicates and run a fixed number of worker
loops. Zero workers runs on the calling thread. A completion callback runs before
its target is marked complete, so recursively discovered work cannot be missed.
Every background result is checked. A failure stops pending work, notifies the
caller and waits for active work and cleanup before raising the original error.
`unstarted_targets()` retains the pending targets removed by a stop.

`collection.engine` supplies ordered per-target phases over that scheduler.
Ordinary phase errors are logged and other phases continue; `FatalCollectionError`
(including failed client cleanup and cancelled output) fails the run. Callers
pass `emit=bridge.put`, `finish=bridge.broadcast_done` and a failure callback that
cancels the bridge to release blocked output producers. The scheduler cannot
force a native provider to return; cancellation still belongs to each client.

`collection.registry.TargetRegistry` provides locked identity/name indexes and a
read-only alias view. Callers retain the meaning of an identity and how evidence
merges: SCCM supplies SID/name rules; MSSQL supplies host/port/instance rules.
`matches_allowed_targets` compares caller-expanded candidates with an already
normalized allow-list. No shared helper invents aliases or strips SQL ports.
See the [scheduling change record](docs/changes/2026-10-27-shared-target-scheduling.md).

- **[ConfigManBearPig 2.0](https://github.com/SpecterOps/ConfigManBearPig)** (PyPI: `configmanbearpig`)
  — the SCCM collector. Depends on a published, capped release (`>=0.1.0,<0.2.0`).
- **`mssql`** — the in-progress MSSQL collector.

This is a library: it is never installed on its own by an end user. It arrives as a transitive
dependency when someone installs a collector:

```bash
uv tool install openhound --with configmanbearpig
```

It ships exactly one command, `openhound-compare` (below); everything else is imported, not invoked.

## `openhound-compare`

For collector commands, `integration_testing.validation.run_requested_checks`
attempts independent callbacks and reports before combining status. Failures,
absent/malformed reports and stale report paths fail visibly; other requested
checks are still attempted. `integration_testing.reports.write_summary_reports`
writes escaped, self-contained HTML beside case-summary JSON. Collectors keep
their own permission and assertion policies. See the
[design and verification record](docs/changes/2026-10-29-requested-checks-and-reports.md).

Diff two OpenGraph payloads down to property name and value. Installed with this package as a console
script — no collection and no framework CLI involved.

```bash
openhound-compare BASELINE CANDIDATE [--exact] [--check-raw] [--allowances PATH] [--json PATH] [-q]
```

Each side may be a `.zip` or a directory of `*.json` payloads, in any combination — an archived
baseline against a fresh `convert` output directory is the common case.

**Baseline is what came first.** A *regression* is anything present in the baseline and missing or
reduced in the candidate: a dropped node or edge, a lost property, a property emptied to
`null`/`""`/`[]`/`{}`, a list-valued property that lost items, or a property name that no longer
appears on a kind at all. Additions and ordinary value changes are reported under `ADDED` and do not
fail the run.

| Exit | Meaning |
|---|---|
| `0` | No regressions. Additions and value changes may still be reported |
| `1` | The candidate lost something the baseline had |
| `2` | A path was neither a `.zip` nor a directory, or could not be read |

There is no flag to disable the exit code. Comparing payloads from two *different* tools will normally
report regressions — each tool emits things the other does not — so a non-zero exit there means
"these differ", not "something broke".

Use `--exact` to require the same graph rather than merely the absence of losses:

```powershell
openhound-compare .\baseline.zip .\candidate\graph --exact --json .\comparison.json
```

Exact mode checks record counts, node kinds, endpoint matching rules, complete
properties (including their JSON types and list order), and each record's
`metadata.source_kind` file label. File names and record order may differ. Kind
labels are treated as an unordered set. Every relationship is retained, so
different login mappings between the same endpoints remain separate. Exact mode
returns `1` for an addition or changed value as well as a loss. The JSON report
contains `is_exact_match`, complete differing records, and any explicit allowances.

Before exact comparison, raw checks reject conflicting properties on repeated
node IDs, repeated JSON keys, identical repeated relationships, malformed graph
records, and non-graph JSON. An empty directory fails; an explicitly empty graph
file is valid. Complementary node records and relationships with different
properties are allowed. `--check-raw` enables the same checks for the ordinary
loss-only comparison. Raw graph failure returns `1`; invalid paths/options return
`2`. Existing imports keep their previous loading rules unless their caller
selects `load_graph(..., validate_raw=True)`.

There are no automatic ignored properties. If a difference is intentional,
`--allowances` accepts a reviewed JSON list such as:

```json
[
  {
    "entity": "node",
    "kind": "MSSQL_Server",
    "property": "last_seen",
    "reason": "A fresh conversion creates a new collection timestamp",
    "mode": "ignore"
  }
]
```

Every allowance names one literal kind/property and includes its reason in the
report. `mode: "unordered"` compares a selected list without considering order
while still counting repeated values. Optional `object_id` limits the rule to
one node ID or one relationship's `start|kind|end` identity. Wildcard kind/property
exceptions are rejected. Review exceptions carefully; permissions, owners,
credentials, ports, and evidence are compared normally unless an explicit rule
names one of their fields. `--allowances` requires `--exact`.

## Developing

Directory logins recognize both `invalidCredentials` and `Invalid Credentials`
when accompanied by a known rejected-account code. A rejected password or account
stops the login attempts; later calls on that same client do not submit it again.
Other connection failures retain their existing retry choices. This applies with
and without optional read budgets. See the approved
[rejected-password fix](docs/changes/2026-10-29-ldap-rejected-password.md).

Every password bind now runs step by step, so a rejection keeps the domain
controller's reason code. Typed-in details rejected with no reason code at all
also stop. To stop a whole run after one rejection, create one
`CredentialGuard` per run and pass it to every `AdClient` and `WmiClient`.
Call `AdClient.confirm_credentials()` once before visiting any computer, and
register a stop action, such as stopping the work queue, with
`add_stop_action`. See
[stop the whole run after one rejected sign-in](docs/changes/2026-10-30-one-rejected-sign-in-per-run.md).

```python
from openhound_collector_common.clients.ad import AdClient, LdapAuth
from openhound_collector_common.clients.credential_guard import (
    CREDENTIALS_REJECTED_REASON, CredentialCheck, CredentialGuard,
)

guard = CredentialGuard()
guard.add_stop_action(lambda: work_queue.stop(CREDENTIALS_REJECTED_REASON))
directory = AdClient("mayyhem.com", dc="dc.mayyhem.com",
                     auth=LdapAuth(username="MAYYHEM\\lowpriv", password="password"),
                     credential_guard=guard)
if directory.confirm_credentials() is CredentialCheck.REJECTED:
    raise SystemExit(1)  # One failed sign-in, and nothing else was tried.
```

The [additional reference contracts](docs/changes/2026-10-29-reference-logging-and-native-values.md)
check logger fan-out and exact Windows domain/SID examples through existing
Python boundaries. They change no runtime behavior and require no lab connection.

SQL and Python LDAP clients also accept opt-in `ReadControl` budgets. Pass the
same target `Deadline` and stop event to `MssqlConnection(read_control=...)`,
`detect_epa(..., read_control=...)` and `AdClient(..., read_control=...)`.
LDAP's read budget covers bind plus all search pages. SQL can select a separate
`query(..., timeout_seconds=...)` budget, retaining the target deadline. A stopped
read closes only its owned connection, waits for cleanup and raises
`ReadStoppedError`; failed cleanup raises `ClientCleanupError`. Existing callers
without these controls retain their prior timeout policy. See the
[read-limit record](docs/changes/2026-10-27-sql-and-ldap-read-limits.md) for Windows
timed-socket behavior, native overruns, remaining setup limits and verification.

Current-user Windows WMI initializes and releases Windows COM on its connecting
thread. Keep an in-process WMI client on that worker through cleanup. Native current-user WMI does not use Python's
SOCKS sockets; collectors must skip or reject that combination.

To request cancellation of a slow current-user or explicit-credential read:

```python
from openhound_collector_common.clients.operations import ReadControl
from openhound_collector_common.clients.wmi import WmiClient

client = WmiClient("ps1-db.mayyhem.com", read_control=ReadControl(30))
try:
    rows = client.query("SELECT Name,StartName FROM Win32_Service WHERE Name='MSSQLSERVER'")
    outcome = client.last_query_result
finally:
    client.close()
```

The read budget includes waiting for a host, authentication, query and results.
The monitor samples every 50 ms and requests cancellation until the read and its
cleanup return. It never kills or abandons a thread. Windows connection/provider
calls can overrun that request, delaying final exit; this is not a guaranteed
stopping time. Complete rows received before failure remain available, with an
unknown total row count and a failed `last_query_result`. An optional `on_query`
callback receives that same non-secret outcome. `ClientCleanupError` must fail
the run rather than be hidden by a best-effort fallback.

`ReadControl` also accepts a target `Deadline` and thread stop event. The shorter
budget wins. Native Windows object creation, reads and release stay on one
thread. Explicit WMI uses a whole-read host lease because impacket stores its
credentials by hostname: another client waits until result iteration and cleanup
finish. Each read closes its namespace connection; no process-wide keepalive
thread or idle connection remains between reads. Different hosts remain
independent. Complete-object reads use `read_instance(namespace, object_path)`.
Use `network_session` for selected Python DNS/proxy settings. Native current-user
WMI rejects SOCKS. SCCM uses the same session protection and complete-object
boundary while retaining its existing authentication ladder and timeout policy.

For collectors that explicitly select the Windows AD fallback:

```python
from openhound_collector_common.clients.ad import AdClient
from openhound_collector_common.clients.operations import ReadControl

client = AdClient("mayyhem.com", "dc.mayyhem.com", native_fallback=ReadControl(30))
try:
    computers = client.enumerate_computers()
finally:
    client.close()
```

Normal ldap3 remains first. An eligible current-user connection/authentication
failure before any returned rows can select Windows LDAP; explicit credentials,
rejected accounts, SOCKS and non-Windows systems never do. Later searches keep
that selected backend. `selected_backend` identifies it, and saved query outcomes
use `Windows LDAP search`. Binary SIDs/GUIDs, multi-value and missing attributes
use the normal AD conversion rules. The selected DC and port are retained;
standard TLS ports use Windows certificate checks. Additional search controls
and ranged attributes are refused visibly, with an incomplete outcome, rather
than silently losing information. A native entry larger than 16 MiB also fails
visibly. Timeouts request a stop and can overrun while Windows returns control.
The fallback creates no child process or temporary credential file. Existing
consumers do not acquire this fallback implicitly.

`socks_proxy_installed(proxy, connect_timeout=15)` bounds the proxy connection and
handshake. A caller's shorter positive socket timeout wins. A socket requesting
immediate return still waits for the bounded SOCKS handshake; its original mode
is restored on success. DNS uses TCP inside the same proxy session. Connections
to local loopback listeners and the proxy's own endpoint retain their local
exception; other ports on the proxy host remain proxied.

You need a **system Python 3.13 or 3.14 on `PATH`**, plus [`uv`](https://docs.astral.sh/uv/).
`pyproject.toml` sets `python-preference = "only-system"`, so uv will not download an interpreter for
you — it fails with *"No interpreter found for Python >=3.13"* rather than fetching one. That is
deliberate: uv's bundled CPython ships a `libcrypto` without the `OPENSSL_Applink` shim, and on Windows
any TLS handshake — LDAPS, MSSQL TDS — aborts the process. The constraint is not Windows-only, which is
why CI provisions Python explicitly instead of relying on the runner's default.

```bash
git clone git@github.com:Mayyhem/openhound-collector-common.git
cd openhound-collector-common
uv sync --group dev
```

### Run the checks

These three are exactly what [`ci.yml`](.github/workflows/ci.yml) runs, so a green local run means a
green pull request. Unlike a collector's curated subset, the whole test directory runs offline — no lab,
no fixture database. The one test that opens a socket binds a loopback echo server.

```bash
uv run ruff check src tests
uv run mypy src/openhound_collector_common
uv run pytest tests -q
```

### Working on this library and a collector at once

Editing here and testing there needs a live link, not a reinstall after every change. Clone the two as
**siblings** — the path is resolved relative to the collector's `pyproject.toml`, so the layout is
load-bearing:

```
~/Desktop/ConfigManBearPig/              a collector
~/Desktop/openhound-collector-common/    this library
```

Then add this to the **collector's** `pyproject.toml`, immediately above `[tool.uv]`:

```toml
[tool.uv.sources]
openhound-collector-common = { path = "../openhound-collector-common", editable = true }
```

**Do not commit that.** A committed path redirect breaks every environment without the sibling checkout,
starting with the collector's CI, whose runner checks out that repository alone. Keep git from staging
it, then sync:

```bash
git update-index --skip-worktree pyproject.toml
uv sync --group dev
```

Two alternatives that look right and are not, both tested: `uv pip install -e ../openhound-collector-common`
installs a **copy**, so your edits are invisible and the next `uv sync` silently reverts it to the
published version; and `[sources]` in a gitignored `uv.toml` is rejected outright — *"`sources` is only
applicable in the context of a project"*.

### Releasing

The tag **is** the release. `hatch-vcs` derives the package version from it, so there is no number to
bump by hand and nothing to upload manually:

```bash
git tag -a v0.1.3 -m "what changed"
git push origin v0.1.3
```

Pushing a `v*` tag triggers [`release.yml`](.github/workflows/release.yml), which builds, asserts the
built version matches the tag, and publishes to PyPI through trusted publishing. The job runs in the
`pypi` GitHub environment, so a required reviewer there turns each release into a deliberate click.
PyPI filenames are immutable — a tag on the wrong commit burns that version number permanently.

### Blast radius

Two collectors consume this package, so a change here is never local to one of them. Both pin a capped
range (`>=x.y.z,<0.2.0`), which means a patch release reaches them on their next lock refresh — not on
publish. Treat any change to a shared signature or output format as breaking for **both**, even when the
version number says patch.

## License

Apache-2.0 (see [LICENSE](LICENSE)). This code was factored out of the SCCM collector, itself a port of
the Apache-2.0 `ConfigManBearPig.ps1`, so it inherits those terms.
