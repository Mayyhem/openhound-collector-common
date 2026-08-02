# openhound-collector-common

Shared **pure-Python, in-process** infrastructure for OpenHound on-prem / Windows-auth
collectors. Factored out of the SCCM extension so collectors (starting with `mssql`) reuse
one implementation of the hard parts instead of copying them.

No child processes, no native database/auth binaries — TDS, NTLM, Kerberos, EPA channel
binding, SPNEGO, LDAP, WMI, and SOCKS5 are all done in Python via `impacket` / `ldap3` /
`pywin32` and the stdlib.

## Layout (built incrementally)

| Subpackage | Purpose |
|---|---|
| `clients/mssql.py` | TDS + TLS-over-TDS + NTLMv2 (EPA CBT/SPN) + Kerberos + SSPI; EPA detection. TLS-1.2 cap. |
| `clients/auth.py` | Kerberos AP-REQ/SPNEGO + NTLM + current-user SSPI token minting. |
| `clients/ad.py` | LDAP transport×bind waterfall (lockout-safe), SPN search, SID→AD-object resolution. |
| `clients/wmi.py` | WMI over impacket DCOM + pywin32 (`Win32_GroupUser`, `Win32_Service`). |
| `discovery/dns.py` | DC/SRV/A discovery + DNS resolver override (proxy-aware). |
| `dlt/source_bridge.py` | push→pull DLT emit-resource bridge for multi-target collection. |
| `dlt/convert_pipeline.py` | convert-reads-DuckDB (self-run pipeline + `opengraph_file` + no-op source). |
| `dlt/duckdb_safe.py` | `_safe`/`_ensure_columns`/`_arr` defenses against dlt column-dropping. |
| `logging/log_context.py` | VERBOSE tier + `[target]`/`[phase]` contextvar tagging. |
| `graph/stub_node.py`, `graph/graph_edge.py` | generic edge model + edge-endpoint stub backfill. |
| `proxy/socks.py` | pure-Python SOCKS5 dialer. |
| `orchestration/run.py` | After convert, `run_end_to_end` flat-zips the emitted graph `*.json` into the graph dir (name from `graph_zip_name`, default `<app.name>_collection.zip`), ready for BloodHound File Ingest (loose files kept), and reports it back on `StagePaths.graph_zip` — the archive that was **written**, or `None` if convert emitted no `*.json`. `derive_stage_paths` leaves it `None`, since it runs before anything exists (including on a collector's failure path). |
| `integration_testing/` | Collector-agnostic assert-and-diff engine: payload loader (dir or zip), pattern matcher, fixture case runner, schema coverage, and the property-level graph comparator behind [`openhound-compare`](#openhound-compare). |

## Consumers

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

Diff two OpenGraph payloads down to property name and value. Installed with this package as a console
script — no collection and no framework CLI involved.

```bash
openhound-compare BASELINE CANDIDATE [--json PATH] [-q]
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

## Developing

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
