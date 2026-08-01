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
| `orchestration/run.py` | After convert, `run_end_to_end` flat-zips the emitted graph `*.json` into the graph dir (name from `graph_zip_name`, default `<app.name>_collection.zip`), ready for BloodHound File Ingest (loose files kept). |
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

See [DEVELOPMENT.md](DEVELOPMENT.md) — including how to work on this library and a collector at the
same time without reinstalling after every edit.

## License

Apache-2.0 (see [LICENSE](LICENSE)). This code was factored out of the SCCM collector, itself a port of
the Apache-2.0 `ConfigManBearPig.ps1`, so it inherits those terms.
