# Shared custom and native graph files

The approved feature-completion plan moves generic file mechanics into common,
while SQL and SCCM retain their graph rules. The old SCCM native writer duplicated
the SDK destination. MSSQL's SDK 0.4.2 destination no longer accepts `source_kind`,
so passing that option only warned and produced unlabelled files. Its dataclass
path also retained thousands of null properties in an actual lab graph.

## Selected approach

`graph/files.py::GraphFileWriter` accepts a mapping from filename prefix to
source label. `None` means omit metadata. The caller supplies complete graph
records through `write_node` and `write_edge`; common does not derive identities,
relationships, evidence, native status, or permission rules. A small shared
`NATIVE_AD_KINDS` set names the native kinds used by the current consumers.

The writer encodes each record once, preserving the established DLT scalar/date
conversion. It omits absent values, preserves other properties and array order,
and buffers at most 1,000 records or eight MiB of encoded text per stream. One
larger record occupies its own part. Empty streams have explicit valid files.
Each invocation stages new files under its chosen output directory. A model or
write failure before publication leaves the old complete files untouched.
Publication replaces files individually; any failure fails conversion.

A hidden `.openhound-files/<prefix>.json` manifest records its owned parts.
Before publication, previous names must match that exact prefix and filename
pattern. Replacement retires only previous recorded parts, including when the
new graph is empty. This is not permission to delete arbitrary JSON or old DLT
outputs. Use a fresh directory when changing from the former writers.

Retaining two destination copies was rejected because SDK differences would
continue to change labels and batching. Another DLT pipeline was unnecessary:
models already read the complete prepared DuckDB, and persistent load state can
introduce stale output. No new dependency or OpenHound core edit is needed.

## Consumers and verification

MSSQL streams nodes once, records its custom IDs, then sends relationships whose
endpoints are both custom to its labelled set. External/native endpoints stay
unlabelled even if `--skip-ad-nodes` omitted their node. SCCM keeps its existing
three passes and prepared routing tables; only the file helper changes. Its
special one-file `hybrid_edges.json` writer stays local and unchanged.

Grouped verification on official Python 3.13.15 passed 82 shared output,
graph-validation, exact-comparison, and orchestration tests. SCCM's affected
conversion/routing selection passed 15 tests. SQL's conversion selection passed
10 tests after correcting a new fixture's column names. Ruff and mypy passed
for common, SQL, and the changed SCCM adapter.

Real network-blocked CLI conversion of the same prepared SCCM data retained
99 nodes and 307 relationships exactly, including every evidence property and
source label, with the named conversion-time allowances. SQL's real lab bucket
retained 193 nodes and 583 relationships after the intentional label restoration
and null omission: 181 custom nodes/557 custom relationships, and 12 native
nodes/26 native relationships. Its ZIP contained the exact loose JSON bytes.
The comparison report is `graph-writer-exact-results.json` under the task work
directory recorded in the SQL implementation status. The full initiative,
Python 3.14 checks, and published dependency updates remain unfinished.

## README correction, October 30, 2026

The README's file table listed a shared convert step, `dlt/convert_pipeline.py`.
That file has never existed in this library. The row came over from the
OpenHound fork with the first commit. SCCM's July 2 shared-library design,
`docs/superpowers/specs/2026-07-02-sccm-shared-lib-migration-design.md` in
ConfigManBearPig, kept a separate convert step in each collector, because the
two do different collector-specific jobs. SQL and SCCM still each have their
own, and neither uses a shared one. The row was removed. The package
description in `__init__.py` no longer mentions a shared convert step, and now
lists the progress display choices that this work added. Only wording changed.

Manual use from a configured project environment:

```python
from openhound_collector_common.graph.files import GraphFileWriter

with GraphFileWriter("graph", {"custom": "Example", "ad": None}) as output:
    output.write_node("custom", {
        "id": "example-1", "kinds": ["Example"], "properties": {"name": "Example"},
    })
```

Suggested owner commit: `Share bounded custom and native graph files`.
After reviewing this feature's files:

```powershell
git add -- src/openhound_collector_common/graph/files.py src/openhound_collector_common/graph/__init__.py tests/test_graph_files.py README.md docs/changes/2026-10-26-graph-files.md
git commit -m "Share bounded custom and native graph files"
```

Those are owner commands, not actions performed by the agent. Review the shared
README and export-file changes alongside their other pending features before
staging, because those files also describe earlier approved work.
