# Exact graph comparison and checks before node merging

## Problem and selected solution

The existing comparator answers whether a candidate lost baseline information.
An ordinary property value change or added record can return success. It also
indexed relationships by start/kind/end, losing earlier login mappings when
several records shared those endpoints. The loader merged conflicting nodes
before a checker could see the conflict. Those behaviors cannot prove that two
collector outputs match the same reference.

Extend the existing tool rather than creating another comparator. The ordinary
mode keeps its existing loss-only verdict; its relationship index now retains
every record. Optional exact mode compares complete record counts, JSON property
values/types/order, kind labels, endpoint matching rules, and file source labels.
It ignores file names and record order, which do not change graph meaning. Node
kind order is irrelevant because those are labels rather than a property list.

Exact mode checks raw files first. The existing convenience node merge remains
available for normal readers, but `Graph.raw_nodes` preserves pre-merge records.
Complementary repeated nodes are valid; shared properties with different values
are errors. Identical repeated relationships are errors, while different
properties may represent different legitimate mappings. Repeated JSON keys are
rejected before the JSON reader could replace their earlier values.

## How it works

- `integration_testing/raw_checks.py` checks file/record shape and raw conflicts.
  `GraphValidationError` keeps each file and its explanation.
- `integration_testing/graph.py` optionally selects these checks and retains
  source labels and endpoint matching rules. Default loading stays compatible
  with existing consumers.
- `integration_testing/exact.py` compares counts of complete records. Narrow
  `PropertyAllowance` objects can omit one named property or ignore one selected
  list's order, with a mandatory reason. No exceptions are enabled by default.
- `integration_testing/compare.py` retains the ordinary report and exposes the
  separately requested `is_exact_match` verdict. Its ordinary relationship
  comparison cancels equal records one-for-one before comparing leftovers.
- `integration_testing/cli.py` adds `--exact`, `--check-raw`, and `--allowances`.
  Invalid graph results return 1; bad paths/options return 2. Exact mode uses the
  exact verdict rather than the older loss-only result.

An alternative that expanded the endpoint key with SQL-only login fields was
rejected: common must also retain other collectors' different relationship
properties. Complete record counts avoid embedding SQL rules in a shared tool.
Globally ignoring timestamps or list order was also rejected because it could
hide an unintended change. An exception file makes each relaxation reviewable.

No dependencies are added. OpenHound core, SQL graph builders, SCCM graph
builders, and both schema files stay untouched by this feature. SCCM's existing
loss-only checks gain detection of missing duplicate-endpoint records; adopting
the stricter file checks or exact verdict remains an explicit caller choice.

## Verification and manual use

The first combined feature checkpoint passed 69 checks across the existing
comparison/regression/CLI/graph tests and the new exact/raw checks, domain
selection, and connection deadlines. Shared lint passed. Type checking found a
Windows API keyword spelling issue in the separate domain feature; that spelling
was corrected and will be rechecked at the next substantial checkpoint.

New comparison checks cover type-sensitive values, reordered lists, kind changes,
added records, source labels, endpoint matching rules, separate linked-login
mappings, multiplicity, scoped exceptions, conflicting pre-merge nodes, duplicate
JSON keys, non-graph files, empty inputs, and ZIP reading. Final consumer checks
and broader integration acceptance remain pending.

Use two saved outputs to verify manually:

```powershell
openhound-compare .\baseline.zip .\candidate\graph --exact --json .\comparison.json
```

Change a copied graph property's owner or port and rerun: exact mode must return
1 even when ordinary loss-only mode would permit that value change. Remove one
of two linked-login mappings sharing endpoints: both modes must report the lost
record. Use copied artifacts so the original collection is preserved.

The owner can review this feature separately as `Add exact graph comparison and
validate raw records before merging`. The final review record will give exact
stage/commit commands after all shared changes and consumer checks are complete;
the agent does not stage, commit, tag, or push.
