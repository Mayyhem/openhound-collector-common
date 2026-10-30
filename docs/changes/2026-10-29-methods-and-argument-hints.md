# Collection choices and command hints

This implements the generic method parsing and argument-warning extractions in
the owner-approved MSSQL feature completion plan. SQL-specific policy remains in
the SQL collector. No OpenHound core code, schema, lab settings, or Git history
was changed.

## Problem and selected approach

SCCM already selected collection phases by a comma-separated list and warned
about mistakes such as `-dc` being interpreted as `-d c`. MSSQL needed those same
mechanics, with different collection methods and dependencies. Copying SCCM's
implementation would leave two versions of the parser and warning redaction to
maintain. Moving SQL's vocabulary and network policy into common would instead
make a generic helper depend on one service's rules.

The selected approach shares only normalization, membership checks, and warning
construction. Each caller still owns its valid choices, defaults, credentials,
option names, logging, and actual network work. There are no new dependencies.
Existing package floors are not changed to an invented release number; the
single shared release and ordinary-installation acceptance remain pending.

## How it works

- [`collection/methods.py`](../../src/openhound_collector_common/collection/methods.py)
  splits comma-separated names, strips spaces, normalizes case and removes
  duplicates. Its immutable result answers whether a phase was selected. It
  preserves the existing generic All behavior, including SCCM's empty-string
  default. It deliberately does not reject unknown service names.
- [`orchestration/arguments.py`](../../src/openhound_collector_common/orchestration/arguments.py)
  constructs warnings from the caller's actual option names. It detects a
  misspelled long option such as `-dc` and a suspicious split value after an
  attached short option. Sensitive values are masked before constructing a
  warning. The caller may also identify sensitive values regardless of option.
  It returns text and does not reparse arguments, change their values, or choose
  a logger.

SCCM's `SourceContext.method_enabled` calls the parser each time, preserving its
existing mutable context behavior. Unknown names remain ignored and All still
includes arbitrary phase names. Its main command delegates warning construction
with the existing option maps and sensitive-value rules. Its authentication,
collection phases, command defaults and exit policy are unchanged.

SQL resolves and validates its list once in `methods.py` and `CollectionConfig`.
Its choices are All, LDAP, MSSQL and WMI. WMI enriches SQL targets and requires
MSSQL. The discovery-only shortcut defaults to LDAP and rejects an explicit SQL
or WMI choice. A scan-all request requires LDAP; following collected links
requires MSSQL. MSSQL-only requires an explicit target source. Invalid choices
fail before existing-output cleanup or network activity. Saved run settings
contain the canonical selected names, and intentionally omitted protocols have
skipped outcomes rather than failed reads.

SQL's LDAP-only branch runs before SQL connection, EPA, Browser and WMI work.
It saves actual directory computers, including their verified disabled state.
Published MSSQL SPNs can produce the existing partial SQL endpoint evidence;
a hostname alone does not prove that SQL exists. The actual computer is marked
`directory_computer` so preprocessing preserves its attributes when the endpoint
also creates a host node. This changes no schema fields. Ordinary SQL collection
retains its existing Go-compatible host shape. Missing SQL permissions and
version remain unknown; directory-only completion describes the requested LDAP
work, not a completed SQL catalog read.

The discovery shortcut saves both endpoint JSON and normal collection status,
with one run ID and selected methods. Its endpoint JSON counts toward the data
limit and belongs to the explicit cleanup list. A usable saved endpoint with a
resource stop returns 3; a stopped run with no usable evidence returns 1. Failed
LDAP enumeration or fatal cleanup cannot appear as a successful empty discovery.

SQL obtains value-taking options from its registered Typer function, rather than
maintaining a second option-name list. Passwords, hashes, tickets, keys, proxy and
target values, and inline `user:password@host` forms are masked. New long aliases
`--username`, `--domain-controller`, and `--dns` use the same parameters as their
existing names. Help/version remain free of collection activity.

## Verification and manual checks

Feature checks cover unknown/dependent method rejection, environment precedence,
aliases, selection before cleanup, disabled-client boundaries, actual directory
attributes, partial SPN evidence, discovery errors and resource-stop status.
Fresh-process integration checks execute real collect/preprocess/convert and ZIP
writing with all target connections refused and only directory replies supplied.
They verify both a bare hostname and a published SQL SPN, including the disabled
computer property in the final graph. Go reference cases verify ordinary SQL
graph behavior. Final passing counts and read-only lab results are recorded in
MSSQL's `docs/changes/2026-10-23-feature-completion-status.md`.

The initial broad check caught outdated producer mocks lacking the now-always
present run ID, an incorrect test spelling of `isEnabled`, and dropped attributes
in the new LDAP-only SPN path. The mocks now assert the run ID, the test uses the
established property name, and that new path preserves verified attributes. The
graph checks were retained, not weakened.

Run through the repositories' declared environments. Use separate log folders
and fresh short `--basetemp` paths on Windows:

```powershell
# Common
uv run pytest tests/test_method_selection.py -q
uv run ruff check src tests
uv run mypy src

# MSSQL
uv run pytest tests/unit/test_method_selection.py tests/unit/test_collection_failure_controls.py tests/integration/test_directory_only_commands.py tests/integration/reference -q

# SCCM
uv run pytest tests/collection_method_selection_test.py tests/cli_argument_warnings_test.py tests/extension_metadata_test.py tests/integration_wiring_test.py tests/convert_pipeline_test.py tests/integration_fixtures_test.py -q
```

After reviewing/installing the shared release, the following read-only examples
use the authorized lab. Resolve target names to the approved lab subnet first:

```powershell
# Actual computer evidence; this explicit hostname carries no published SPN.
uv run openhound collect mssql .\directory-check -m LDAP -t ps1-db.mayyhem.com:1433 -d mayyhem.com --domain-controller 10.10.10.100 --dns 10.10.10.100 --run-all

# SQL catalog without WMI or directory enrichment.
uv run openhound collect mssql .\sql-check -m MSSQL -t ps1-db.mayyhem.com:1433 -d mayyhem.com --dc 10.10.10.100 --run-all

# SPN target list and status only; no SQL/WMI/EPA/Browser work.
uv run openhound collect mssql .\discovery-check -d mayyhem.com --dc 10.10.10.100 --domain-enum-only
Get-Content .\discovery-check\collection-status.json
```

MSSQL-only graph IDs may fall back to hostnames when LDAP was omitted. Use All
when directory-based identities and all supported enrichment are wanted. A
selected read that fails still produces incomplete status; intentional omission
does not hide a failure in a selected method.

## Owner review and suggested commits

These files overlap earlier feature work; review their full combined changes.
The owner performs all Git actions. Suggested messages and exact file lists:

```powershell
# In openhound-collector-common
git add src/openhound_collector_common/collection/methods.py src/openhound_collector_common/orchestration/arguments.py tests/test_method_selection.py README.md docs/changes/2026-10-29-methods-and-argument-hints.md
git commit -m "Share collection method parsing and safe argument hints"

# In openhound-mssql
git add src/openhound_mssql/methods.py src/openhound_mssql/arguments.py src/openhound_mssql/auth.py src/openhound_mssql/main.py src/openhound_mssql/collection/run.py src/openhound_mssql/collection/targets.py src/openhound_mssql/collection/partial.py src/openhound_mssql/ad_nodes.py src/openhound_mssql/resource_limits.py src/openhound_mssql/extension.yaml tests/unit/test_method_selection.py tests/unit/test_command_controls.py tests/unit/test_collection_failure_controls.py tests/integration/test_directory_only_commands.py README.md ARCHITECTURE.md docs/changes/2026-10-23-feature-completion-status.md
git commit -m "Select MSSQL collection methods and preserve directory-only evidence"

# In ConfigManBearPig
git add src/openhound_sccm/main.py src/openhound_sccm/context.py tests/collection_method_selection_test.py ARCHITECTURE.md
git commit -m "Use shared method parsing and argument warning helpers"
```

No staging, commits, pushes or publication have been performed by the agent.
