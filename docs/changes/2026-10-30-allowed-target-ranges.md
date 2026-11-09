# Allowed-target lists with names and IP ranges

Status: implemented on October 30, 2026, as approved in
[the proposal](2026-10-30-allowed-target-ranges-proposal.md). The owner chose
both recommended answers. A name on the list is allowed even if it points
outside the listed ranges. The list does not apply to the domain controller,
but collectors warn when it points outside the ranges.

## What was added

[`collection/registry.py`](../../src/openhound_collector_common/collection/registry.py)
now holds `AllowedTargets` and `ScopeDecision`, next to the existing
`matches_allowed_targets`, which is unchanged.

- **Reading the list.** `AllowedTargets(entries)` reads each entry as a range
  (`10.10.11.0/24`), a single address (kept as a one-address range), or a
  computer name. Blank entries are ignored. Every mistyped entry is collected
  into one error message before anything runs, for example
  "'10.10.11.5/24' is not the start of its range; did you mean 10.10.11.0/24?".
  A SQL instance, a port or a wildcard is not a computer name.
- **Names.** `is_name_listed` ignores capital letters and a trailing dot. A
  listed full name also matches the same computer's short name, and a listed
  short name matches any full name that starts with it. A different full name
  with the same first part does not match.
- **Ranges.** `addresses_outside` returns each address that is in no listed
  range. IPv6 zone suffixes such as `%12` are ignored.
- **The decision.** `check(names, addresses)` returns a `ScopeDecision`:
  - allowed when no list was given;
  - allowed when a name is listed;
  - otherwise allowed only when every address is inside a listed range;
  - refused when a name is not listed, cannot be looked up, or points outside.

  A name that is itself an address is treated as an address. Every decision
  carries a plain reason for logs and saved results. Long range lists are
  summarized after five.
- **No lookups.** The class never looks anything up. Each collector passes the
  addresses it found with its own DNS and proxy settings.

It uses Python's built-in `ipaddress` module. There is no new dependency.

## Consumers

The SQL collector adopts it for `--include-targets`, in the same change; see
its `docs/changes/2026-10-30-allowed-target-list.md`. SCCM does not change. It
could accept ranges in `--computers` later through the same class, as a
separate reviewed change.

## A gap the proposal missed

The SQL collector's linked-server step runs one query on each allowed server.
The server itself then signs in to each linked server to check the link's
rights, up to ten links deep. That traffic comes from the SQL server, not the
collector, so this list cannot filter it without changing that query.

At first, the SQL collector warned about this whenever the list was used. On
October 31, 2026 the owner approved replacing that query with a step-by-step
walk. The walk checks every linked server against this list before sending it
anything, so the warning was removed. See the SQL collector's
`docs/changes/2026-10-31-linked-server-walk.md`. This class did not change for
it.

## Checks

- New [`tests/test_allowed_targets.py`](../../tests/test_allowed_targets.py), 17 tests:
  - no list allows everything;
  - the short-name and full-name rule, including near-miss names;
  - a listed name allowed outside the ranges;
  - every address must be inside a range;
  - an address that cannot be looked up;
  - numeric names, IPv6 ranges and zoned addresses;
  - summarized range lists;
  - all mistyped entries reported together;
  - normalized entries kept for saved settings.
- Shared library full suite: **634 passed**, 1 skipped (needs a newer Python).
  That count includes the November 4 refused sign-in fix's 3 tests; it was 631
  before them.
  Ruff and mypy found no problems.
- SQL collector: 1,046 passed, 1 skipped, with 17 new tests of the option at
  the time. One of them, for the linked-server warning, was later removed with
  the warning, leaving 16.
  SCCM's full suite also passed against this change: 1,265 passed, 65 skipped
  for optional test tools.
- Lab, only `10.10.11.0/24` allowed: cas-db (10.10.10.51) was skipped with the
  reason and received nothing; ps1-db (10.10.11.51) was collected.

## Manual verification

Last run exactly as written: November 2, 2026, on ps1-dev. The commands were
copied from this section and run in order in one fresh PowerShell session.
Every result matched what is shown here.

### Before you start

- Open a new PowerShell window on ps1-dev. These steps don't contact the lab.
- The first `uv run` in this folder takes a minute or so while it installs the
  shared library's packages into the folder's `.venv`, which git ignores.
- This is the shared library's own folder, so its commands use this copy
  directly. No `--with-editable` is needed here.

### Step 1: Run the allowed-target tests

```powershell
Set-Location C:\Users\domainadmin\openhound-collector-common
uv run --locked pytest tests\test_allowed_targets.py -q
```

**You should see** `17 passed` on the last line.

### Step 2: See how the list decides some lab examples

[`tests/scripts/show_allowed_target_decisions.py`](../../tests/scripts/show_allowed_target_decisions.py)
gives the list a few computers, with the addresses their names point to
written into the script. It prints each decision and its reason.

```powershell
uv run --locked python tests\scripts\show_allowed_target_decisions.py
```

**You should see:**

```text
List 10.10.11.0/24
  ps1-db.mayyhem.com (10.10.11.51): allowed. ps1-db.mayyhem.com points only to addresses inside 10.10.11.0/24
List 10.10.11.0/24
  cas-db.mayyhem.com (10.10.10.51): NOT allowed. cas-db.mayyhem.com points to 10.10.10.51, which is not in 10.10.11.0/24
List 10.10.11.0/24
  two-homes.mayyhem.com (10.10.11.5, 10.10.10.5): NOT allowed. two-homes.mayyhem.com points to 10.10.10.5, which is not in 10.10.11.0/24
List 10.10.11.0/24, cas-db
  cas-db.mayyhem.com (10.10.10.51): allowed. cas-db.mayyhem.com is on the allowed-target list
List 10.10.11.51
  ps1-db.mayyhem.com (10.10.11.51): allowed. ps1-db.mayyhem.com points only to addresses inside 10.10.11.51/32
List 10.10.11.5/24, not a range/99
  refused: '10.10.11.5/24' is not the start of its range; did you mean 10.10.11.0/24?; 'not a range/99' is not a valid IP range
```

A single address such as `10.10.11.51` is shown as `10.10.11.51/32`, which
means a range of one address.

The line `The allowed-target list has entries that could not be read` may print
first, or among these lines. It's the library's own log message for the last
example, which is meant to fail.

### What these steps prove

- **An address inside a range is allowed, and one outside is not.** The first
  two examples show both, with the reasons a collector saves and logs.
- **Every address must be inside.** `two-homes` points to one address inside
  and one outside, so it isn't allowed.
- **A listed name always wins.** `cas-db` is allowed by name even though its
  address is outside the range.
- **Mistakes are named, all at once, with a suggested fix.**
- How a collector uses this in the lab is in the SQL collector's
  `docs/changes/2026-10-30-allowed-target-list.md` manual verification.

### Clean up

Nothing to clean up. The steps save nothing.
