# Proposal: allowed-target lists with names and IP ranges

Status: approved by the owner on October 30, 2026, with both recommended
answers to the open questions below. The implementation is recorded in
`2026-10-30-allowed-target-ranges.md`. One gap this proposal missed, each
server's own checks of its linked servers, is described there.

## The problem

The SQL collector has no allowed-target boundary. `-t` says where collection
starts, not where it must stop. With `--collect-from-linked`, it follows linked
servers named inside SQL Server's own data, and a link can name any server. That
includes servers outside the ranges you are authorized to test, such as the
lab's `10.10.10.0/24` and `10.10.11.0/24`.

SCCM already has a boundary (`--computers` and `--computer-file`), but it
matches names only.

## Decisions the owner already made

On October 30, 2026 the owner decided that the list:

- accepts both a comma-separated list and a file;
- accepts IP ranges;
- skips a linked server outside the list and makes clear why.

## What I recommend

### Shared library: one matcher both collectors can use

Add a small allowed-target matcher next to the existing
`matches_allowed_targets` in `collection/registry.py`.

- **Reading the list.** Each entry is a computer name, a single IP address, or
  a range such as `10.10.11.0/24`. A mistyped entry, such as `10.10.11.0/33`,
  stops the run before anything is contacted, and the message names the entry.
- **Names.** Matching ignores capital letters. A full name also matches its
  short name and the other way round, which is the rule SCCM uses today.
- **Ranges.** A computer is inside a range only if *every* address its name
  points to is inside an allowed range. One address outside is enough to skip
  it, because a name pointing outside the authorized ranges is not authorized.
- **No lookups inside the matcher.** Each collector passes the addresses it has
  already looked up, using its own DNS and proxy settings.
- **A plain reason for every decision.** For example: "sql9.example.com points
  to 172.16.0.5, which is not in 10.10.10.0/24 or 10.10.11.0/24."

It uses Python's built-in `ipaddress` module, so there is no new dependency.
Existing callers of `matches_allowed_targets` keep working unchanged.

### SQL collector: `--include-targets`

- Accepts one entry, a comma-separated list, or a file path with one entry per
  line and `#` comments. This is the same rule `-t` already uses.
- Applies to every server before any network work: `-t` servers, servers found
  from the directory, `--scan-all-computers`, and every linked server queued by
  `--collect-from-linked`.
- A server outside the list gets no SQL, connection-security, WMI or SQL
  Browser traffic. Its result is saved as `skipped`, with the reason, and the log
  shows a warning that names the server and the reason.
- The linked-server relationship that pointed to it is still saved, because it
  was read from an allowed server.
- Skipped servers do not make the run incomplete. This is the existing rule:
  intentional skips are not missing work.
- The list is saved with the run's settings, so a later reader knows the scope.
- Without `--include-targets`, nothing changes.

SCCM does not change in this proposal. It could accept ranges in `--computers`
later, through the same matcher, as a separate reviewed change.

## Why the shared library is the right home

Both collectors need the same safety rule, so one matcher with one set of tests
keeps them from drifting into two slightly different ideas of "in scope". The
shared library already owns the name matcher that SCCM uses. This extends it.

## Alternatives considered

- **A matcher inside the SQL collector only.** Faster to build, but SCCM would
  need its own later, and the two rules could drift apart.
- **Allow a server when any one of its addresses is inside a range.** Rejected:
  a name that points both inside and outside could send traffic outside.
- **Look up names inside the matcher.** Rejected: it would ignore each
  collector's DNS and proxy settings.

## Open questions for the owner

1. **A list that mixes names and ranges.** If a name is on the list but points
   outside every listed range, should it be allowed?
   - I recommend allowing it. A name typed into the list is explicit
     permission, and the rule stays simple: a server is allowed if its name is
     listed, or if every address it points to is inside a listed range.
   - The stricter choice is to always require every address to be inside the
     ranges, even for a listed name.
2. **The domain controller.** It is not a collection target, so I recommend the
   list does not apply to directory sign-ins. The run would log a warning if
   the domain controller points outside the listed ranges.

## Checks I would add

- Short and full names, single addresses, IPv4 and IPv6 ranges, and mistyped
  entries.
- A name that points to two addresses, one of them outside.
- A linked server outside the list: nothing is sent to it, its relationship is
  still saved, and the skip reason is saved and logged.
- The exit code is not affected by skipped servers.
- Lab: collect `ps1-db` and `cas-db` with `--include-targets 10.10.11.0/24`.
  Expect `ps1-db` (10.10.11.51) to be collected and `cas-db` (10.10.10.51) to be
  skipped with the reason.
