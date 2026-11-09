# A refused directory sign-in is reported as refused, not as stopped

Status: approved by the owner on November 4, 2026 ("that's fine make the
change"), after the SQL collector's clear wrong-password message fix (its
`docs/changes/2026-11-04-clear-wrong-password-message.md`) left this case open.
It follows [one rejected sign-in per run](2026-10-30-one-rejected-sign-in-per-run.md).

## The problem

A collector can link its run's stop signal to the time limit on every read.
The SQL collector does this once collection has started: a rejection anywhere
stops servers that haven't started and interrupts reads in progress.

When the domain controller refused a password during a timed directory sign-in,
that sign-in's own report set the stop signal while the sign-in's time limit was
still running. The time limit and the directory client then saw the signal and
described the refusal as a stop:

```text
ERROR    LDAP bind via LDAPS+CBT failed with a credential error: ... data 52e ...
ERROR    The domain controller dc.mayyhem.com rejected the supplied sign-in details; stopping the whole run so the account is not tried again
WARNING  LDAP bind returned after stopping (timeout overrun 0.000s)
WARNING  LDAP bind stopped; refusing further authentication attempts
```

The sign-in then ended with `ReadStoppedError: LDAP bind was stopped` instead of
the domain controller's refusal. The first two lines are right. The last two,
and the error, name the wrong cause. The run itself behaved correctly: it
stopped after one failed sign-in, and the run-wide record said the domain
controller rejected the password.

The same happened when the sign-in was part of a directory search, with
"LDAP search returned after stopping", "LDAP search stopped; closing its owned
connection" and `LDAP search was stopped`.

**When it shows.** In the SQL collector, the November 4 fix connects the stop
signal only after the one-time password check, so a wrong password is caught
first and reads clearly. This case remained for a refusal later in a run. That
only happens when the one-time check couldn't reach a domain controller and a
later directory sign-in is refused. The SCCM collector isn't affected: its
directory client has no time limit.

## Why the shared library

The mislabeling happens inside the shared directory client (`AdClient` in
[`clients/ad.py`](../../src/openhound_collector_common/clients/ad.py)). That's
where the refusal is reported and where the time limits are set. For a refusal
later in a run, a collector can't fix it without giving up the stop signal on
its reads. Any collector that links the two would see it.

## The solution, and why

Inside a timed sign-in or search, the directory client still remembers the
refusal at once. It reports the refusal to the run-wide record only when that
sign-in's or search's own time limit has finished. Then the stop the report
triggers can't reach the read that caused it, so nothing calls the refusal a
stop. The run still stops: the report comes microseconds later, before the
error leaves the client. The client also passes on the refusal itself, even if
a stop from elsewhere or the time limit arrived at the same moment. The refusal
is the more specific reason.

It was chosen because it's contained in the directory client. Nothing else in
the shared library changes, and collectors need no changes.

## Alternatives considered

- **Teach the time limit (`ReadOperation` in
  [`clients/operations.py`](../../src/openhound_collector_common/clients/operations.py))
  to ignore a stop the read caused itself.** Rejected. The time limit is shared
  by every SQL, WMI, directory and DNS read. It can't tell who set the stop
  signal without a new interface, and changing it affects every read.
- **Only change the directory client's own "stopped" message.** Rejected: the
  time limit's "returned after stopping" line would remain.
- **Leave it.** The owner chose to fix it. It's rare, but it names the wrong
  cause when it happens.
- **Fix it in each collector.** Rejected: the only collector-side fix is not
  linking the stop signal to reads, which would stop a wrong password from
  interrupting reads in progress.

## How it works in the code

In [`clients/ad.py`](../../src/openhound_collector_common/clients/ad.py):

- `_remember_rejection` still remembers the refusal in `_credential_failure`
  straight away, so this client never submits the password again.
  - With no timed sign-in or search running, it reports to the run-wide record
    at once, as before.
  - Inside one, it keeps where the refusal happened in `_unreported_rejection`
    and logs that it will report it when the read ends.
- `_report_rejection` is new. It reports a held-back refusal to the
  `CredentialGuard`, once.
- `bind()` and `paged_search()`:
  - pass the refusal on unchanged when `_unreported_rejection` is set, instead
    of turning it into "stopped";
  - call `_report_rejection` in their `finally`, after their time limit has
    finished. A sign-in inside a search leaves the report to the search, whose
    time limit finishes last.

Untimed clients (no `read_control`) report at once, exactly as before.

## Dependencies

None new.

## Effects on collectors and users

- **SQL collector:** a directory sign-in refused later in a run reads as a
  refusal. It no longer logs "LDAP bind stopped", "returned after stopping" or
  `LDAP bind was stopped`. The run still stops after that one failed sign-in.
  With this change, the collector's November 4 ordering fix in `main.py` would
  no longer be needed for the first check. It stays, because the collector uses
  the published shared library until the next release.
- **SCCM collector:** no change. Its directory client (`ADClient` in its
  `clients/ad.py`) has no time limit, so it reports a refusal at once, as
  before.
- **Other users of `AdClient`:** untimed clients are unchanged. Timed clients
  without a run-wide record (`credential_guard`) are unchanged too, since there
  is nothing to report.
- **Not covered, and unchanged:** a refusal that arrives after the sign-in's
  own time limit has run out. The sign-in has already been stopped by then, so
  it ends as `LDAP bind was stopped` and the refusal isn't recorded. This was
  reproduced offline with a stand-in that refuses after the time limit. It has
  not been seen in the lab.
- No schema, graph, permission or OpenHound core change.

## Testing

- New test in
  [`tests/test_credential_guard.py`](../../tests/test_credential_guard.py):
  `test_refusal_that_stops_the_run_is_reported_as_refused_not_stopped`. It
  links a run's stop signal to the client's time limit, as the SQL collector
  does, and signs in with a stand-in domain controller that refuses the
  password. It runs three ways:
  - the one-time sign-in check;
  - a plain sign-in;
  - a sign-in as part of a directory search.

  Each must end with the refusal (or "rejected" for the check), make one
  attempt, set the stop signal, and log nothing with "stopped". All three
  failed before the fix with `ReadStoppedError: LDAP bind was stopped`, and
  pass now.
- [`tests/scripts/show_refused_sign_in_messages.py`](../../tests/scripts/show_refused_sign_in_messages.py)
  prints what such a sign-in logs, for the manual check. pytest doesn't run it.
  Before the fix it printed the two "stopped" warnings and
  `ReadStoppedError: LDAP bind was stopped`.
- Shared library full suite: **634 passed**, 1 skipped (needs a newer Python).
  Ruff, Ruff formatting and mypy found no problems.
- Against this library, with `--with-editable`: SQL collector **1,076 passed**,
  1 skipped (with its uncommitted November 6 and 9 changes); SCCM collector
  **1,274 passed**, 65 skipped.

## Added November 6: one refusal, fewer repeated lines

Approved by the owner on November 6, 2026: "just make a change to suppress 1
and 4, (leave 2)".

- **Problem:** one wrong password put six lines on the console. Two of them
  repeated what other lines already said:
  - `The LDAP bind was rejected` (warning), written the moment the domain
    controller says no. The next line says the same, with the domain
    controller's reason (`data 52e`);
  - `The sign-in details were rejected before any computer was visited`
    (error), from the one-time sign-in check. The collector's own message
    straight after says the same, and what to do next.
- **Solution:** log both at debug level. They leave the console and the issues
  log, and stay in the full run log for engineers.
- **Alternatives:** removing them (engineers lose a step in the full log);
  lowering the line with the domain controller's reason too (the owner chose to
  keep it on the console).
- **How it works:** in [`clients/ad.py`](../../src/openhound_collector_common/clients/ad.py),
  `_open_connection` logs "The LDAP bind was rejected" with `logger.debug`, and
  `confirm_credentials` logs "rejected before any computer was visited" with
  `logger.debug`. Nothing else changes.
- **Effects:**
  - The SQL collector's console now shows three lines for a wrong password: the
    domain controller's reason, the run-wide stop, and the collector's message.
    The SQL collector's status line, which follows them, now also says why.
  - The SCCM collector's warnings and errors are the same three lines, plus its
    own "Stopping target scheduling" line. Its summary now says
    "1 WARNING, 3 ERRORs" instead of 4 errors. Its issues log keeps debug lines
    written while an error is being handled, uncounted, so the sign-in check
    line still appears there, marked `DEBUG`.
  - Searches of the full log find the same lines as before.
- **Testing:** two existing tests now also check the levels:
  - `test_every_password_bind_keeps_the_domain_controllers_reason` checks the
    reason is logged as an error and "The LDAP bind was rejected" only at debug;
  - `test_refusal_that_stops_the_run_is_reported_as_refused_not_stopped`, in its
    sign-in check form, checks "rejected before any computer was visited" is
    logged only at debug.

  Both failed with the old levels and pass now. The test counts are unchanged.

## Manual verification

Last run exactly as written: November 4, 2026, on ps1-dev as
`MAYYHEM\domainadmin`. The commands were copied from this section and run in
order in one fresh PowerShell session. Every result matched what is shown here.
Step 3's SQL collector steps were run the same day and matched too.

### Before you start

- Open a new PowerShell window on ps1-dev. Steps 1 and 2 don't contact the lab.
  Step 3 does, through the SQL collector's own steps.
- The first `uv run` in this folder takes a minute or so while it installs the
  shared library's packages into the folder's `.venv`, which git ignores.

### Step 1: Run the sign-in rejection tests

```powershell
Set-Location C:\Users\domainadmin\openhound-collector-common
uv run --locked pytest tests\test_credential_guard.py -q
```

**You should see** `26 passed` on the last line. Three of them are the new test,
run three ways.

### Step 2: Show what a refused sign-in logs once the run can be stopped

This signs in once with a wrong password to a stand-in domain controller that
refuses it the way the lab's does, with the run's stop signal connected.
Nothing is contacted.

```powershell
uv run --locked python tests\scripts\show_refused_sign_in_messages.py
```

**You should see:**

```text
Logged:
  ERROR    LDAP bind via LDAPS+CBT failed with a credential error: invalidCredentials: 8009030C: LdapErr: DSID-0C0906B0, comment: AcceptSecurityContext error, data 52e, v4f7c
  ERROR    The domain controller dc.example.test rejected the supplied sign-in details; stopping the whole run so the account is not tried again
The sign-in ended with: LDAPBindError: invalidCredentials: 8009030C: LdapErr: DSID-0C0906B0, comment: AcceptSecurityContext error, data 52e, v4f7c
Run-wide record: rejected by The domain controller dc.example.test
Run's stop signal set: yes
```

**If you see** `LDAP bind returned after stopping`, `LDAP bind stopped`, or
`ReadStoppedError: LDAP bind was stopped`, the old behavior is back.

### Step 3: Check the real wrong-password run, through the SQL collector

Follow the manual verification in the SQL collector's
`docs/changes/2026-11-04-clear-wrong-password-message.md`. Its commands already
use this local copy of the shared library. It shows a real wrong password
against the lab domain controller still costs one failed sign-in and ends with
the clear "rejected" lines.

### What these steps prove

- **A refusal is reported as a refusal**, even with the run's stop signal
  connected. Step 1 covers a plain sign-in, the one-time check and a search.
  Step 2 shows the messages.
- **The run still stops.** Step 2 shows the stop signal set and the run-wide
  record naming the domain controller.
- **The real wrong-password run is unchanged:** one failed sign-in and the
  clear message (step 3).

### Clean up

Nothing to clean up for steps 1 and 2. Step 3's SQL collector steps include
their own clean-up.
