# Stop the whole run after one rejected sign-in

Status: approved by the owner on October 30, 2026 ("Go ahead and implement"),
after a lab check showed the problem. The owner's rule is to bail after a
single invalid attempt.

## The problem

A wrong password must cost the account at most one failed sign-in. In the lab,
it cost far more. `MAYYHEM\lowpriv` with a wrong password, one computer at a
time:

| Run | Failed sign-ins before | Run reported |
|---|---|---|
| SCCM, ps1-sms, all collection methods | 42 | success |
| SCCM, ps1-sms and ps1-mp, all methods | 82 | success |
| SCCM, both, per-computer methods only | 23 | success |
| SQL, ps1-db and cas-db, one after the other | 2 | partial |

Two separate causes produced this.

**The directory stop rule never triggered.** The shared directory client stops
trying other sign-in methods when the domain controller's reply contains a
known reason code, such as `data 52e` for a wrong password. But it signed in
with the directory library's one-step "automatic bind". On failure, that step
reports only `automatic bind not successful - invalidCredentials` and drops the
reason code. So the client tried its next method, which was a second failed
sign-in. It also never remembered the rejection, so each of SCCM's 18
directory searches signed in again. That accounted for 36 of the 42.

The October 29 unit tests passed only because they used a made-up message that
included the reason code. The SQL collector was not affected by this part: it
already used the step-by-step bind, which keeps the reason.

**Nothing stopped the run.** Each client remembered its own rejection, but a
run builds a new client for every computer. Every computer therefore tried the
same password again. SCCM tries several methods on each computer (Kerberos,
the AdminService web page, WMI and SMB), costing about five failed sign-ins
per computer. The SQL collector cost one per server.

## The fix

1. **Keep the reason code.** Every password sign-in now opens, upgrades and
   binds the connection step by step. A rejection carries the domain
   controller's full reply, including `data 52e`, so the existing stop rule
   works. If a rejection for typed-in details still has no reason code at
   all, it is treated as a rejected password, because guessing wrong would
   cost another failed sign-in.
2. **One record per run.** The new `CredentialGuard` is created once per run
   and handed to every client that signs in. Each client checks it before
   signing in and reports a definite rejection to it. The first report runs
   the collector's stop actions, such as stopping the queue of computers. After
   that, every sign-in is refused without contacting anything.
3. **Check the password once, first.** `AdClient.confirm_credentials()` signs
   in to the domain controller once. Both collectors call it before discovery
   and before any computer or server. A wrong password costs that one failed
   sign-in and nothing else.
4. **Report the run as failed.** Each collector ends a rejected run with a
   failure code and a plain message, instead of reporting success.

### What counts as a definite rejection

Only replies that prove the account or its password was refused stop a run:

- the directory's `invalidCredentials` with reason `52e`, `532`, `533`, `701`,
  `773` or `775`, or with no reason at all for typed-in details;
- Windows status codes for a wrong password, or a disabled, locked or expired
  account, already listed in `clients/identity_errors.py`;
- Kerberos replies 6, 18, 23 and 24: unknown account, disabled or locked
  account, expired password, wrong password.

"Access denied" does not count, and neither does SQL Server's "Login failed".
A correct account that simply lacks access gets those same replies. Stopping on
them would end ordinary low-privilege collection at the first computer it
cannot read.

## How it works in the code

- [`clients/credential_guard.py`](../../src/openhound_collector_common/clients/credential_guard.py)
  is new. `CredentialGuard` holds the first rejection under a lock, so several
  worker threads can report at once and the stop actions still run exactly
  once. `check_before_sign_in` raises `CredentialsRejectedError` after a
  rejection. `is_rejected_sign_in` decides whether an error is definite.
  `CredentialCheck` names the four outcomes of the one-time check: accepted,
  rejected, unchecked (no domain controller reachable) and not needed (no
  typed-in details, so the Windows session is used).
- [`clients/ad.py`](../../src/openhound_collector_common/clients/ad.py):
  `_open_connection` always uses the step-by-step bind and releases a failed
  connection. `_is_uncoded_rejection` recognizes a reply with no reason code.
  `_remember_rejection` is now the one place that remembers a rejection and
  tells the guard. `has_supplied_credentials` and `confirm_credentials` are
  new. The optional `credential_guard` argument is checked in `_bind`.
- [`clients/wmi.py`](../../src/openhound_collector_common/clients/wmi.py):
  `WmiClient` accepts an optional `credential_guard`, checks it in `connect`,
  and reports definite rejections from `_remember_rejection`.
- [`clients/kerberos.py`](../../src/openhound_collector_common/clients/kerberos.py):
  `KerberosAcquisitionError` now keeps the domain controller's numeric reason
  as `kdc_error_code`, and `is_rejected_identity` says whether it proves the
  password or account was refused. A key file's cached failure keeps the
  number too.

The step-by-step bind also reads the directory's server details once. The
previous monitored path read them twice.

### Things this does not cover

- The current Windows user (no typed-in details) keeps its existing retries.
  The Go reference lets that identity try Windows' own directory reader after
  a reply with no reason code, and a mapped Go test checks that.
- A SQL-only login cannot be checked first, because it is not a domain
  account. SQL Server's reply cannot tell a wrong password from a missing
  login, so its rejections stay per server.
- Workers already signing in at the moment of a rejection can each finish that
  one attempt. With the one-time check, this only matters if the password
  stops working partway through a run.

## Alternatives considered

- **Treat every directory `invalidCredentials` as a rejection.** Rejected: the
  channel-binding reply (`data 80090346`) uses the same label but says nothing
  about the password, and the next method can succeed.
- **Read the reason from the automatic bind's error.** Not possible: the
  library drops the server's reply before raising.
- **Stop on SQL Server "Login failed".** Rejected for the reason above: it also
  means "correct account, no SQL login", which is the normal low-privilege case.
- **Only stop the queue, with no per-client checks.** Rejected: a computer's
  remaining steps, and workers already running, would still sign in.
- **Each collector keeps its own record.** Rejected: both collectors need the
  same rule, and the shared clients must consult it themselves.

## Effects on collectors and users

Both collectors adopt it in the same change, and each has its own change note.
Callers that pass no guard keep their per-client behavior, apart from the
reason code fix, which applies everywhere. No new dependency, schema, graph,
permission or OpenHound core change is involved. Users see one new check
message at the start of each run with typed-in details, and a clear failure
when the password is wrong.

## Checks

| Project | Result |
|---|---|
| Shared library | 614 passed, 1 skipped (needs a newer Python) |
| SQL collector | 1,029 passed, 1 skipped (needs saved live output) |
| SCCM collector | 1,265 passed, 65 skipped (optional test tools) |

Ruff and mypy found no problems in the shared library. New tests in
[`tests/test_credential_guard.py`](../../tests/test_credential_guard.py) cover
the record, the exact lab message, the real connection-opening code with a
stand-in for the library, the one-time check's four outcomes, WMI, and
Kerberos. The October 29 test that expected a reply with no reason code to try
the next method now excludes that case. A key-file test in
`tests/test_kerberos_credentials.py` checks the cached reason. The three tests
tracked by the Go coverage map are unchanged, and the audit still matches 439
of Go's tests with the same 7 unfinished.

Lab check after the fix, same accounts and computers as above:

| Run | Failed sign-ins after | Run reported |
|---|---|---|
| SCCM, ps1-sms, all collection methods | 1 | failure |
| SCCM, ps1-sms and ps1-mp, all methods | 1 | failure |
| SCCM, both, per-computer methods only | 1 | failure |
| SQL, ps1-db alone / cas-db alone / both | 1 each | failure |

With the correct password, both collectors signed in, collected, and left the
failed sign-in counter at 0. SCCM reported success. The SQL collector reported
partial collection because `lowpriv` has no SQL login on ps1-db. That reply
correctly did not stop the run.

## Manual verification

From this project, in its declared environment:

```powershell
uv run --locked pytest tests/test_credential_guard.py tests/test_ldap_rejection_contracts.py tests/test_kerberos_credentials.py tests/test_wmi_inprocess.py -q
uv run --locked ruff check src tests
uv run --locked mypy src
```

The lab scripts and saved results are in the private feature work folder:
`tests/sccm_wrong_password_run_count.ps1`, `tests/wrong_password_run_count.ps1`
and `tests/correct_password_run_check.ps1`, with matching `*-lab.txt` results.
