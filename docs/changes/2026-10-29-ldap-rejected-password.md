# Stop after a known rejected-password reply, regardless of label spacing

**Update, October 30, 2026.** A lab run showed this rule never fired for SCCM.
The one-step automatic bind dropped the `data 52e` reason code, so a reply
like the one below matched no known code. Every password bind now keeps the
reason code, and typed-in details rejected with no reason code at all also
stop. The test below that expected a bare "Invalid Credentials" to retry no
longer includes that case. See
[stop the whole run after one rejected sign-in](2026-10-30-one-rejected-sign-in-per-run.md).

The owner approved the [plain-English proposal](2026-10-29-ldap-bad-password-proposal.md)
on October 29, 2026. The original offline proof showed two submissions after the
exact Go example `LDAP Result Code 49 "Invalid Credentials": data 52e`.

## Problem, choice and implementation

The shared client recognized the label `invalidCredentials`, but missed the same
words with a space. That made its existing stop rule ineffective for one spelling
of a known rejected-account reply. Retrying that same rejected password cannot
correct it and can move the account closer to a lockout.

In `clients/ad.py`, `_is_credential_failure` now removes whitespace only for the
label check. It still requires the same known `data` code from the original error
text: `52e`, `532`, `533`, `701`, `773` or `775`. These describe wrong, expired,
disabled, locked or otherwise rejected account credentials. The original error
object and its text are not rewritten. No authentication message or credential
value is parsed or changed.

The existing `_bind` loop already saves the first rejected-account exception and
refuses subsequent submissions through that client. Correcting the label check
makes that existing protection apply to both spellings. Calling `bind` again or
starting a later search on the same rejected client raises the saved failure.
Failed search outcomes retain an unknown row count, rather than claiming that
the directory contains zero matching objects.

An error about connection security, including the reference's `80090346` reply,
does not prove the password was rejected. It keeps its existing permitted retry
rules. Stopping on every LDAP error would break that recovery. Adding a second
login routine or special collector-only error checks would duplicate the shared
policy. Normalizing the existing label check is the smallest correction.

## Effects on MSSQL, CMBP and other consumers

Both collectors use this shared AD client. MSSQL opts into read budgets; CMBP's
AD subclass retains its existing timeout policy. Both inherit the corrected stop
rule without a new option or production adapter change. Other consumers of this
client receive the same correction. Recommend adopting it in the planned reviewed
common release alongside the approved EPA isolation and NTLM hash-input fixes.
No published dependency number is invented in this working-tree change.

No new dependency, child process, service setting, lab account, permission, graph
node, relationship or schema change is involved. Other login methods, native
fallback eligibility and known rejection codes retain their existing behavior.
This fix does not add the separate Go SimpleBind fallback that remains under
review for feature coverage.

## Verification

`tests/test_ldap_rejection_contracts.py` replaces only discovery and provider
connection calls. Actual bind planning, owned read controls, bind/search loops,
cached rejection and query outcome handling still run. It uses public error
examples and illustrative credentials, with network access prohibited.

The checks cover the exact Go rejected-password and connection-security examples,
all six known rejected-account codes, spaced/unspaced labels, both timeout
policies, the installed LDAP library's own exception class, repeat bind/search
calls and non-credential failures. Saved outcomes and logs are checked for the
illustrative password; saved outcomes also omit arbitrary provider error text.
`ConfigManBearPig/tests/ad_rejection_test.py` checks both spellings through its
actual AD subclass.

Final feature verification passed:

- Common: **591 passed, one expected Python-version skip**, including all 44 new
  rejection/retry checks. Full source/test Ruff checking and mypy checking of 64
  source files passed. The new test file passed formatting verification.
- MSSQL: **76 passed**, covering directory/target behavior and reference mapping/
  execution auditing. The two exact Go error cases now have executed mappings.
- CMBP: **31 passed**, including both new inherited-error checks and the existing
  AD authentication, credential, attribute and principal-resolution selection.
  Its new test file passed Ruff and formatting verification. The existing dlt
  loader emitted 17 Pydantic `dict` deprecation warnings; this fix changes no
  dependency or loader code.

Execution evidence is `.tmp/q29-ldap-rejection-{common,sql,sccm}-results.xml`,
using the established isolated environments and fresh short pytest directories.
The complete reference audit now confirms **439 records** and correctly returns
1 for **nine unfinished records**: three unit records and six live integration
lifecycle records. It retains 32 upload exclusions and no skipped required cases.
The saved reports are `reference-ldap-rejection-audit.json/.html` in the private
feature folder. Earlier 437/11 audit checkpoints are historical.

No live wrong-password check is needed. The reproducer and retained checks cannot
change an AD lockout counter. A live successful login alone would not establish
that this error path is fixed.

## Manual verification and owner review

Use common's declared environment and a fresh short temporary directory:

```powershell
uv run --locked pytest tests/test_ldap_rejection_contracts.py tests/test_ldap_query_outcomes.py tests/test_windows_ldap.py -q --basetemp=C:\Users\domainadmin\.tmp\ldap-rejection-review-01
uv run --locked ruff check --no-cache src tests
uv run --locked mypy src/openhound_collector_common
```

Suggested common commit after owner review:

```powershell
git add src/openhound_collector_common/clients/ad.py tests/test_ldap_rejection_contracts.py README.md docs/changes/2026-10-29-ldap-bad-password-proposal.md docs/changes/2026-10-29-ldap-rejected-password.md
git commit -m "Stop LDAP retries for spaced rejected-account replies"
```

Suggested bounded CMBP follow-up:

```powershell
git add tests/ad_rejection_test.py README.md ARCHITECTURE.md
git commit -m "Verify shared rejected-password protection through SCCM"
```

Review the MSSQL mapping/documentation changes with its pending reference work.
No files were staged or committed. No push, package release or lab mutation was
performed. Complete all-tools integration acceptance remains unfinished.
