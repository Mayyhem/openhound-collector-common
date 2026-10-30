# Proposal: stop after the first bad-password reply

Status: approved by the owner on October 29, 2026. The implementation and
verification are recorded in `2026-10-29-ldap-rejected-password.md`.

## The problem

The shared directory-login code recognizes `invalidCredentials` but can miss
the same message written as `Invalid Credentials`. The Go tests include that
second spelling, followed by a code that means the password is wrong.

An offline check gave that exact reply to our real login code. It tried the
failed login twice instead of stopping after the first reply. Repeating a bad
password can move an account closer to being locked. The check replaced every
connection attempt, used only example text and saved only counts and yes/no
results. It contacted no server and used no real credentials.

## What I recommend

Make the existing check recognize both spellings, while still requiring one of
the known codes for a wrong password or another rejected-account condition.
After the first such reply, stop trying and report the failure. Keep the current
handling for replies that mean something else: an encrypted-connection problem,
for example, does not prove the password is wrong.

This is a small change to the existing check, not a new login method. There are
no new settings, installed packages, helper programs, server changes or graph
changes.

## Why this belongs in the shared library

MSSQL and CMBP use the same directory-login code. Fixing it once protects both
tools. I recommend that CMBP take this fix in the already planned shared-library
release, along with the two approved SQL authentication fixes.

The code to change is `_is_credential_failure` in
`src/openhound_collector_common/clients/ad.py`. The example check and its safe
report are `tests/prototype_ldap_rejection.py` and `ldap-rejection-proof.json` in
the private feature-work folder. The report shows two attempts and a missed
bad-password classification. The example program is disposable, not collector code.

## How I will check it

Use the exact Go error messages and the normal library messages. Confirm that
a wrong password stops after one attempt and that calling the same client again
does not send another login. Confirm that an encrypted-connection problem still
follows the existing permitted retry rules. Check the saved failure and logs
without printing passwords or authentication messages.

Then run the affected shared and collector tests at the end of the change.
No live wrong-password test is needed. The existing lab authorization is enough
for any normal successful-login checks needed afterward.

Leaving the check unchanged keeps the demonstrated repeated-login problem.
Stopping on every login error would also stop some valid accounts unnecessarily.
Recognizing the known rejected-account reply is the smallest correction.
