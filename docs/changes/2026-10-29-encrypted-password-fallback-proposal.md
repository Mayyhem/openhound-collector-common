# Proposal: support Go's additional encrypted directory-password login

Status: decided by the owner on October 30, 2026. Go's two username-spelling
tests are excluded, because the collector must bail after a single invalid
attempt. Go's three-spelling retry will not be copied, and no code changed. The
two lab checks that informed the decision are under "Lab check" and "Follow-up
lab check" below. This is separate from the rejected-password label correction,
which the owner approved on October 29.

## The missing behavior

Go can try a standard username-and-password directory login when its usual
Windows login method fails because of connection-security requirements. This
additional method is called SimpleBind. It sends the password inside an encrypted
connection. Our shared client currently tries only NTLM for ordinary explicit
passwords. It does not implement this additional method, despite an old comment
suggesting otherwise.

Two remaining Go checks specify which form of the username to use. For example,
`MAYYHEM\domainadmin` first becomes `domainadmin@mayyhem.com`, using the configured
DNS domain. Copying a name-conversion helper that no login actually uses would
not complete this behavior.

## Recommended change

Add an optional shared-client setting that allows this password fallback. MSSQL
would select it; CMBP and other callers would keep their existing default. This
does not need a new collector command-line option.

Keep the existing preferred login first. Try the additional method only over an
already encrypted connection, or after successfully upgrading the selected
connection to encryption. Confirm encryption before submitting a password. Never
send this kind of login on an unencrypted connection. Respect a selected port,
the existing certificate policy, DNS/proxy settings and read/target stop controls.
Use a new owned connection for a failed attempt rather than reusing one in an
uncertain state.

Use only the explicitly selected username and password. Do not switch to the
logged-in Windows account. Hashes and selected Kerberos credentials keep their
existing methods and do not gain this fallback. A known rejected-account reply
stops before another method or username spelling is tried, using the approved
rejected-password fix. A failed encryption upgrade cannot proceed to password
submission.

The Go name-order checks remain exact: for `MAYYHEM\domainadmin`, the configured
DNS-domain name comes first, followed by the supplied Windows name and its
`domainadmin@MAYYHEM` form. An already supplied email-style name stays intact. A
bare username tries the configured-domain form before the bare form. Avoid
duplicate spellings. Preserve any explicitly supplied directory distinguished
name rather than interpreting it as a Windows account name.

## Location and effects

The shared client owns directory connection/login planning, the rejected-account
stop rule and connection cleanup. Adding the actual fallback there avoids a
second directory-login implementation in MSSQL and permits a separately reviewed
CMBP adoption if a concrete need appears. CMBP's behavior does not change under
this proposal. Its approved rejected-password correction still applies normally.

Likely implementation boundaries are `AdClient` construction, `_select_auth_modes`,
`_build_attempt_plan` and `_open_connection` in `clients/ad.py`, plus MSSQL's client
construction points. Retain public error/outcome handling and safe logging.
Update both relevant READMEs, MSSQL architecture and the reference map in the same
feature. Do not claim the two username tests complete until they exercise the
actual added login path.

Use the existing ldap3 package; no dependency, process, temporary credential file,
permission, lab account, service setting, graph or OpenHound-core edit is needed.
This changes shared behavior only for callers that select the new option, so
the owner's shared-repository proposal rule applies before editing runtime code.

## Checks and limits

Check the exact two Go username tables through actual connection construction and
login attempts. Check preferred-method success without fallback, permitted failure
followed by encrypted-password success, failed encryption with zero password
submissions, selected ports, hashes/Kerberos without fallback, rejected accounts
without another submission, owned cleanup, cancellation and safe failure reports.
Verify unchanged default planning for CMBP and other callers.

A successful read-only lab login using this method can confirm interoperability
without changing the domain controller. Existing lab authorization covers that
testing. No live wrong-password test or server policy change is proposed.
Verify the exact installed ldap3 2.10.2rc4 source before implementation; the current
2.10.2 documentation describes the established SIMPLE/StartTLS interfaces, but
does not by itself prove every release-candidate implementation detail.

## Alternatives and source evidence

The owner can instead explicitly exclude these two Go checks and retain current
password behavior. Merely excluding them as language-specific would be inaccurate:
the underlying login method is a real missing capability. Adding an unused name
helper would hide that gap. Automatically enabling it in every collector would
change CMBP without demonstrating a need, so an opt-in shared setting is preferred.

Reviewed reference: pinned `internal/ad/client_test.go` and `client.go`, commit
`92efaeb892cd3e43dbdd5b4308dbf55383db1453`. Go's inner username loop does not itself
stop on a rejected-password reply; retain our approved stop rule across every
username submission instead of copying that retry behavior.

Primary documentation checked October 29, 2026:

- [ldap3 bind operations](https://ldap3.readthedocs.io/en/latest/bind.html)
- [ldap3 connection authentication choices](https://ldap3.readthedocs.io/en/latest/connection.html)
- [ldap3 SSL and TLS](https://ldap3.readthedocs.io/en/latest/ssltls.html)
- [Microsoft's LDAP signing and channel-binding guidance](https://support.microsoft.com/en-us/servicing/os/windows/2020/02/2020-2023-and-2024-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412)

## Lab check, October 30, 2026

The owner asked for a read-only lab check before deciding. A short script asked
the lab domain controller how it answers Go's username spellings. It used an
encrypted connection to `dc.mayyhem.com` with a verified certificate. Nothing
was searched, written or changed.

The script tried five spellings with the documented `MAYYHEM\lowpriv` password:
Go's three spellings, the account name with an unrelated domain, and an account
name that does not exist. All five received the same reply: LDAP result 49,
`invalidCredentials`, `data 52e`.

A follow-up read-only directory query found that `lowpriv` does not exist in the
lab domain. None of the five spellings matched an account, so no real account
received a wrong password. The domain's lockout threshold is zero, so no account
could have been locked.

**What this shows.** Active Directory answers a username that matches no account
with exactly the reply it uses for a wrong password. The approved stop rule treats
`data 52e` as a rejected password and stops. Suppose Go's first spelling fails
because it names no account. Under that rule, the second and third spellings are
never tried. They could run only after an unusual reply that is not a password
rejection.

## Follow-up lab check, October 30, 2026

The owner asked whether different spellings of one username count as separate
failed sign-ins against the same account. The owner also asked for `lowpriv` to
be created, and allowed `MAYYHEM\domainadmin` for checks. `lowpriv` was created
as an ordinary domain user with the documented password and no extra groups.

A second script signed in as `lowpriv` over the same verified encrypted
connection. After each attempt it read `lowpriv`'s failed sign-in counter,
`badPwdCount`, as `domainadmin`. A final correct sign-in reset the counter to 0.

| Spelling | Correct password | Wrong password | Counter after |
|---|---|---|---|
| `lowpriv@mayyhem.com` (Go's first) | Accepted | Rejected, `52e` | 1 |
| `MAYYHEM\lowpriv` (Go's second) | Accepted | Rejected, `52e` | 2 |
| `lowpriv@MAYYHEM` (Go's third) | Accepted | Rejected, `52e` | 3 |
| `lowpriv@other.example` (no match) | Rejected, `52e` | Rejected, `52e` | 3 |
| `no-such-user-q30@mayyhem.com` (no match) | Rejected, `52e` | Rejected, `52e` | 3 |

**What this shows.** Every spelling that matches the account counts as its own
failed sign-in against that account. With a wrong password, Go's three spellings
cost three failed sign-ins in a single attempt. In a domain that locks accounts
after a few failures, that can lock the account quickly. Spellings that match no
account count against nobody, but the reply looks identical, so the collector
cannot tell the two cases apart.

The approved stop rule therefore matters. The collector stops at the first
`52e`, so it costs at most one failed sign-in.

**Recommendation.** Exclude the two Go username-order tests, and record this lab
evidence as the reason. Do not copy Go's three-spelling retry. If the encrypted
password login is added later, try only the username exactly as the user typed
it. All three forms worked in this lab, and the typed form is the one most
likely to match the intended account.

Evidence in the private feature-work folder:

- `simple-bind-spellings-lab.json` and `tests/simple_bind_spellings_probe.py`
  from the first check
- `simple-bind-bad-password-count-lab.json` and
  `tests/simple_bind_bad_password_count_probe.py` from the follow-up

No code or reference exclusions have been changed for this draft.
