# More checks for the existing Windows directory reader

This is test-only work within the approved Go comparison effort. It changes no
shared behavior, dependencies, collector defaults, settings or graph output.

`tests/test_windows_ldap.py` now covers a successful empty search without a
reader change; the exact generic Go current-user failure; an explicit password
without a username; the default 1,000-entry Windows page request; and both Go
multiline diagnostics without repeating troubleshooting/signing paragraphs.
Existing pointer, page-continuation, binary-value, identity and cleanup checks
remain active. Python uses the owner's selected Windows LDAP reader instead of
Go's ADO component, preserving the page-size purpose without adding unused code.

The affected file passed **33 tests**, with Ruff clean. SQL's actual scan-all
selection and timeout tests also passed. The combined execution auditor confirms
437 reference records and retains eleven unfinished records; it does not turn
those gaps into passing coverage. Evidence and SQL-specific behavior are in
`openhound-mssql/docs/changes/2026-10-29-native-discovery-reference.md`.

These checks make no live connection and need no credentials. Reproduce from
common's declared environment:

```powershell
uv run --locked pytest tests/test_windows_ldap.py -q
uv run --locked ruff check --no-cache tests/test_windows_ldap.py
```

Suggested owner commit after reviewing the shared test changes:

```powershell
git add tests/test_windows_ldap.py docs/changes/2026-10-29-native-reference-tests.md
git commit -m "Verify Windows fallback, paging and concise logs"
```

The separately found wrong-password spelling issue has its own approval proposal
in `2026-10-29-ldap-bad-password-proposal.md`. These tests do not implement that
fix. No staging, commits, pushes or publication were performed.
