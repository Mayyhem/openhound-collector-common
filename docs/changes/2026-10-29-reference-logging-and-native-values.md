# Reference checks for shared logging and Windows values

These six test-only checks are part of the approved Go-reference work. They
change no shared behavior, collector defaults, dependencies or graph records.

`tests/test_reference_logging_contracts.py` retains Go's four handler contracts
through Python's existing logger and common formatter: message/field fan-out,
independent severity thresholds, a bound target in both outputs, and named/empty
operation context with the same handlers. The checks use isolated in-memory
streams. No new handler wrapper or application logging setup is needed.

`tests/test_windows_reference_contracts.py` retains the exact two Go domain/DN
inputs, including surrounding whitespace, through the existing explicit-domain
selection and AD client construction. It also checks the exact 28-byte public
SID vector and two-byte short input. Python's unknown SID is None rather than
Go's empty string. No domain lookup, bind or network call occurs.

The domain normalization stays at its existing input boundary rather than
adding a second DN-normalizing helper. The logger uses its existing native
fan-out rather than copying Go-specific wrappers. These alternatives keep the
implementation readable without dropping the underlying assertions.

These checks plus the mapped NTLM/LDAP contracts passed **51 tests**, with Ruff
clean. Actual evidence is `.tmp/q29-collector-contracts-common-results.xml`.
The preceding complete common checkpoint passed 535 tests/one expected version
skip; these six test-only contracts were added afterward, so a complete 541-test
pass is not claimed. SQL's independent auditor consumed the real common JUnit
report, its own 699-check report and the later passing output-format check. After
the owner excluded only the optional file-format address, that audit confirmed
429 reference records and failed on nineteen remaining gaps. Full feature
acceptance remains unfinished.

Manual verification from the declared common environment:

```powershell
uv run --locked pytest tests/test_reference_logging_contracts.py tests/test_windows_reference_contracts.py -q
uv run --locked ruff check --no-cache tests/test_reference_logging_contracts.py tests/test_windows_reference_contracts.py
```

Suggested owner commit after reviewing the shared tests and SQL mapping notes:

```powershell
git add tests/test_reference_logging_contracts.py tests/test_windows_reference_contracts.py README.md docs/changes/2026-10-29-reference-logging-and-native-values.md
git commit -m "Verify shared logging and Windows value reference contracts"
```

No staging, commits, pushes or publication were performed. The remaining runtime
format-link proposal was subsequently declined. The shared writer stays unchanged.
