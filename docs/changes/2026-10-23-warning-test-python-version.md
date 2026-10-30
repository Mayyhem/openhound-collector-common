# Match the warning test to the Python version

The shared package supports Python 3.13 and 3.14. Its import tests include a
check that importing the SQL client does not suppress warnings from unrelated
code. That check compiles a function containing a return from a finally block.
Python only started warning about this in 3.14, so the check incorrectly failed
on 3.13 even when the client did nothing wrong.

The owner approved running that one warning-specific check on Python 3.14 and
later. The separate import check still runs on every supported Python version.
This changes test selection, not the SQL client or its warning handling. No new
dependency or package setting is needed. Removing the check would lose useful
coverage on Python 3.14; changing production warning filters would address the
wrong problem.

The condition is next to the test in
[`tests/test_impacket_import_quiet.py`](../../tests/test_impacket_import_quiet.py).
Python documents the warning in
[the Python 3.14 release notes](https://docs.python.org/3.14/whatsnew/3.14.html#pep-765-control-flow-in-finally-blocks).

## Verification

Run in an isolated project environment:

```powershell
uv run --locked pytest tests/test_impacket_import_quiet.py -q
```

On Python 3.13, the import test must pass and the warning-specific test must
report its explicit version-based skip. On Python 3.14, both tests must run.
Results from the feature-completion work are recorded in its collector status
document. Python 3.14 validation is still required before claiming that coverage.

Suggested owner commit after review:

```powershell
git add -- tests/test_impacket_import_quiet.py docs/changes/2026-10-23-warning-test-python-version.md
git commit -m "Fix warning-test selection on Python 3.13" -m "Run the PEP 765 warning-isolation check only where Python emits that warning. Preserve the import check on both supported versions; production behavior and dependencies are unchanged."
```

The agent does not stage, commit, or push.
