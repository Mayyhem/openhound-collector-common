"""impacket's Python 3.14 SyntaxWarning must not reach a collector's console.

impacket 0.13.1's `mssql/version.py:182` returns from inside a `finally` block.
Python 3.14 reports that as a SyntaxWarning, emitted by the COMPILER -- so it
fires once, when the module's bytecode is first built, and never again while a
valid .pyc exists. `clients/mssql.py` imports `impacket.tds` at module level,
and `tds.py:54` imports the offending module, so the warning surfaces on the
operator's console as noise about a third-party file they cannot act on.

Testing this needs care on two counts:

* The warning only fires on a COMPILE. A test that merely imports the module
  passes for the wrong reason as soon as the venv has a cached .pyc.
  `PYTHONPYCACHEPREFIX` redirects the whole bytecode cache into an empty tmp
  directory, which forces a recompile WITHOUT deleting anything from the venv
  (which would be a side effect on a shared environment, and racy under -n).
* `-W error::SyntaxWarning` promotes the warning at compile time, where it
  surfaces as a `SyntaxError`, not a `SyntaxWarning`. So assert on the
  subprocess exit status rather than trying to catch a specific type.
"""
import os
import subprocess
import sys
import textwrap

import pytest


def test_importing_mssql_client_emits_no_syntax_warning(tmp_path):
    program = textwrap.dedent(
        """
        import warnings
        warnings.simplefilter("error", SyntaxWarning)
        import openhound_collector_common.clients.mssql  # must not raise
        print("clean")
        """
    )
    env = {**os.environ, "PYTHONPYCACHEPREFIX": str(tmp_path)}
    done = subprocess.run(
        [sys.executable, "-c", program], capture_output=True, text=True, env=env
    )
    assert done.returncode == 0, (
        "importing clients.mssql raised on a forced recompile -- the impacket "
        f"SyntaxWarning guard is missing or ineffective:\n{done.stderr}"
    )
    assert "clean" in done.stdout, done.stdout


@pytest.mark.skipif(
    sys.version_info < (3, 14),
    reason="Python 3.14 introduced the return-in-finally SyntaxWarning (PEP 765)",
)
def test_the_guard_is_scoped_and_does_not_hide_our_own_return_in_finally(tmp_path):
    """The guard must not leave a process-wide filter behind.

    A global `filterwarnings(message=...)` would also silence a return-in-finally
    written in OUR code, or any other dependency's. Importing the module and then
    compiling such a function must still warn.
    """
    program = textwrap.dedent(
        """
        import warnings
        import openhound_collector_common.clients.mssql  # installs nothing global
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            compile("def f():\\n try:\\n  pass\\n finally:\\n  return 1\\n", "ours.py", "exec")
        assert any("finally" in str(w.message) for w in caught), \\
            "our own return-in-finally was silenced by a leaked global filter"
        print("scoped")
        """
    )
    env = {**os.environ, "PYTHONPYCACHEPREFIX": str(tmp_path)}
    done = subprocess.run(
        [sys.executable, "-c", program], capture_output=True, text=True, env=env
    )
    assert done.returncode == 0, done.stderr
    assert "scoped" in done.stdout, done.stdout
