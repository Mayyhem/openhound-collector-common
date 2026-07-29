"""Unit tests for openhound_collector_common.logging.log_context."""
import logging

from openhound_collector_common.logging import log_context as lc


def test_verbose_level_registered():
    """Importing the module registers VERBOSE (15) and a logger.verbose() method."""
    assert lc.VERBOSE == 15
    assert logging.getLevelName(15) == "VERBOSE"
    logger = logging.getLogger("test_verbose_level_registered")
    assert hasattr(logger, "verbose")


class _CapturingHandler(logging.Handler):
    """Collects formatted messages so a test can assert on the rendered text."""

    def __init__(self):
        super().__init__()
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        # getMessage() applies args to the (possibly prefixed) format string.
        self.messages.append(record.getMessage())


def _make_logger(name: str) -> tuple[logging.Logger, _CapturingHandler]:
    logger = logging.getLogger(name)
    logger.setLevel(lc.VERBOSE)
    logger.handlers.clear()
    logger.propagate = False
    handler = _CapturingHandler()
    handler.addFilter(lc.LogContextFilter())
    logger.addHandler(handler)
    return logger, handler


def test_verbose_logger_emits_at_verbose_level():
    """logger.verbose(...) actually emits a record at the VERBOSE level."""
    logger, handler = _make_logger("test_verbose_logger_emits")
    logger.verbose("hello %s", "world")
    assert handler.messages == ["hello world"]


def test_target_context_folds_prefix_into_record():
    """with_log_context / target_context fold [target] into the rendered message."""
    logger, handler = _make_logger("test_target_context_prefix")

    with lc.target_context("ps1-db.mayyhem.com"):
        logger.info("probing port 1433")
    # Outside the context, no prefix is added.
    logger.info("done")

    assert handler.messages == [
        "[ps1-db.mayyhem.com] probing port 1433",
        "done",
    ]


def test_target_and_phase_both_present():
    """Both [target] and [phase] are folded, target first then phase."""
    logger, handler = _make_logger("test_target_and_phase")

    with lc.target_context("host1"), lc.phase_context("LDAP"):
        logger.warning("searching SPNs")

    assert handler.messages == ["[host1][LDAP] searching SPNs"]


def test_contextvar_restored_after_block():
    """target_context restores the previous (None) value on exit."""
    assert lc.get_current_target() is None
    with lc.target_context("temp"):
        assert lc.get_current_target() == "temp"
    assert lc.get_current_target() is None


def test_with_log_context_decorator_on_function():
    """The decorator tags log lines emitted inside a plain function."""
    logger, handler = _make_logger("test_decorator_function")

    @lc.with_log_context(phase="COLLECT", target="srv")
    def do_work():
        logger.info("working")

    do_work()
    assert handler.messages == ["[srv][COLLECT] working"]


def test_with_log_context_decorator_on_generator():
    """The decorator keeps context active across a generator's yields."""
    logger, handler = _make_logger("test_decorator_generator")

    @lc.with_log_context(phase="SCAN", target="gen-host")
    def gen():
        logger.info("first")
        yield 1
        logger.info("second")
        yield 2

    values = list(gen())
    assert values == [1, 2]
    assert handler.messages == [
        "[gen-host][SCAN] first",
        "[gen-host][SCAN] second",
    ]


def test_with_log_context_target_from_ctx_attr():
    """target_from_ctx_attr reads the target off the first positional arg."""
    logger, handler = _make_logger("test_decorator_ctx_attr")

    class Ctx:
        domain = "MAYYHEM.COM"

    @lc.with_log_context(phase="LDAP", target_from_ctx_attr="domain")
    def resource(ctx):
        logger.info("enumerating")

    resource(Ctx())
    assert handler.messages == ["[MAYYHEM.COM][LDAP] enumerating"]


def test_install_filter_is_idempotent():
    """install_filter adds the singleton at most once on the root logger."""
    root = logging.getLogger()
    before = list(root.filters)
    lc.install_filter()
    lc.install_filter()
    count = sum(1 for f in root.filters if isinstance(f, lc.LogContextFilter))
    assert count == 1
    # Clean up so we don't perturb other tests' root logger state.
    for f in list(root.filters):
        if isinstance(f, lc.LogContextFilter) and f not in before:
            root.removeFilter(f)
