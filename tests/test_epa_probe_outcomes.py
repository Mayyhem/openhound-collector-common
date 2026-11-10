"""An unanswered protection probe must never establish an unprotected SQL service."""

import pytest

from openhound_collector_common.clients.mssql import (
    EPAPrereqError,
    _classify_binding,
    _ProbeOutcome,
)


@pytest.mark.parametrize("mode", ["bogus_cbt", "bogus_service"])
@pytest.mark.parametrize("message", ["timed out", "connection reset", "unrecognized SQL error"])
def test_inconclusive_bogus_probe_is_unknown(mode, message):
    calls = []

    def probe(requested):
        calls.append(requested)
        return _ProbeOutcome(error_message=message)

    with pytest.raises(EPAPrereqError, match=mode):
        _classify_binding(probe, mode, "missing", "explicit")
    assert calls == [mode]


@pytest.mark.parametrize("auth_method", ["explicit", "sspi"])
def test_inconclusive_missing_probe_is_not_allowed(auth_method):
    outcomes = {
        "bogus": _ProbeOutcome(is_untrusted_domain=True),
        "missing": _ProbeOutcome(error_message="timed out"),
    }
    with pytest.raises(EPAPrereqError, match="missing"):
        _classify_binding(outcomes.__getitem__, "bogus", "missing", auth_method)


@pytest.mark.parametrize("accepted", [
    _ProbeOutcome(success=True),
    _ProbeOutcome(is_login_failed=True),
])
def test_completed_login_results_preserve_off_and_allowed(accepted):
    assert _classify_binding(lambda _: accepted, "bogus", "missing", "explicit") == "Off"
    outcomes = {"bogus": _ProbeOutcome(is_untrusted_domain=True), "missing": accepted}
    assert _classify_binding(outcomes.__getitem__, "bogus", "missing", "explicit") == "Allowed"


@pytest.mark.parametrize("auth_method,expected", [("explicit", "Required"), ("sspi", "Allowed/Required")])
def test_known_binding_rejections_preserve_required_and_sspi_ambiguity(auth_method, expected):
    assert _classify_binding(
        lambda _: _ProbeOutcome(is_untrusted_domain=True), "bogus", "missing", auth_method,
    ) == expected
