"""Verify per-call DNS budgets without sending a query outside this process."""

from threading import Event
import time

import dns.exception
import dns.resolver
import pytest

from openhound_collector_common.clients.operations import ReadControl, ReadStoppedError
from openhound_collector_common.clients.deadline import Deadline
from openhound_collector_common.discovery.dns import make_resolver


def test_dns_uses_shorter_parent_remaining_time_and_forces_proxy_tcp(monkeypatch):
    calls = []

    def resolve(
        self,
        qname,
        rdtype,
        rdclass,
        tcp,
        source,
        raise_on_no_answer,
        source_port,
        lifetime,
        search,
    ):
        calls.append((qname, tcp, lifetime))
        return "answer"

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", resolve)
    resolver = make_resolver(force_tcp=True, read_control=ReadControl(5))
    parent = ReadControl(2, Deadline.after(0.3)).operation(
        "owned SQL fixture", lambda: None
    )
    with parent:
        assert (
            resolver.resolve("dc.example.invalid", lifetime=20, tcp=False) == "answer"
        )
        # Resolve() also accepts lifetime/TCP by position; do not duplicate them.
        assert (
            resolver.resolve("dc.example.invalid", "A", "IN", False, None, True, 0, 0.1)
            == "answer"
        )
    assert all(tcp for name, tcp, budget in calls)
    assert 0 < calls[0][2] <= 0.3
    assert calls[1][2] <= 0.1


def test_stop_during_a_bounded_dns_call_rejects_its_late_answer(monkeypatch):
    stopped = Event()

    def resolve(*args):
        stopped.set()
        return "late answer must not be used"

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", resolve)
    resolver = make_resolver(read_control=ReadControl(1, stop_event=stopped))
    with pytest.raises(ReadStoppedError):
        resolver.resolve("fixture.invalid")
    with pytest.raises(ReadStoppedError):
        resolver.resolve("next-must-not-run.invalid")


def test_dns_timeout_is_a_stopped_read_when_its_elapsed_budget_expired(monkeypatch):
    def resolve(*args):
        # Use the passed public lifetime to model the provider's bounded wait.
        time.sleep(args[8] + 0.01)
        raise dns.exception.Timeout()

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", resolve)
    resolver = make_resolver(read_control=ReadControl(0.05))
    with pytest.raises(ReadStoppedError):
        resolver.resolve("fixture.invalid")


def test_ordinary_dns_miss_retains_its_meaning(monkeypatch):
    def resolve(*args):
        raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", resolve)
    resolver = make_resolver(read_control=ReadControl(1))
    with pytest.raises(dns.resolver.NXDOMAIN):
        resolver.resolve("missing.invalid")
