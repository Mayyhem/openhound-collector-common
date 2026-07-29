"""make_resolver(force_tcp=True) must actually force TCP on resolve()."""
from openhound_collector_common.discovery.dns import make_resolver


def test_force_tcp_defaults_resolve_to_tcp(monkeypatch):
    import dns.resolver
    seen = {}

    def _fake_resolve(self, qname, rdtype=None, *args, **kwargs):
        seen["tcp"] = kwargs.get("tcp")
        return []

    # Patch the CLASS method BEFORE make_resolver runs, so make_resolver's
    # wrapper captures this fake as its _orig_resolve bound method.
    monkeypatch.setattr(dns.resolver.Resolver, "resolve", _fake_resolve, raising=True)
    resolver = make_resolver("10.0.0.1", force_tcp=True)
    resolver.resolve("_ldap._tcp.example.com", "SRV")
    assert seen["tcp"] is True


def test_no_force_tcp_leaves_resolve_untouched():
    resolver = make_resolver("10.0.0.1", force_tcp=False)
    # No wrapper: resolve is the class method, not a per-instance closure.
    assert "resolve" not in resolver.__dict__


def test_force_tcp_bare_resolve_forwards_without_rdtype(monkeypatch):
    import dns.resolver
    seen = {}

    def _fake_resolve(self, qname, *args, **kwargs):
        seen["args"] = args
        seen["tcp"] = kwargs.get("tcp")
        return []

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", _fake_resolve, raising=True)
    resolver = make_resolver("10.0.0.1", force_tcp=True)
    resolver.resolve("example.com")  # no rdtype — wrapper must NOT inject rdtype=None
    assert seen["tcp"] is True
    assert seen["args"] == ()  # nothing extra forwarded (no bogus rdtype)
