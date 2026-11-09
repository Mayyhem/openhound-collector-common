"""Shared target indexes and allowed-target lists.

Collectors retain their own identity and record-merging rules. The allowed-target
list (``AllowedTargets``) is the shared safety boundary: it decides from names
and already-looked-up addresses whether a computer may be contacted at all.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Collection, Iterable, Mapping
from dataclasses import dataclass
from threading import RLock
from types import MappingProxyType
from typing import Generic, TypeVar, Union

from ..logging import get_logger

logger = get_logger(__name__)
Record = TypeVar("Record")
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

# A computer name: dot-separated labels of letters, digits, hyphens and
# underscores (Active Directory allows underscores). Anything else, such as a
# SQL instance ("host\\SQLEXPRESS"), a port ("host:1433") or a wildcard, is
# rejected so a typo cannot silently widen or empty the list.
_NAME_LABEL = r"[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?"
_COMPUTER_NAME = re.compile(rf"^{_NAME_LABEL}(?:\.{_NAME_LABEL})*$")
# Long range lists are summarized in messages after this many entries.
_RANGES_SHOWN_IN_MESSAGES = 5


class TargetRegistry(Generic[Record]):
    """Find the same caller-owned record by an identity or one of its names.

    The caller chooses what an identity means and when records should merge.
    Hold lock across a compound find/merge/bind decision so another worker cannot
    create a duplicate in between. Individual index operations also take that
    same reentrant lock. Alias views are read-only; record contents remain owned
    by the collector, such as SCCM site codes or SQL ports and instances.
    """

    def __init__(self, alias_key: Callable[[str], str] = str.lower) -> None:
        self.lock = RLock()
        self._alias_key = alias_key
        self._identities: dict[str, Record] = {}
        self._aliases: dict[str, Record] = {}

    @property
    def aliases(self) -> Mapping[str, Record]:
        """Expose current aliases without allowing unguarded index assignment."""
        return MappingProxyType(self._aliases)

    def find(self, identity: str | None, name: str) -> Record | None:
        """Prefer a caller-proven identity, then fall back to the supplied name."""
        with self.lock:
            if identity is not None:
                record = self._identities.get(identity)
                if record is not None:
                    return record
            return self._aliases.get(self._alias_key(name))

    def bind_identity(self, identity: str, record: Record) -> None:
        """Index an identity after the collector has established that it matches."""
        with self.lock:
            self._identities[identity] = record
            logger.debug("Registered a collection target identity")

    def bind_alias(self, name: str, record: Record) -> None:
        """Keep an old queued name usable when its record gains a better name."""
        with self.lock:
            self._aliases[self._alias_key(name)] = record
            logger.debug("Registered collection target alias %s", name)

    def snapshot(self, identity: Callable[[Record], str]) -> list[Record]:
        """Return each record once using the collector's stable snapshot key."""
        with self.lock:
            return list(
                {identity(record): record for record in self._aliases.values()}.values()
            )


def matches_allowed_targets(
    allowed: Collection[str],
    candidates: Iterable[str],
    normalize: Callable[[str], str] = str.lower,
) -> bool:
    """Match caller-supplied name forms; an empty allow-list allows every target.

    The caller expands its own names and normalizes the allow-list once when
    parsing configuration. This helper never strips a SQL port or instance,
    invents a short hostname, or performs a DNS lookup.
    """
    if not allowed:
        return True  # An absent include-only filter deliberately allows all.
    # The caller normalizes its allow-list once when parsing configuration.
    # Rebuilding a large set for every discovered host would be unnecessary.
    return any(normalize(value) in allowed for value in candidates)


@dataclass(frozen=True)
class ScopeDecision:
    """Whether a computer may be contacted, and a plain reason for logs and reports."""

    is_allowed: bool
    reason: str


class AllowedTargets:
    """An allowed-target list of computer names, single IP addresses and IP ranges.

    A computer is allowed when one of its names is on the list, or when every
    address its name points to is inside a listed range. One address outside is
    enough to refuse it: a name pointing outside the authorized ranges is not
    authorized. An empty list allows everything, which is how a run behaves
    when no list was given.

    Names ignore capital letters and a trailing dot. A listed full name also
    matches the same computer's short name, and a listed short name matches any
    full name that starts with it, the rule SCCM's ``--computers`` already uses.

    This class never looks anything up. Each collector passes the addresses it
    found with its own DNS and proxy settings.
    """

    def __init__(self, entries: Iterable[str] = ()) -> None:
        names: set[str] = set()
        networks: list[IPNetwork] = []
        kept: list[str] = []
        problems: list[str] = []
        for raw in entries:
            entry = raw.strip()
            if not entry:
                continue  # Blank entries, such as a trailing comma, add nothing.
            try:
                parsed = _parse_entry(entry)
            except ValueError as problem:
                # Collect every problem so one message lists all mistyped entries.
                problems.append(str(problem))
                continue
            if isinstance(parsed, str):
                names.add(parsed)
                kept.append(parsed)
            else:
                networks.append(parsed)
                kept.append(str(parsed))
        if problems:
            logger.error("The allowed-target list has entries that could not be read")
            raise ValueError("; ".join(problems))
        self._full_names = frozenset(name for name in names if "." in name)
        self._short_names = frozenset(name for name in names if "." not in name)
        self._first_labels_of_full_names = frozenset(
            name.split(".", 1)[0] for name in self._full_names
        )
        self._networks = tuple(networks)
        self.entries: tuple[str, ...] = tuple(kept)

    @property
    def is_empty(self) -> bool:
        """True when no list was given, so every computer is allowed."""
        return not self.entries

    @property
    def has_ranges(self) -> bool:
        """True when the list contains at least one address or range."""
        return bool(self._networks)

    def is_name_listed(self, name: str) -> bool:
        """True when *name* matches a listed name under the short/full-name rule."""
        candidate = _normalize_name(name)
        if not candidate:
            return False
        if candidate in self._full_names:
            return True
        first_label = candidate.split(".", 1)[0]
        if "." not in candidate and candidate in self._first_labels_of_full_names:
            return True  # A short name for a listed full name.
        return first_label in self._short_names  # A listed short name.

    def addresses_outside(self, addresses: Iterable[str]) -> list[str]:
        """Return each address that is not inside any listed range."""
        outside = []
        for text in addresses:
            address = _parse_address(text)
            if address is None or not any(
                address in network for network in self._networks
            ):
                outside.append(text)
        return outside

    def check(self, names: Iterable[str], addresses: Iterable[str]) -> ScopeDecision:
        """Decide whether a computer with these names and addresses may be contacted.

        *names* are the computer's known names. A name that is itself an IP
        address is treated as an address. *addresses* are what the collector's
        own lookup returned; pass none when the lookup failed.
        """
        name_list = [name for name in names if name and name.strip()]
        address_list = list(dict.fromkeys(addresses))
        for name in name_list:
            if _parse_address(name) is not None and name not in address_list:
                address_list.append(name)  # A numeric "name" is an address.
        label = (
            name_list[0] if name_list else ", ".join(address_list) or "This computer"
        )
        if self.is_empty:
            return ScopeDecision(True, "No allowed-target list was given")
        for name in name_list:
            if _parse_address(name) is None and self.is_name_listed(name):
                return ScopeDecision(True, f"{name} is on the allowed-target list")
        if not self._networks:
            return ScopeDecision(False, f"{label} is not on the allowed-target list")
        ranges = self._describe_ranges()
        if not address_list:
            return ScopeDecision(
                False,
                f"{label} could not be looked up, so it cannot be shown to be inside {ranges}",
            )
        outside = self.addresses_outside(address_list)
        if outside:
            pointing = "" if outside == [label] else f"{label} points to "
            return ScopeDecision(
                False,
                f"{pointing}{', '.join(outside)}, which is not in {ranges}",
            )
        if address_list == [label]:
            return ScopeDecision(True, f"{label} is inside {ranges}")
        return ScopeDecision(True, f"{label} points only to addresses inside {ranges}")

    def _describe_ranges(self) -> str:
        shown = [str(network) for network in self._networks[:_RANGES_SHOWN_IN_MESSAGES]]
        hidden = len(self._networks) - len(shown)
        if hidden:
            return ", ".join(shown) + f" or {hidden} more listed ranges"
        if len(shown) == 1:
            return shown[0]
        return ", ".join(shown[:-1]) + " or " + shown[-1]


def _normalize_name(name: str) -> str:
    """Lower-case a computer name and drop a trailing dot (a fully qualified spelling)."""
    return name.strip().lower().rstrip(".")


def _parse_address(text: str) -> IPAddress | None:
    """Return the address in *text*, ignoring an IPv6 zone such as ``%12``."""
    try:
        return ipaddress.ip_address(text.strip().strip("[]").split("%", 1)[0])
    except ValueError:
        return None  # Not an address; the caller treats it as a name or as unknown.


def _parse_entry(entry: str) -> str | IPNetwork:
    """Read one list entry as a range, a single address or a computer name.

    Returns a normalized name, or a network (a single address becomes a
    one-address range). Raises ValueError with a plain message for anything else.
    """
    if "/" in entry:
        try:
            return ipaddress.ip_network(entry, strict=True)
        except ValueError:
            try:
                intended = ipaddress.ip_network(entry, strict=False)
            except ValueError:
                raise ValueError(f"'{entry}' is not a valid IP range") from None
            raise ValueError(
                f"'{entry}' is not the start of its range; did you mean {intended}?"
            ) from None
    address = _parse_address(entry)
    if address is not None:
        return ipaddress.ip_network(address)
    name = _normalize_name(entry)
    if _COMPUTER_NAME.match(name):
        return name
    raise ValueError(
        f"'{entry}' is not a computer name, IP address or IP range "
        "(for example ps1-db.mayyhem.com, 10.10.11.51 or 10.10.11.0/24)"
    )
