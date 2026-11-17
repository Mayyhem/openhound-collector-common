"""Read SQL addresses without confusing an instance name with a TCP port.

These records describe connection evidence, not graph identities. A named
instance needs an observed or supplied port before it can be contacted by name.
Collectors may separately try an anonymous conventional-port candidate; that
attempt does not resolve this named address.
An SPN without a port also leaves that port unknown; a registration is not a
measurement of the service's current configuration.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..logging import get_logger

logger = get_logger(__name__)
DEFAULT_PORT = 1433


@dataclass(frozen=True)
class SqlAddress:
    """A SQL host, optional instance name, and known TCP port, if any."""

    host: str
    port: int | None = None
    instance: str | None = None


def sql_port(value: str | int) -> int:
    """Require a TCP port in 1..65535; never replace invalid input with 1433."""
    text = str(value).strip()
    if not text.isascii() or not text.isdecimal() or not 1 <= int(text) <= 65535:
        logger.warning("SQL TCP port must be an integer from 1 to 65535")
        raise ValueError("A SQL TCP port must be an integer from 1 to 65535")
    # A valid numeric port needs no additional operational diagnostic.
    return int(text)


def parse_sql_address(
    value: str, *, default_port: int | None = DEFAULT_PORT
) -> SqlAddress:
    """Read host, host:port, host,port, host\\instance[:port], or an MSSQLSvc SPN.

    A bare connection hostname uses the caller's default. An instance name or
    an SPN with no numeric port stays unresolved. This matches the collectors'
    current hostname/IPv4 connection syntax; IPv6 support is not added here.
    """
    text = value.strip()
    is_spn = text.casefold().startswith("mssqlsvc/")
    if is_spn:
        text = text[len("MSSQLSvc/") :]
        default_port = None
        if "\\" in text:
            logger.warning("SQL SPNs use a colon before their port or instance name")
            raise ValueError("Use MSSQLSvc/host:portOrInstance for a SQL registration")
    # Ordinary connection strings retain the caller's explicit default.
    instance: str | None = None
    port: int | None = None
    if "\\" in text:
        host, remainder = text.split("\\", 1)
        instance = remainder
        if ":" in remainder or "," in remainder:
            instance, port_text = remainder.replace(",", ":").rsplit(":", 1)
            port = sql_port(port_text)
        # A name without a numeric suffix needs separate port resolution.
    else:
        host = text
        suffix: str | None = None
        if ":" in text or "," in text:
            if text.count(":") > 1:
                logger.warning("SQL address has more than one port separator")
                raise ValueError(
                    "SQL address needs one host and one port or instance suffix"
                )
            host, suffix = text.replace(",", ":").split(":", 1)
        # A plain hostname has no suffix to interpret.
        if suffix is not None:
            if suffix.isascii() and suffix.isdecimal():
                port = sql_port(suffix)
            elif suffix and "," not in text:
                instance = suffix
            else:
                logger.warning("SQL address has an empty or invalid port or instance")
                raise ValueError("A SQL port or instance name cannot be empty")
        elif not is_spn:
            port = sql_port(default_port) if default_port is not None else None
        # A bare SPN deliberately carries no TCP-port claim.
    if (
        not host
        or host != host.strip()
        or any(c.isspace() for c in host)
        or "/" in host
    ):
        logger.warning("SQL address has an empty or invalid host")
        raise ValueError("A SQL address needs a nonempty host without whitespace")
    if instance is not None and (
        not instance
        or instance != instance.strip()
        or any(character in instance for character in "\\/:,\x00")
    ):
        logger.warning("SQL address has an invalid instance name")
        raise ValueError("Invalid SQL instance name")
    logger.debug(
        "Parsed SQL address: host=%s instance=%s port=%s", host, instance, port
    )
    return SqlAddress(host, port, instance)


def parse_sql_spn(value: str) -> SqlAddress | None:
    """Read one MSSQLSvc registration; return None for another service class."""
    if not value.casefold().startswith("mssqlsvc/"):
        # AD accounts routinely have unrelated service registrations.
        return None
    return parse_sql_address(value, default_port=None)
