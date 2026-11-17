"""Try the conventional SQL port without claiming it belongs to a named engine."""

from __future__ import annotations

from collections.abc import Mapping
from threading import Lock

from ..logging import get_logger
from .sql_server import DEFAULT_PORT, SqlAddress

logger = get_logger(__name__)

SQL_INSTANCE_QUERY = (
    "SELECT SERVERPROPERTY('ServerName') AS ServerName, "
    "SERVERPROPERTY('InstanceName') AS InstanceName"
)


def sql_instance_name(row: Mapping[str, object]) -> str:
    """Read an engine's own identity; distinguish an unread value from default.

    SQL returns NULL for the default instance. Require the accompanying server
    name so a missing result cannot accidentally identify that default instance.
    Call this only with a row read from the connected SQL engine.
    """
    fields = {key.casefold(): value for key, value in row.items()}
    server = fields.get("servername")
    instance = fields.get("instancename")
    if (
        not isinstance(server, str)
        or not server.strip()
        or "instancename" not in fields
    ):
        logger.warning("SQL did not return a complete instance identity")
        raise ValueError("SQL instance identity is unread")
    if instance is None and "\\" not in server:
        logger.debug("SQL identified its default instance")
        return "MSSQLSERVER"
    if (
        isinstance(instance, str)
        and instance.strip()
        and server.casefold().endswith("\\" + instance.casefold())
    ):
        logger.debug("SQL identified its named instance %s", instance)
        return instance
    logger.warning("SQL returned an inconsistent instance identity")
    raise ValueError("SQL instance identity is inconsistent")


class SqlPortFallback:
    """Reserve one fallback endpoint per host for one collection run.

    Callers keep their existing TCP/login clients, timeouts, proxy and graph
    rules. Reserving an address is permission to try it, never evidence that
    SQL answered or that a requested instance uses it. Known 1433 endpoints
    should be remembered before workers start, avoiding a duplicate fallback.
    """

    def __init__(self) -> None:
        self._hosts: set[str] = set()
        self._lock = Lock()

    def remember(
        self, host: str, port: int, *, host_identity: str | None = None
    ) -> None:
        """Avoid a fallback when this host already has a known 1433 endpoint."""
        if port != DEFAULT_PORT:
            return  # Other ports do not cover the conventional endpoint.
        with self._lock:
            self._hosts.add(host.casefold().rstrip("."))
            if host_identity:
                self._hosts.add(host_identity.casefold())
            # An unavailable computer identity leaves hostname-based tracking.

    def claim(
        self, host: str, *, host_identity: str | None = None
    ) -> SqlAddress | None:
        """Return an anonymous 1433 candidate once; never attach an instance name."""
        with self._lock:
            key = host.casefold().rstrip(".")
            keys = {key}
            if host_identity:
                keys.add(host_identity.casefold())
            # Reuse an existing AD identity without performing another DNS query.
            if self._hosts.intersection(keys):
                self._hosts.update(keys)
                logger.debug("SQL port 1433 on %s is already covered in this run", host)
                return None
            self._hosts.update(keys)
        logger.warning(
            "SQL instance port is unresolved on %s; trying TCP 1433 without assuming an instance identity",
            host,
        )
        return SqlAddress(host, DEFAULT_PORT)
