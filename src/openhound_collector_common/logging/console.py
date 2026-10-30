"""Opt-in MSSQLHound-style console records using the existing shared log context.

Importing this module changes no handlers or levels. Existing collectors keep
their current output unless they explicitly select this formatter.
"""

from __future__ import annotations

import logging
import os
import re
import sys
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TextIO, TypeAlias

from .log_context import VERBOSE, get_current_phase, get_current_target

LogValue: TypeAlias = str | bool | int | float | None | list[str]
_RESET = "\x1b[0m"
_DIM = "\x1b[2m"
# The pinned reference's palette order is part of its FNV-1a target color rule.
_TARGET_PALETTE = (
    124,
    131,
    167,
    173,
    203,
    208,
    209,
    136,
    143,
    179,
    186,
    222,
    37,
    49,
    77,
    84,
    114,
    120,
    150,
    27,
    33,
    39,
    51,
    69,
    75,
    80,
    111,
    117,
    63,
    105,
    135,
    141,
    147,
    176,
    183,
    189,
)
_SECRET_KEY = re.compile(
    r"(^|_)(password|passwd|hash|ticket|token|keytab|secret|authorization|ccache|response)(_|$)",
    re.IGNORECASE,
)
_URL_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://")


def is_secret_field(name: str) -> bool:
    """Recognize both camelCase and underscore-separated credential field names."""
    separated = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name)
    separated = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", separated)
    return _SECRET_KEY.search(separated.replace("-", "_")) is not None


class SecretRedactor:
    """Remove explicitly supplied secrets and inline credentials from log text."""

    def __init__(self, secrets: Iterable[str] = ()) -> None:
        # Longest first avoids partially replacing a secret that contains another.
        self._secrets = tuple(
            sorted({value for value in secrets if value}, key=len, reverse=True)
        )

    def redact(self, text: str) -> str:
        """Return safe text without changing a shared LogRecord for other handlers."""
        for secret in self._secrets:
            text = text.replace(secret, "<redacted>")
        if "@" not in text:
            return text  # Most diagnostic messages contain no inline credentials.
        # Process each whitespace-delimited token once. Searching an unanchored
        # credential pattern repeatedly can stall on a large ordinary message.
        return re.sub(r"\S+", self._redact_inline_token, text)

    @staticmethod
    def _redact_inline_token(match: re.Match[str]) -> str:
        token = match.group()
        credentials, separator, endpoint = token.rpartition("@")
        if not separator:
            return token  # A token without @ cannot contain inline credentials.
        scheme_match = _URL_SCHEME.match(credentials)
        scheme = scheme_match.group() if scheme_match else ""
        credentials = credentials[len(scheme) :]
        username, colon, _password = credentials.partition(":")
        if not colon or not username:
            return token  # Ordinary user@domain text is not an inline password.
        return f"{scheme}{username}:<redacted>@{endpoint}"


def log_event(
    logger: logging.Logger, level: int, message: str, **fields: LogValue
) -> None:
    """Emit ordered, typed detail fields through the ordinary shared logger."""
    for name, value in fields.items():
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) is None:
            raise ValueError(
                "Log detail names must contain only letters, digits, and underscores"
            )
        if not (
            value is None
            or isinstance(value, (str, bool, int, float))
            or isinstance(value, list)
            and all(isinstance(item, str) for item in value)
        ):
            raise ValueError("Log details must be scalars or lists of strings")
        # Routine shape validation needs no log; invalid values are never printed.
    safe_fields = tuple(
        (key, "<redacted>" if is_secret_field(key) else value)
        for key, value in fields.items()
    )
    logger.log(level, message, extra={"_oh_fields": safe_fields})


def _value_text(value: LogValue) -> str:
    """Render the scalar and string-list field types used by the pinned reference."""
    # These are formatting choices only, without an operational outcome to log.
    if value is None:
        return "<nil>"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        return "[" + " ".join(value) + "]"
    return str(value)


def _target_color(target: str) -> str:
    """Use the reference's 32-bit FNV-1a hash over UTF-8 target bytes."""
    digest = 2166136261
    for byte in target.encode("utf-8"):
        digest = ((digest ^ byte) * 16777619) & 0xFFFFFFFF
    return f"\x1b[38;5;{_TARGET_PALETTE[digest % len(_TARGET_PALETTE)]}m"


class GoConsoleFormatter(logging.Formatter):
    """Render UTC whole-second records, target context, and ordered safe fields.

    The caller selects terminal color once and supplies the run's known secrets.
    Other file handlers can keep their own formats and independent log levels.
    """

    def __init__(self, *, color: bool = False, secrets: Iterable[str] = ()) -> None:
        super().__init__()
        self.color = color
        self.redactor = SecretRedactor(secrets)

    def format(self, record: logging.LogRecord) -> str:
        """Format one complete record without mutating it or duplicating context."""
        # These branches choose presentation only; failures are already log records.
        if record.levelno >= logging.ERROR:
            level, level_color = "ERROR", "\x1b[31m"
        elif record.levelno >= logging.WARNING:
            level, level_color = "WARNING", "\x1b[33m"
        elif record.levelno >= logging.INFO:
            level, level_color = "INFO", ""
        elif record.levelno >= VERBOSE:
            level, level_color = "VERBOSE", "\x1b[90m"
        else:
            level, level_color = "DEBUG", "\x1b[35m"
        label = f"{level:<7}"
        if self.color:
            label = level_color + label + _RESET
        timestamp = datetime.fromtimestamp(record.created, timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        parts = [label, timestamp]
        fields = list(getattr(record, "_oh_fields", ()))
        target = (
            getattr(record, "_oh_target", None)
            or getattr(record, "target", None)
            or get_current_target()
            or next((value for key, value in fields if key == "target"), None)
        )
        if target:
            text = "[" + self.redactor.redact(str(target)) + "]"
            parts.append(
                _target_color(str(target)) + text + _RESET if self.color else text
            )
        message = getattr(record, "_oh_original_message", None)
        parts.append(
            self.redactor.redact(
                message if message is not None else record.getMessage()
            )
        )
        phase = getattr(record, "_oh_phase", None) or get_current_phase()
        if phase and not any(key == "phase" for key, _value in fields):
            fields.append(("phase", phase))
        for key, value in fields:
            if key == "target":
                # Target context is rendered once, above.
                continue
            text = (
                "<redacted>"
                if is_secret_field(key)
                else self.redactor.redact(_value_text(value))
            )
            field_key = _DIM + key + "=" + _RESET if self.color else key + "="
            parts.append(field_key + text)
        return " ".join(parts)


def console_supports_color(stream: TextIO, *, no_color: bool = False) -> bool:
    """Use color only for a real terminal, enabling Windows terminal processing."""
    if no_color or not stream.isatty():
        # Redirected or explicitly plain output needs no terminal setup.
        return False
    if os.name != "nt":
        return True
    # Match the Windows reference's GetConsoleMode/SetConsoleMode behavior.
    import ctypes
    import msvcrt
    from ctypes import wintypes

    try:
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetConsoleMode.argtypes = (
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.DWORD),
        )
        kernel.SetConsoleMode.argtypes = (wintypes.HANDLE, wintypes.DWORD)
        kernel.GetConsoleMode.restype = kernel.SetConsoleMode.restype = wintypes.BOOL
        handle = msvcrt.get_osfhandle(stream.fileno())
        mode = wintypes.DWORD()
        if not kernel.GetConsoleMode(handle, ctypes.byref(mode)):
            # A terminal without console-mode access gets safe plain text.
            return False
        return bool(
            mode.value & 0x0004 or kernel.SetConsoleMode(handle, mode.value | 0x0004)
        )
    except (OSError, ValueError):
        # Color is optional; failed terminal detection must not affect collection.
        return False


class _RedactingFormatter(logging.Formatter):
    """Keep an existing file format while removing this run's known secrets."""

    def __init__(self, original: logging.Formatter, secrets: tuple[str, ...]) -> None:
        super().__init__()
        self.original = original
        self.redactor = SecretRedactor(secrets)

    def format(self, record: logging.LogRecord) -> str:
        return self.redactor.redact(self.original.format(record))


class _ConsoleFilter(logging.Filter):
    """Keep ordinary collector messages and meaningful dependency failures."""

    def __init__(self, namespaces: tuple[str, ...], debug: bool) -> None:
        super().__init__()
        self.namespaces = namespaces
        self.debug = debug

    def filter(self, record: logging.LogRecord) -> bool:
        # Routine dependency chatter is available when debug was explicitly chosen.
        return (
            self.debug
            or record.levelno >= logging.WARNING
            or record.name.startswith(self.namespaces)
        )


@dataclass(frozen=True)
class ConsoleSettings:
    """A caller's explicit console choices, reusable after a framework stage reset.

    Nothing is installed until apply() is called. File handlers remain attached
    with their existing layout and independent levels. The caller supplies its
    own namespaces and known secrets; the shared library imports no collector.
    """

    namespaces: tuple[str, ...]
    level: int = logging.INFO
    silent: bool = False
    no_color: bool = False
    secrets: tuple[str, ...] = field(default=(), repr=False)

    def apply(self) -> None:
        """Install one stderr handler and preserve/redact existing file handlers."""
        root = logging.getLogger()
        for name in ("", "dlt", "openhound"):
            current = logging.getLogger(name)
            for handler in list(current.handlers):
                if isinstance(handler, logging.FileHandler):
                    original = handler.formatter or logging.Formatter("%(message)s")
                    if isinstance(original, _RedactingFormatter):
                        original = original.original
                    # Reconfiguration changes redaction, never the saved layout.
                    handler.setFormatter(_RedactingFormatter(original, self.secrets))
                elif isinstance(handler, logging.StreamHandler) or hasattr(
                    handler, "console"
                ):
                    current.removeHandler(handler)
                    if getattr(handler, "_oh_owned_console", False):
                        handler.close()
                    # Framework-owned handlers are detached, never closed here.
            current.setLevel(
                logging.DEBUG
                if name == "" or self.level <= logging.DEBUG
                else logging.WARNING
            )
            if name:
                current.propagate = True
        handler = logging.StreamHandler(sys.stderr)
        setattr(handler, "_oh_owned_console", True)
        handler.setLevel(logging.CRITICAL + 1 if self.silent else self.level)
        handler.setFormatter(
            GoConsoleFormatter(
                color=console_supports_color(sys.stderr, no_color=self.no_color),
                secrets=self.secrets,
            )
        )
        handler.addFilter(_ConsoleFilter(self.namespaces, self.level <= logging.DEBUG))
        root.addHandler(handler)
        # Existing context filters on file handlers may run first; their private
        # message snapshot lets this formatter render one target label either way.
