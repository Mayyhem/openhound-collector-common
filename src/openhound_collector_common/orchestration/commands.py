"""Produce usable continuation commands without reading secrets or running a shell."""

from __future__ import annotations

import os
import logging
import re
import shlex
from pathlib import Path

logger = logging.getLogger(__name__)


def cli_path_arg(path: Path) -> str:
    """Quote one path for the current platform's normal command shell.

    Windows commands target PowerShell. Keep the established simple/space-path
    display, but use literal single quotes if expansion or command characters
    occur. POSIX commands use the standard library's shell quoting.
    """
    text = str(path)
    if os.name != "nt":
        # Pure display formatting has no operational outcome to log.
        return shlex.quote(text)
    if any(character in text for character in "$`\"'&;|<>()[{}!#\r\n"):
        return "'" + text.replace("'", "''") + "'"
    return f'"{text}"' if any(character.isspace() for character in text) else text


def continuation_commands(name: str, output_path: Path) -> tuple[str, str]:
    """Derive both saved-data commands from the collector's one output path."""
    if not re.fullmatch(r"[a-z][a-z0-9_-]*", name):
        logger.error("A continuation command has an invalid collector name")
        raise ValueError("Invalid registered collector name")
    lookup = output_path / "lookup.duckdb"
    return (
        f"uv run openhound preprocess {name} {cli_path_arg(output_path)} {cli_path_arg(lookup)}",
        f"uv run openhound convert {name} {cli_path_arg(output_path / name)} "
        f"{cli_path_arg(output_path / 'graph')} --lookup-file {cli_path_arg(lookup)}",
    )
