"""Small shared records for collectors that read several targets."""

from .records import RunDescription, TargetRowWriter
from .outcomes import OperationResult, TargetResult, RunResult

__all__ = [
    "RunDescription",
    "TargetRowWriter",
    "OperationResult",
    "TargetResult",
    "RunResult",
]
