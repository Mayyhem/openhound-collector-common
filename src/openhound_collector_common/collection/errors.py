"""Failures that a collector must not turn into an ordinary skipped read."""


class FatalCollectionError(RuntimeError):
    """Stop the owning run and report failure after active work has cleaned up."""
