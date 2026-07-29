"""End-to-end phase orchestration for OpenHound collectors.

Stock OpenHound runs ``collect`` -> ``preprocess`` -> ``convert`` as three separate
CLI commands, and offers no single "collect all the way to a graph" verb (a new
top-level verb can't be added without editing framework core). This subpackage
provides the reusable, framework-agnostic chaining that lets an extension expose
that convenience as a flag on its own ``collect`` command (e.g.
``openhound collect sccm --run-all``).

Modules:
- ``run`` — derive the preproc/convert paths from one collect OUTPUT_PATH and run
  both stages in-process off an OpenHound app's registered hooks.
"""

from .run import StagePaths, derive_stage_paths, run_end_to_end

__all__ = [
    "StagePaths",
    "derive_stage_paths",
    "run_end_to_end",
]
