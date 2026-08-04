"""Detection Validation Pipeline harness.

The harness turns a *validation profile* into evidence: it emulates adversary
behaviour, queries the telemetry platform for both alerts and raw telemetry, and
classifies every rule/technique pair into the three-state outcome model
(``detected`` / ``visible`` / ``blind``) described in ``docs/three-state-model.md``.
"""

from __future__ import annotations

#: Kept in step with pyproject.toml by tests/test_core.py. Not read from
#: importlib.metadata: `dvp --version` has to work from a source checkout that
#: was never installed, which is how it is most often run on an IR host.
__version__ = "0.4.0"
__all__ = ["__version__"]
