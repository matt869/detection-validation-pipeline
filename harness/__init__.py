"""Detection Validation Pipeline harness.

The harness turns a *validation profile* into evidence: it emulates adversary
behaviour, queries the telemetry platform for both alerts and raw telemetry, and
classifies every rule/technique pair into the three-state outcome model
(``detected`` / ``visible`` / ``blind``) described in ``docs/three-state-model.md``.
"""

from __future__ import annotations

__version__ = "0.1.0"
__all__ = ["__version__"]
