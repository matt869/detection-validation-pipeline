"""``python -m harness`` - the same entry point as the ``dvp`` console script.

Useful when the package is on the path but its scripts directory is not, which
is the normal situation inside a container.
"""

from __future__ import annotations

import sys

from harness.cli import main

if __name__ == "__main__":
    sys.exit(main())
