"""A deliberately tiny template renderer.

Reports and the dashboard use ``{{ name }}`` substitution and nothing else.
Loops and conditionals are written in Python, where they can be tested, rather
than in a template language.

The reason for not pulling in Jinja2 is narrow but real: this tool runs in CI
containers and on incident-response laptops, and every optional dependency is
one more thing that can be missing at the moment someone needs a report. The
whole renderer is thirty lines, so the trade is easy.

Values are HTML-escaped by default. ``{{& name }}`` inserts pre-built markup -
only ever used for fragments this codebase generated itself.
"""

from __future__ import annotations

import html
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

__all__ = ["escape", "load_template", "render"]

_PLACEHOLDER = re.compile(r"\{\{(?P<raw>&?)\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\}\}")

_TEMPLATE_DIR = Path(__file__).parent / "templates"


def escape(value: Any) -> str:
    """HTML-escape a value, including quotes so it is safe inside attributes."""
    return html.escape(str(value), quote=True)


def render(template: str, context: Mapping[str, Any]) -> str:
    """Substitute ``{{ name }}`` placeholders.

    A missing key renders as an empty string rather than raising: a report with
    one blank section is more useful than no report at all.
    """

    def _replace(match: re.Match[str]) -> str:
        name = match.group("name")
        if name not in context:
            return ""
        value = context[name]
        return str(value) if match.group("raw") else escape(value)

    return _PLACEHOLDER.sub(_replace, template)


def load_template(name: str, *, directory: Path | None = None) -> str:
    path = (directory or _TEMPLATE_DIR) / name
    if not path.exists():
        raise FileNotFoundError(f"template not found: {path}")
    return path.read_text(encoding="utf-8")


def render_file(name: str, context: Mapping[str, Any], *, directory: Path | None = None) -> str:
    return render(load_template(name, directory=directory), context)
