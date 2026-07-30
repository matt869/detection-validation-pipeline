"""Report generation.

``write_reports`` is the single entry point: give it a run and the analysis
objects, and it writes every configured format into one directory named after
the run. Keeping the formats together means the JSON, the HTML, and the JUnit
XML can never disagree about what happened.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

from harness.analysis.baseline import NoiseFinding
from harness.analysis.coverage import CoverageReport
from harness.analysis.diff import RunDiff
from harness.analysis.gates import GateOutcome
from harness.core.errors import UsageError
from harness.core.logging import get_logger
from harness.core.models import RunRecord
from harness.reporting.console import print_case, print_case_lines, print_summary
from harness.reporting.html import render_html
from harness.reporting.junit import render_junit
from harness.reporting.markdown import render_markdown
from harness.reporting.navigator import build_layer

__all__ = [
    "FORMATS",
    "build_layer",
    "print_case",
    "print_case_lines",
    "print_summary",
    "render_html",
    "render_json",
    "render_junit",
    "render_markdown",
    "write_reports",
]

log = get_logger("report")

FORMATS = ("json", "markdown", "html", "junit", "navigator")

_EXTENSIONS = {
    "json": "report.json",
    "markdown": "report.md",
    "html": "report.html",
    "junit": "junit.xml",
    "navigator": "navigator-layer.json",
}


def render_json(
    run: RunRecord,
    *,
    coverage: CoverageReport | None = None,
    gates: GateOutcome | None = None,
    diff: RunDiff | None = None,
    noise: Sequence[NoiseFinding] = (),
) -> str:
    """The complete machine-readable record. Everything else is derived from it."""
    payload = run.to_dict()
    if coverage is not None:
        payload["coverage"] = coverage.to_dict()
    if gates is not None:
        payload["gates"] = gates.to_dict()
    if diff is not None:
        payload["diff"] = diff.to_dict()
    if noise:
        payload["noise"] = [n.to_dict() for n in noise]
    return json.dumps(payload, indent=2, default=str) + "\n"


def write_reports(
    run: RunRecord,
    output_dir: Path | str,
    *,
    formats: Sequence[str] = ("json", "markdown"),
    coverage: CoverageReport | None = None,
    gates: GateOutcome | None = None,
    diff: RunDiff | None = None,
    noise: Sequence[NoiseFinding] = (),
    latest_symlink: bool = True,
) -> list[Path]:
    """Write every requested format into ``output_dir/<run_id>/``.

    Returns the paths written, in the order requested.
    """
    unknown = [f for f in formats if f not in FORMATS]
    if unknown:
        raise UsageError(
            f"unknown report format(s): {', '.join(unknown)}",
            hint=f"Available: {', '.join(FORMATS)}",
        )

    directory = Path(output_dir) / run.run_id
    directory.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    for fmt in formats:
        path = directory / _EXTENSIONS[fmt]
        if fmt == "json":
            body = render_json(run, coverage=coverage, gates=gates, diff=diff, noise=noise)
        elif fmt == "markdown":
            body = render_markdown(run, coverage=coverage, gates=gates, diff=diff, noise=noise)
        elif fmt == "html":
            body = render_html(run, coverage=coverage, gates=gates, diff=diff, noise=noise)
        elif fmt == "junit":
            body = render_junit(run)
        else:  # navigator
            if coverage is None:
                log.warning("skipping navigator layer: no coverage data")
                continue
            body = json.dumps(build_layer(run, coverage), indent=2) + "\n"

        path.write_text(body, encoding="utf-8")
        written.append(path)
        log.info("wrote %s", path)

    if latest_symlink and written:
        _write_pointer(Path(output_dir), run.run_id)

    return written


def _write_pointer(root: Path, run_id: str) -> None:
    """Record the newest run id.

    A plain text file rather than a symlink: symlinks need elevation on Windows
    and do not survive most artifact-upload steps, and the only consumer is
    ``dvp report --latest``.
    """
    try:
        (root / "LATEST").write_text(run_id + "\n", encoding="utf-8")
    except OSError as exc:  # pragma: no cover - unwritable output dir
        log.warning("could not update LATEST pointer: %s", exc)
