# ADR 0003: One required dependency

- **Status**: accepted
- **Date**: 2026-02-03
- **Deciders**: detection-engineering

## Context

The pipeline runs in three places with very different constraints: a developer
laptop, a CI container, and a hardened incident-response host where
`pip install` is a change request.

The initial dependency list was PyYAML, pydantic, Jinja2, click, rich and httpx.
During an incident review someone needed to re-render a six-month-old report on
a locked-down host and could not, because Jinja2 was not present. The report
existed; the tool that could display it did not run.

## Decision

**PyYAML is the only required dependency.** `httpx` is an optional extra needed
solely for live backends.

Specifically:

- CLI: `argparse`, not click or typer
- Models: dataclasses, not pydantic
- Terminal output: hand-rolled ANSI, not rich
- HTML reports and dashboard: a thirty-line `{{ }}` substitution renderer, not
  Jinja2
- Dashboard server: `http.server`, not Flask
- Storage: `sqlite3`

Optional dependencies must degrade with an actionable message, never an
`ImportError` at start-up. `httpx` is imported lazily inside
`harness/backends/http.py` for exactly this reason.

## Consequences

**Good**

- `pip install detection-validation-pipeline` pulls one package.
- Rule linting, offline validation, all report formats and the dashboard work
  with no network access and no extras.
- Nothing breaks because a transitive dependency changed its API.

**Bad**

- More code owned: a template renderer, a table formatter, a CLI argument
  layout, a small HTTP router. Roughly 400 lines that a framework would have
  provided.
- The template renderer supports `{{ name }}` and nothing else. Loops and
  conditionals are written in Python, which is more verbose than a template
  language - though it is also testable, which templates are not.
- `argparse` produces less polished help than click.

## Alternatives considered

**Vendor the dependencies.** Solves availability, creates a security-patching
obligation for code we did not write. Wrong trade for a security tool.

**Require Jinja2 but ship a fallback renderer.** Two implementations of the same
output, guaranteed to drift, and the fallback would only ever be exercised on
the machine where it mattered most.

**Ship a single-file zipapp.** Attractive for the IR-host case, but makes the
content directories (`detections/`, `fixtures/`) awkward, and those are meant to
be edited. Still worth considering as an additional artefact.
