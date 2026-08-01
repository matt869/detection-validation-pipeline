# Changelog

Notable changes, newest first. Format follows [Keep a
Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [semantic
versioning](https://semver.org/spec/v2.0.0.html).

Two things are treated as public API and will not change without a major
version: the **exit codes** in
[`docs/architecture.md`](docs/architecture.md#exit-codes), which CI depends on
to tell "detections regressed" from "the SIEM was down", and the **`report.json`
schema**, which is what anyone downstream parses.

## [Unreleased]

### Fixed

- CI ran `pytest` where the Makefile runs `python -m pytest`. Four test modules
  import shared builders via `from tests.conftest import`, which needs the
  repository root on `sys.path` — the module form puts it there and the bare
  command does not, so the suite passed locally and failed on the runner.
  `pythonpath = ["."]` in `pyproject.toml` makes the invocation irrelevant, and
  the workflow now matches the Makefile.
- A failing gate no longer fails the nightly job. `ransomware-precursor` exits
  1 by design — it measures an estate with two dated, owned gaps — so the
  nightly was permanently red, and a job that is always red is a job nobody
  reads. This is the same call the systemd units already make with
  `SuccessExitStatus=0 1`. Exit codes 2-8 still fail. The pull-request gate is
  unchanged and still fails on 1.

### Changed

- Actions bumped to `checkout@v7`, `setup-python@v7`, `upload-artifact@v7`;
  the v4/v5 tags target Node 20, which runners now force onto Node 24.

## [0.2.0] — 2026-07-31

### Added

- GitHub Actions workflows: `ci` (the `pr-smoke` job from
  `scheduler/jobs.yml` — content linting, ruff, mypy, pytest on 3.11–3.13, and
  an offline validation run whose exit code distinguishes a regressed detection
  from a broken pipeline) and `nightly` (every offline profile).
- `scripts/render_systemd.py`, which generates the per-profile systemd drop-ins
  in `scheduler/systemd/generated/` from `scheduler/jobs.yml`. It refuses a
  schedule it cannot translate — systemd accepts a malformed `OnCalendar=` by
  never firing, so a bad schedule produces a validation job that silently stops
  running — and refuses `execute: true` without an authorisation reference.
  `--check` fails the build when the manifest and the committed units disagree.
- `.pre-commit-config.yaml`, so rule linting runs on commit as the README has
  always claimed it could.
- `SECURITY.md`, `CONTRIBUTING.md`, and this file.
- `make schedule`, `make schedule-check`; `make ci` now also runs `typecheck`
  and the schedule drift check.

### Changed

- The `quick-smoke` profile selects `medium` severity and above, not `high`.
  The one rule that demonstrates a `visible` outcome is medium severity, so the
  gate that runs most often never exercised the state that distinguishes a
  detection gap from a visibility gap — the reason the project exists. Gate
  severity is unchanged, so what can fail a build has not widened.
- Formatted the tree with `ruff format`. `make lint` had always run
  `ruff format --check` and it had never passed, because the code sat at 88
  columns while `pyproject.toml` declared 100.

### Fixed

- Emulation output captured before a timeout is decoded rather than dropped.
  `subprocess` decodes on the success path, but `TimeoutExpired` can carry raw
  bytes, and output captured up to the timeout is often the only evidence of
  what the behaviour managed to do.
- `mypy harness rulekit` is clean, and now runs in CI. Fixing it turned up two
  shadowed variables — `tactics` holding both a technique's tactic list and the
  report's per-tactic index in one function, and `result` holding both a
  `QueryResult` and a `CaseResult` — which were correct today and were an
  ordinary edit away from not being.
- Removed a `case_fields()` stub in the classifier that always returned an
  empty projection.
- Project URLs pointed at `github.com/example`.

## [0.1.0] — 2026-07-30

First release.

### Added

- The three-state outcome model — `detected` / `visible` / `blind` — with
  expectation tracking on a separate axis, so a documented gap passes without
  hiding. [ADR 0001](docs/adr/0001-three-state-outcome-model.md).
- `rulekit`: Sigma-shaped rule parsing, linting, quality scoring, and query
  compilation to Splunk SPL, Elastic/OpenSearch Lucene, Microsoft Sentinel KQL,
  and a fixture dialect that compiles to a Python predicate. Compilers refuse
  rather than approximate: a rule that would silently lose a `not` clause fails
  to compile instead of deploying.
- The validation pipeline: plan, baseline, emulate, settle, collect, classify,
  score — with per-run quality gates, ATT&CK coverage against declared targets,
  and a diff against the previous run.
- Default-deny emulation safety: eight preconditions, an empty `host_allowlist`
  that allows nothing, a permanent impact-technique denylist no profile can
  override, and `executor: manual` as a first-class option.
  [ADR 0002](docs/adr/0002-default-deny-emulation.md).
- Reporting: console, JSON, Markdown, HTML, JUnit, and ATT&CK Navigator layers.
- SQLite run storage with migrations, and a local read-only review dashboard.
- 19 detections, 20 emulation tests, and recorded corpora for seven scenarios —
  the whole pipeline runs offline with no SIEM, no lab, and no credentials.
