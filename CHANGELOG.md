# Changelog

Notable changes, newest first. Format follows [Keep a
Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [semantic
versioning](https://semver.org/spec/v2.0.0.html).

Two things are treated as public API and will not change without a major
version: the **exit codes** in
[`docs/architecture.md`](docs/architecture.md#exit-codes), which CI depends on
to tell "detections regressed" from "the SIEM was down", and the **`report.json`
schema**, which is what anyone downstream parses.

## [0.4.0] — 2026-08-04

### Added

- **`dvp run --record NAME`** — capture a live run as a replayable corpus.
  Producing one by hand meant writing JSONL with the right `_test` / `_offset` /
  `_host` attribution, which nobody does twice, so the evidence a range produced
  died with the range. Each declared telemetry source is now queried over each
  emulation window using the same selector that scoped the rule and compiled its
  probe — one definition, so a corpus cannot hold a different slice of the
  platform than the probe measured. The baseline window is captured too;
  without it a replay cannot measure quiet-period noise and every rule looks
  cleaner than it is.
- The recorder refuses rather than approximates, in the three places it could
  have guessed: an event with no usable timestamp is dropped instead of written
  at offset 0 (which would invent a detection at the instant the test began), a
  source with no selector for the dialect is reported instead of silently
  omitted (a replay would otherwise report BLIND and blame the estate for a hole
  in the recording), and an existing corpus is never overwritten without
  `--overwrite`, because a corpus is evidence with a date on it.
- Recordings are real estate data. Redaction runs before anything reaches the
  disk, the manifest carries `origin: recorded` and `review_required: true`, and
  a test fails if a corpus marked that way is ever committed beside the
  synthetic ones. `SECURITY.md` and `CONTRIBUTING.md` say so too.

### Removed

- `FixtureBackend.record()`, dead since it was written: nothing called it, its
  docstring referred to a `dvp fixtures record` command that never existed, and
  it anchored timestamp-less events to offset 0 — the exact bug the replacement
  refuses to commit. `fixtures/README.md` documented it; it now documents the
  command that exists.

## [0.3.0] — 2026-08-01

### Added

- **`dvp heartbeat`** — per-host liveness for a log source, the question
  validation cannot answer. A run only checks whether telemetry arrived *during
  a test window*; a forwarder that dies at 02:00 on a Tuesday stays invisible
  until the next scheduled run, and usually surfaces as a detection that did
  not fire during an incident. Three states: `alive` within the expected
  interval, `late` while overdue but inside the grace multiplier, `silent`
  past it. Only `silent` exits non-zero, because paging on the first missed
  interval is how a liveness alert gets muted. Sources may declare their own
  cadence with a `heartbeat:` block — set on `aws_cloudtrail_management`, whose
  batched delivery the 15m default would report as dead every night.
- Hosts are reported because they sent something, or because an operator named
  them via `--inventory`. The first implementation inferred which hosts *should*
  send a source from the naming convention and immediately invented a gap on a
  host that sends Sysmon but produced no process-creation events in a scenario
  snippet. Inference deleted, in a tool whose compilers already refuse rather
  than approximate.
- Corpora now carry `recorded_at` through to the loader, so anything asking a
  question about elapsed time knows when offset zero actually was. A corpus
  without it is skipped rather than anchored to a guess.
- A **"What the numbers mean"** section in the README. `scoreable` is
  `detected + visible + blind`; errors and skips are excluded; **blind counts
  against the detection rate**. That last one is a deliberate choice — a
  control you cannot see is not a control you have, and excusing it rewards
  estates for not collecting — but it was only discoverable by reading
  `models.py`, and a percentage gets screenshotted out of context far more
  often than code gets read.

### Changed

- The rate and coverage gates now fail on the part of a shortfall that is
  **undocumented**, rather than on the shortfall. `ransomware-precursor` failed
  two gates every run because one case declares `expect: blind` against
  SEC-4471 — a gate that cannot pass until an unrelated Q4 ticket lands is not
  a signal, and the repository already argues this for `SuccessExitStatus=0 1`
  and for the three-state model itself: a documented, owned, dated gap must not
  page anyone. The reported rate is unchanged and still true (90% visibility is
  90%, never excused into 100%), the accepted gaps are named in the gate's own
  output every run, and the moment one stops matching its declared expectation
  the gate fails again and says which case. Verified against the shipped
  content by flipping `expect: blind` to `detected` on the Defender rule: three
  gates fire immediately.

### Added

- `defender_exclusion_registry`: the same behaviour as
  `defender_exclusion_added`, read through the sensor this estate actually
  collects. SEC-4471 leaves the Defender event channel unforwarded, but
  `infra/sysmon/sysmon-config.xml` has always included the Defender exclusions
  key in its RegistryEvent group — the telemetry was being collected and
  nothing was reading it. Both rules share one emulation test, so a single run
  now reports `blind` for the channel that is missing and `detected` for the
  sensor that is deployed, side by side. The corpus gains the Sysmon EventID 13
  write the recording had omitted; note it carries `MsMpEng.exe`, not
  `powershell.exe`, because `Add-MpPreference` has the Defender service make
  the change — so the registry rule detects the exclusion but cannot attribute
  it without correlating process creation.
- `ransomware-precursor` now meets its detection-rate gate (80%, was 78%). Its
  visibility-rate gate still fails, correctly: a compensating control is not a
  closure, and `defender_exclusion_added` stays `expect: blind` until SEC-4471
  lands.

### Fixed

- A technique with one blind case and one detected case vanished from
  `dvp coverage --gaps visibility`. The listing keyed on the technique's
  summary status, which only says `visibility-gap` when *every* case is blind,
  so adding a compensating rule deleted the uncollected log source from the
  report — a green tick over a hole, which is the failure this project exists
  to prevent. Gap listings now key on the case counts. Two existing CLI tests
  caught it the moment the second rule landed.
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
