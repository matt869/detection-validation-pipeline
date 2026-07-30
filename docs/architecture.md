# Architecture

## What this is

A pipeline that turns the claim "we detect credential dumping" into evidence,
repeatedly and automatically. It emulates a behaviour, asks the telemetry
platform two questions about what happened, and classifies the answer using the
[three-state model](three-state-model.md).

## Shape

```
                    ┌──────────────────────────────────────────┐
   detections/  ──> │  rulekit                                 │
   mapping/     ──> │  parse -> validate -> lint -> compile    │
                    └───────────────┬──────────────────────────┘
                                    │  CompiledQuery (detection + telemetry probe)
                                    v
  config/profiles ──>  ┌────────────────────────────────────────┐
  fixtures/emulation ─>│  harness.pipeline                      │
                       │                                        │
                       │  plan ─> baseline ─> emulate ─> settle  │
                       │       ─> collect ─> classify ─> score   │
                       └───┬──────────────┬─────────────────┬───┘
                           │              │                 │
                    ┌──────v─────┐  ┌─────v──────┐   ┌──────v──────┐
                    │  backends  │  │  emulation │   │  analysis   │
                    │  fixture   │  │  safety    │   │  classify   │
                    │  splunk    │  │  executors │   │  coverage   │
                    │  elastic   │  │            │   │  diff/gates │
                    │  sentinel  │  │            │   │  baseline   │
                    └────────────┘  └────────────┘   └──────┬──────┘
                                                            │
                              ┌─────────────────────────────┼──────────────┐
                              v                             v              v
                     harness.store (SQLite)        harness.reporting    dashboard
                       runs, cases, coverage        json / md / html      (read-only)
                                                    junit / navigator
```

## Packages

| Package | Responsibility | Depends on |
| --- | --- | --- |
| `harness.core` | Models, config, time, IDs, errors, logging | stdlib + PyYAML |
| `rulekit` | Parse, lint, score and **compile** rules to query dialects | `harness.core` |
| `harness.backends` | Talk to telemetry platforms | `rulekit` (query types) |
| `harness.emulation` | Produce behaviour, under a safety policy | `harness.core` |
| `harness.analysis` | Interpret results: classify, cover, diff, gate | `harness.core` |
| `harness.store` | Persist runs | `harness.analysis` |
| `harness.reporting` | Render runs | `harness.analysis` |
| `harness.pipeline` | Orchestrate the above | everything |
| `dashboard` | Read-only web view | `harness.store` |

`rulekit` deliberately does not depend on the harness runtime. That is what lets
`dvp rules lint` run in a pre-commit hook with no SIEM, no database, and no
emulation library present.

## The seven stages

**1. plan.** Resolve a profile into concrete cases. A rule with three emulation
tests becomes three cases: each variant of a technique is proven separately,
because a rule that catches one and misses another is only half a control.
Separable via `--plan-only`, so an operator can see exactly what would happen
before anything touches a host.

**2. baseline.** Run every rule's detection logic over a recent window in which
nothing was emulated. This happens *before* emulation, so the behaviour under
test cannot be counted as background noise.

**3. emulate.** Produce the behaviour. Every test passes through the safety
policy first. Three modes:

- `dry-run` - records intent, executes nothing. The default.
- `replay` - reserves a real time window so recorded telemetry can be rebased
  onto it. No execution; this is what makes offline runs produce real latencies.
- `local` - actually runs the command, then its cleanup.

**4. settle.** Wait for ingestion. Skipped entirely for replayed corpora, which
is why an offline run finishes in under a second.

**5. collect.** Two queries per case - detection and telemetry probe - plus the
baseline query. Against a live backend, undetected cases are re-queried until
they fire or the wait budget expires; that loop is what turns "we queried once,
too early" into a measured latency.

**6. classify.** Apply the three-state model. See
[three-state-model.md](three-state-model.md).

**7. score.** Coverage against targets, diff against the previous run, noise
against accepted baselines, then gates.

## Design decisions worth knowing about

### One dependency

PyYAML is the only required package; `httpx` is needed solely for live
backends. Reports, the HTML renderer and the dashboard are all standard library.

This is not minimalism for its own sake. The tool runs in CI containers and on
incident-response laptops, and every optional dependency is one more thing that
can be missing at the moment someone needs a report. The template renderer that
replaced Jinja2 is thirty lines.

### The fixture backend is a first-class citizen, not a mock

Recorded events are tagged with the emulation test that produced them and an
offset in seconds. At query time those offsets are rebased onto the current
run's emulation window, so an offline run executed today produces the same
outcomes and the same latencies as the day the corpus was recorded.

Because the fixture dialect compiles to a Python predicate rather than a query
string, offline evaluation uses exactly the matching semantics in
`rulekit.matcher` - the same code path the linter checks. A semantic regression
there is caught before it can silently change what a live query means.

### Attribution in replay

Search windows are padded by minutes to absorb ingestion lag, while tests run
seconds apart. Without attribution, every rule would see every other test's
telemetry and report a false `detected`. The fixture backend therefore filters
by test id.

Live platforms cannot do this - an event carries no marker saying which
emulation caused it - so separation there comes from `inter_test_delay` instead.
The `attribution` parameter on `Backend.search` is honoured by backends that
can and ignored by those that cannot, and that asymmetry is real rather than
papered over.

### Compilers refuse rather than approximate

A rule that cannot be expressed in a target dialect raises `CompileError`. A
rule that silently loses its `not filter` clause is far worse than a rule that
fails to deploy, so the Splunk compiler switches between search syntax and
`| where` eval syntax as a whole, never mixing the two.

### Runs are immutable

A re-run is a new run. Rule metadata is denormalised onto each case row, because
a rule can be edited or deleted afterwards and the report must still describe
what was actually validated - not what the rule says today.

## Extending it

**A new backend**: subclass `harness.backends.base.Backend`, implement `search`
and `health`, register it in `harness/backends/__init__.py`. Honour the two
rules in that module's docstring: never raise for "no results", and always
report truncation.

**A new query dialect**: subclass `rulekit.compilers.QueryCompiler`, implement
the five rendering hooks, call `register_compiler`. Then add a `backends.<name>`
block to each source in `mapping/telemetry_sources.yml` - without it, rules have
no scope and no telemetry probe on that platform.

**A new lint check**: subclass `rulekit.linters.base.Linter`, add it to
`ALL_LINTERS`. Give it a stable code so teams can suppress it individually.

**A new report format**: add a renderer under `harness/reporting/` and register
it in `FORMATS`.

## Exit codes

Stable, and defined in `harness.core.errors.ExitCode`. CI needs to tell
"detections regressed" apart from "the SIEM was down".

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | A gate failed - regressions, coverage, lint errors |
| 2 | Usage error |
| 3 | Configuration error |
| 4 | Rule parse/compile error |
| 5 | Backend unreachable |
| 6 | Emulation failed |
| 7 | Blocked by the safety policy |
| 8 | Storage failure |
| 130 | Interrupted |
