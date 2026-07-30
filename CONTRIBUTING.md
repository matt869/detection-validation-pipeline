# Contributing

Most contributions here are **content**, not code: a new detection, an emulation
test, a corpus, a coverage target. The pipeline exists to hold that content to a
standard, so the content path is the one documented first.

```console
$ pip install -e '.[dev]'
$ pre-commit install
$ make ci          # what a pull request must pass
```

## Adding a detection

A rule is not finished when it matches. It is finished when the pipeline can
prove it matches, and can tell you why on the day it stops.

1. **Copy the template.** [`detections/_shared/template.yml`](detections/_shared/template.yml)
   documents every supported key. Put the file under
   `detections/<platform>/<tactic>/<name>.yml`, and generate a fresh UUID —
   duplicate ids fail the build.

2. **Declare `telemetry:`.** Ids from
   [`mapping/telemetry_sources.yml`](mapping/telemetry_sources.yml). This is
   not optional and it is not documentation: it is what compiles the probe query
   that separates a detection gap from a visibility gap. A rule without it
   degrades the whole model to guessing.

3. **Keep exceptions in `tuning:`, not in `detection:`.** Local noise belongs
   somewhere that updating the detection logic will not clobber.

4. **Write the emulation test** in `fixtures/emulation/<platform>.yml`. Default
   to `executor: manual` for anything touching credentials, defences, or
   persistence that outlives the run. Automate only a benign stand-in that
   produces telemetry of the same shape (`safe_mode: true`). No offensive
   payloads — see [SECURITY.md](SECURITY.md).

5. **Record a corpus** under `fixtures/runs/<scenario>/` so the rule can be
   validated with no lab and no credentials. Events are synthetic; invent the
   hosts and users. This is what makes the rule testable in CI forever, and it
   is the step most likely to be skipped and most likely to be regretted.

6. **Set `validation.expect:`** honestly:

   | | |
   | --- | --- |
   | `detected` | The rule should fire. The default; anything else needs a reason. |
   | `visible` | Telemetry arrives, the rule deliberately does not fire yet. |
   | `blind` | The log source is not onboarded. |

   Anything other than `detected` is reported by the linter every single run
   (`VL003`), and a gap with no `owner:` is reported again (`VL006`) — nobody
   is going to close a gap that belongs to nobody. Write the `justification:`
   with a ticket and a target date. The linter cannot check that the date is
   real; your reviewer can.

7. **Run it.**

   ```console
   $ dvp rules lint --dialect fixture --dialect splunk --dialect elastic
   $ dvp rules score --explain
   $ dvp run --profile quick-smoke
   ```

The gate is bidirectional, which surprises people: a rule that *starts* working
when it declared `expect: visible` also fails the build, as `UNEXPECTED_PASS`.
That is deliberate. Stale metadata is how a known gap becomes a forgotten one.

## Changing code

- `make ci` is the whole gate: content lint, tests, ruff, mypy, the schedule
  drift check, and an offline validation run. It is the same thing
  [`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs.
- **Comments explain why, not what.** The existing code is written that way and
  a patch that drops to narrating the syntax will read as a different project.
- **New dependencies need a reason in an ADR.** PyYAML is the only required
  one, deliberately — see [ADR 0003](docs/adr/0003-minimal-dependencies.md).
  Reports, the HTML renderer and the dashboard are standard library so this
  runs on a hardened host with no network.
- **Changing the safety policy needs more than a passing test.** Say in the
  pull request which of the eight preconditions you touched and why the default
  is still "do nothing".
- Editing a schedule in `scheduler/jobs.yml` means re-rendering:
  `python scripts/render_systemd.py`. CI fails if you forget.

## Architectural decisions

Anything that changes the shape of the pipeline gets an ADR in
[`docs/adr/`](docs/adr/) — one page: context, decision, consequences, and what
you rejected. Three exist already and they are short on purpose.

## Pull requests

One concern per pull request. Explain the reasoning in the commit message
rather than the diff: what was broken, why this fix and not the obvious one,
and what you decided not to do. If it changes a rule's outcome, paste the
`dvp run` output — the before and after states are the review.
