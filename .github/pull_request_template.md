<!--
  Explain the reasoning here rather than in the diff: what was broken, why this
  fix and not the obvious one, and what you decided not to do.
-->

## What and why

## If this changes detection content

Paste the run. The before and after states are the review:

```console
$ dvp run --profile quick-smoke
```

- [ ] Every rule declares `telemetry:` — without it the outcome is a guess
- [ ] `validation.expect:` is honest, and any `visible` / `blind` has an owner
      and a dated justification
- [ ] A recorded corpus exists, so the rule stays testable with no lab
- [ ] Local exceptions are in `tuning:`, not in `detection:`

## If this changes the safety policy

- [ ] Which of the eight preconditions changed, and why the default is still
      "do nothing":

## Checks

- [ ] `make ci` passes locally
- [ ] `scheduler/jobs.yml` edited? `python scripts/render_systemd.py` re-run
- [ ] Hard to reverse, or reasoning not obvious from the code? ADR added
