# ADR 0001: Three-state outcome model

- **Status**: accepted
- **Date**: 2026-01-08
- **Deciders**: detection-engineering

## Context

The first prototype reported pass/fail per rule. Within two weeks it had
produced a concrete harm: an engineer spent a day tuning the LSASS access rule
against telemetry that was not being collected. The rule "failed", so they
edited it, re-ran, and it failed again. The actual problem was that
`ProcessAccess` had been removed from the Sysmon config three weeks earlier.

A binary outcome cannot distinguish "the rule is wrong" from "the data is not
there", and those have different owners and opposite fixes.

## Decision

Every case resolves to one of `detected`, `visible`, or `blind`, decided by
running two queries: the rule's detection logic, and a telemetry-presence probe
derived from the same `telemetry:` declaration.

`error` and `skipped` are operational states, excluded from coverage arithmetic.

Outcome is kept on a separate axis from pass/fail status, so a rule can declare
`expect: visible` for a known, owned gap and report `pass` without anyone being
paged - while still counting against the technique's coverage target.

## Consequences

**Good**

- Gaps route to the correct team automatically.
- Visibility regressions are caught, which pass/fail could not see at all.
- Known gaps stay documented and dated instead of being silently tolerated.

**Bad**

- Every rule must declare its telemetry sources, and the telemetry catalogue has
  to be maintained. This is real ongoing work.
- Two queries per case roughly doubles backend load.
- Rules without a telemetry declaration produce low-confidence results, so the
  model degrades on exactly the least-maintained content.

## Alternatives considered

**Infer the log source from the rule's `logsource` block.** Sigma's `logsource`
is too loose - `product: windows, service: sysmon` does not identify an index or
a table. Would have produced probes that were wrong in ways nobody could see.

**Ask the platform for agent health instead.** Answers "is the agent alive?",
not "did this specific event type arrive in this window?", which is the question
that matters. Also needs a different API per platform.

**Four states, splitting "rule not deployed" from "rule did not match".**
Attractive, but the pipeline compiles and runs queries itself rather than
reading the platform's rule inventory, so it genuinely cannot tell the
difference. Rejected as unimplementable rather than undesirable.
