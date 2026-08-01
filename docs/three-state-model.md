# The three-state model

## The problem with pass/fail

Most detection testing reports two outcomes: the rule fired, or it did not. That
is a comfortable model and a misleading one, because "did not fire" collapses two
completely different failures into one number.

Consider a rule for LSASS credential access that does not fire during a test.
There are two possibilities:

1. **The telemetry arrived and the rule did not match it.** Sysmon logged the
   process access, the event reached the SIEM, and the rule's logic was wrong -
   a bad `GrantedAccess` value, an over-broad exclusion, a field name that
   changed in the last agent upgrade.

2. **The telemetry never arrived.** Sysmon was not configured for
   `ProcessAccess`, or the channel was not in the forwarder subscription, or the
   agent had been dead for six days. The rule was never given the chance.

These have different owners, different fixes, and different urgencies. Fixing
the rule in case 2 is not merely useless, it is *actively harmful*: an engineer
will tune the rule against data that is not there, convince themselves it works,
and close the ticket. The gap survives, now with a green tick next to it.

A two-state model cannot tell you which case you are in. So this pipeline uses
three.

## The three states

Every validation case - one rule against one emulated behaviour - resolves to
exactly one of these.

| State | Meaning | Owner | Fix |
| --- | --- | --- | --- |
| **`detected`** | The rule matched events produced by the behaviour. | - | Nothing. The control works. |
| **`visible`** | The required telemetry arrived; the rule matched none of it. | Detection engineering | **Detection gap.** Fix the rule. |
| **`blind`** | No telemetry of the required type arrived at all. | Platform / logging | **Visibility gap.** Fix collection. Do not touch the rule. |

Two further states exist for cases that did not produce evidence. They are
excluded from all coverage arithmetic, because counting them would silently
inflate or deflate scores whenever infrastructure misbehaved:

| State | Meaning |
| --- | --- |
| `error` | The query failed, or emulation crashed. We do not know anything. |
| `skipped` | The behaviour was never produced - dry run, or blocked by the safety policy. |

## How the states are decided

Each case runs **two** queries, both compiled from the same rule:

- the **detection query** - the rule's full logic
- the **telemetry probe** - the rule's declared log sources, *with no detection
  logic at all*

The probe is what makes the model possible. It comes from the same
`telemetry:` declaration that scopes the detection query, so a rule can never
search one index while its blindness probe checks another - a mismatch that
would make the whole result meaningless.

```
                    detection query matched?
                             |
                    yes ─────┴───── no
                     |              |
                 DETECTED    telemetry probe matched?
                                    |
                          yes ──────┴────── no
                           |                |
                        VISIBLE           BLIND
                    (detection gap)  (visibility gap)
```

### When there is no probe

A rule with no `telemetry:` declaration cannot be probed. The classifier does
not guess. It reports `visible` with **low confidence** and attaches a note
explaining why.

That choice is deliberate and it is the lesser of two evils: wrongly reporting
`blind` sends the platform team hunting for a logging fault that does not exist,
and erodes trust in every future `blind` result. Wrongly reporting `visible`
sends a detection engineer to look at a rule, where they will immediately notice
the missing telemetry declaration and fix it. The linter flags the same rule as
`TM001`, so the situation is loud rather than silent.

## Outcome is not the same as pass/fail

Outcome and *status* are separate axes, and conflating them is the second
mistake this model exists to avoid.

Some gaps are known. `defender_exclusion_added` in this repository expects
`blind`: the Defender operational channel is not in the WEF subscription,
onboarding is tracked as SEC-4471, and there is an owner and a date. Reporting
that as a failure every night would train everyone to ignore the report.

So each rule declares what it expects, and status compares the two:

```
                    BLIND  <  VISIBLE  <  DETECTED

observed  >  expected   ->  UNEXPECTED_PASS   (better than documented)
observed ==  expected   ->  PASS
observed  <  expected   ->  FAIL
```

This produces the distinctions that matter:

| Observed | Expected | Status | Reading |
| --- | --- | --- | --- |
| `detected` | `detected` | `pass` | Working control. |
| `visible` | `visible` | `pass` | **Accepted** detection gap, owned and dated. |
| `blind` | `blind` | `pass` | **Accepted** visibility gap, owned and dated. |
| `visible` | `detected` | **`fail`** | A detection broke. |
| `blind` | `detected` | **`fail`** | A log source died. |
| `blind` | `visible` | **`fail`** | It got worse. |
| `detected` | `visible` | `unexpected_pass` | It got fixed - update the rule's metadata. |

`unexpected_pass` is not a celebration, it is a work item. A rule whose
documented expectation is stale is a rule nobody will trust the next time it
says something surprising.

An accepted gap is still a gap. It passes its own expectation *and* it still
counts against the technique's coverage target, so it stays visible in the
coverage report until it is actually closed. Those are two different questions
and the pipeline answers both.

There is a third question underneath them: **should this fail a build?** The
rate and coverage gates report the true number — a run with one uncollected log
source shows 90% visibility and says so, because a rate that excused its own
gaps would let an estate reach 100% by accepting everything. But they fail only
when some part of the shortfall is *undocumented*. A gap that is owned and
dated has already been through review; failing every run until an unrelated
ticket lands does not make it land sooner, it teaches the team that the gate is
always red, and that is how a real regression gets waved through. So the gate
says:

```
pass  visibility-rate  telemetry visibility 90% is below the 95% target,
                       entirely from 1 documented gap(s) - tracked, not drifting
```

and names the gap every time. The moment one of those gaps stops matching its
declared expectation — the rule was edited, the log source came back, a
different source died — the same gate fails and names the case responsible.
Passing is not the same as hiding.

## Noise is a fourth, orthogonal question

Before any emulation runs, every rule's detection logic is also run over a
recent window in which nothing was emulated. Anything it matches there is noise
it would produce in production.

This is tracked separately from outcome, because **a rule can be `detected` and
noisy at the same time**, and that rule is not a working control - it is an
alert generator that happens to fire on the right thing too. In this repository
`run_key_persistence` demonstrates exactly that: it detects the emulated
behaviour *and* matches a Teams autostart entry in the baseline corpus.

Accepted noise is recorded in `baseline/profiles/` with a reason, an owner, and
a review date. The format is the point: tolerating noise should be a decision
someone signed, not a thing that quietly became normal.

## Confidence

The outcome is never downgraded by uncertainty - it is annotated. An operator
reading `blind` needs to know whether the probe returned zero or whether it
timed out.

| Confidence | Cause |
| --- | --- |
| `high` | Normal. |
| `medium` | Truncated result set, or replayed from a recorded corpus rather than executed live. |
| `low` | No telemetry probe available, or the probe query itself failed. |

## Latency

For `detected` cases, latency is measured from the start of the emulated
behaviour to the first matching event. Each rule declares its own budget
(`validation.max_latency`), because "detected" means something different for
Sysmon process creation (seconds) and CloudTrail (minutes, because delivery is
batched).

Two details that took real debugging to get right:

- **The search window must extend past the rule's own latency budget.** If it
  does not, a detection that arrives inside its budget but outside the window is
  reported as a visibility gap - and a budget breach could never be observed at
  all.
- **A negative latency is discarded, not reported.** Search windows are padded
  before the behaviour to absorb clock skew. A "match" that predates the
  behaviour matched something else, so the number is not a latency.

## What an offline result does and does not prove

The `fixture` backend replays recorded telemetry and evaluates rules with the
same matching semantics the linter checks. That makes an offline run genuinely
useful and genuinely limited:

**It does prove** the rule's logic matches the events the behaviour produces,
that the exclusions do not swallow the true positive, and that nothing regressed
since the corpus was recorded.

**It does not prove** that the compiled query runs correctly on your SIEM, that
the field names survived your ingestion pipeline, or that the log source is
healthy today. Only a live run proves those.

So offline runs gate pull requests, and scheduled live runs measure the estate.
Neither substitutes for the other.
