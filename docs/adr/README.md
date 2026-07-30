# Architecture decision records

Short records of decisions that were expensive to make and would be expensive to
reverse. Each one states the context, the decision, and — importantly — what it
costs, because a decision with no downsides listed is usually one that has not
been thought through.

| ADR | Decision |
| --- | --- |
| [0001](0001-three-state-outcome-model.md) | Three-state outcome model rather than pass/fail |
| [0002](0002-default-deny-emulation.md) | Default-deny emulation with a two-key opt-in |
| [0003](0003-minimal-dependencies.md) | One required dependency |
| [0004](0004-offline-only-ci.md) | CI validates offline; live validation stays in the lab |

## Writing one

Add a record when a decision is hard to reverse, when the reasoning will not be
obvious from the code, or when the next person will otherwise re-litigate it.
Not for routine choices.

Number sequentially, never renumber, and never delete. A superseded ADR gets its
status changed to `superseded by NNNN` and stays where it is — the fact that a
decision was once made differently is part of the record.

Structure: **Status / Date / Deciders**, then **Context**, **Decision**,
**Consequences** (good *and* bad), **Alternatives considered** (with why they
were rejected).
