# ADR 0002: Default-deny emulation with a two-key opt-in

- **Status**: accepted
- **Date**: 2026-01-15
- **Deciders**: detection-engineering, platform-engineering

## Context

The pipeline needs to run attacker-shaped commands on real hosts. That
capability will eventually be pointed at the wrong inventory - not maliciously,
but through a copied config, an inventory typo, or a scheduled job someone
forgot was enabled.

The design assumption is that this tool will one day be run by someone who has
not read the documentation, against an inventory they did not build, from a CI
job nobody is watching.

## Decision

Emulation is denied unless **all** of the following hold:

1. `safety.authorized: true` in configuration
2. `safety.authorization_reference` is non-empty, and is stored with the run
3. `--execute` was passed on the command line
4. The target host matches `host_allowlist` (empty means *nothing* is allowed)
5. The host looks like a lab system, unless `require_lab_tag` is disabled
6. The technique is not on the permanent denylist
7. The test defines a cleanup block
8. Destructive tests additionally require `allow_destructive`

Impact techniques (T1485, T1486, T1489, T1490, T1561) are denylisted by default
and cannot be re-enabled by a profile - only by editing settings.

Refusals report as `skipped` with the reason attached. They are never retried
and never downgraded.

## Consequences

**Good**

- A fresh clone cannot execute anything, but still produces a complete,
  scoreable run against recorded fixtures.
- Configuration alone cannot enable execution, so a scheduled job cannot start
  executing because someone edited a YAML file.
- Every executed run has a traceable authorisation.
- An empty allowlist fails closed - the inversion that most often goes the other
  way in security tooling.

**Bad**

- Eight conditions is a lot to satisfy, and first-time users will hit a refusal
  they have to read carefully. Mitigated by naming the specific failed check.
- The lab heuristic is a string match on hostnames. It will mis-classify a
  host named `labyrinth-prod-01`, and it is a speed bump rather than a control.
- Cleanup is required even where cleanup is meaningless, which slightly distorts
  test definitions.

## Alternatives considered

**A single `--force` flag.** Too easy to add to a script and forget. Splitting
the decision between a reviewed config file and an interactive flag means both a
human and a change record are involved.

**A signed authorisation token with an expiry.** Genuinely better, and rejected
as disproportionate for a tool that should only ever point at a lab. Worth
revisiting if this is ever run against production.

**Denylist hosts instead of allowlisting them.** Fails open. A host absent from
the denylist because nobody knew it existed is exactly the host you do not want
to emulate against.
