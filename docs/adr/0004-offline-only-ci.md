# ADR 0004: CI validates offline; live validation stays in the lab

- **Status**: accepted
- **Date**: 2026-07-30
- **Deciders**: detection-engineering

## Context

`scheduler/jobs.yml` describes four validation jobs. Two are offline replays
against recorded corpora; two execute emulation against a real SIEM in the lab
and are the ones that produce numbers anybody outside the team cares about.

The obvious way to schedule all four is GitHub Actions, which already runs on
every pull request. Doing that means a hosted runner needs a SIEM URL, a search
token, and network reach into the lab — and it means the thing authorised to
emulate credential access is a container that anyone able to merge a workflow
change can modify.

The counter-pressure is real: a pull-request gate that only replays recordings
cannot catch "the rule works against the fixture but not against the actual
index", which is a failure this project is specifically supposed to catch.

## Decision

**GitHub Actions runs only what needs no credentials.** `ci.yml` and
`nightly.yml` use the fixture backend, `execute: false`, and no secrets at all.

**Jobs that execute emulation run from the systemd timers in
`scheduler/systemd/`,** on a host inside the lab, under a service account whose
credentials live in a root-owned `EnvironmentFile` that no repository write can
reach. The schedule for those jobs is still reviewed in this repository —
`scripts/render_systemd.py` generates the drop-ins from the same manifest — but
the authority to run them is granted on the host, not in the workflow.

The consequence worth stating plainly: **a green pull request means the content
is internally consistent, not that the estate is covered.** The scheduled live
runs are what measure the estate, and their reports are the ones to read before
telling anyone that a control works.

## Consequences

**Good**

- No SIEM credential is reachable from a workflow file, and a compromised or
  malicious action cannot reach the lab.
- The PR gate cannot be flaky: nothing leaves the runner, so a slow SIEM cannot
  turn into a red build that teaches people to re-run jobs until they pass.
- Forks get the full gate. A contributor with no lab access can still see every
  check pass.
- Runtime is seconds, so the gate is fast enough to actually block a merge on.

**Bad**

- Drift between a fixture and the real index is caught by the nightly lab run,
  not at review time. A rule can merge green and fail in the lab that night.
- Two schedulers to understand instead of one, and the systemd side is only
  reviewable here — whether the timers are actually installed and firing is a
  host question, answered with `systemctl list-timers`.
- The lab host is now infrastructure with an owner and a patching obligation.

## Alternatives considered

**Self-hosted runner inside the lab.** Closest to "one scheduler", and it was
the first choice. Rejected because a self-hosted runner executes workflow files
from the repository, so anyone who can merge a workflow change can run arbitrary
code on a host that is authorised to emulate credential access. That is a
larger grant of authority than the problem needs, and it is granted implicitly.

**Live backend in Actions with secrets, restricted to the default branch.**
Keeps one scheduler and one place to look. Rejected because the credential still
exists in a system whose access model is "who can merge", and because the lab
would need to accept connections from GitHub's egress ranges.

**Recorded-response backend: capture real SIEM responses, replay them in CI.**
Genuinely attractive, and it would narrow the fixture-versus-index gap. Rejected
for now because captured responses contain real estate data that would have to
be scrubbed before being committed, and a scrubber that is wrong once has
published production log content to a public repository. Worth revisiting with
a synthetic capture from a lab index that has no real data in it.
