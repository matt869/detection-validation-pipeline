# Security policy

## Reporting a vulnerability

Report privately through [GitHub's security advisory
form](https://github.com/matt869/detection-validation-pipeline/security/advisories/new).
Please do not open a public issue for anything exploitable.

Include what you did, what happened, and what you expected. A failing test or a
profile that reproduces it is worth more than a description. Expect an
acknowledgement within a few days; this is not a funded project, and there is no
bounty.

## What this project treats as a vulnerability

This is tooling that is *designed* to run attacker-shaped behaviour, so the
boundary matters more here than in most repositories. In scope:

- **Any path that executes emulation without the full safety policy holding.**
  The eight preconditions in [`harness/emulation/safety.py`](harness/emulation/safety.py)
  are the control. A profile, config file, environment variable, or CLI flag
  that gets a command to run without all of them is the most serious bug this
  project can have.
- **Escaping the technique denylist.** T1485/T1486/T1489/T1490/T1561 are
  permanently denied and no configuration may re-enable them.
- **Credential leakage.** Tokens reaching a report, the run database, a log
  line, or the environment of an emulated process.
- **Evidence leakage.** Redaction failing to remove a configured field before
  evidence is stored or rendered into a shared report.
- **Query injection.** Rule content that escapes its dialect and alters the
  search a backend runs, rather than failing to compile.
- **Path traversal** in fixture, profile, or report handling.

Out of scope: that the repository contains detection logic describing attacker
behaviour, that emulation tests produce telemetry resembling an attack, and that
a rule can be written badly. Those are the subject matter.

## What is not in this repository

No offensive payloads, no exploit code, no malware samples, and no credentials.
Emulation tests are either benign simulations that produce telemetry of the same
shape as the real behaviour, or `executor: manual` — where the harness reserves
a window and scores the result while an operator performs the action under their
own authority.

Recorded corpora under [`fixtures/runs/`](fixtures/runs/) are synthetic. Host
names, users, and addresses in them are invented; none of it came from a real
estate, and a test in the suite fails if a corpus marked `origin: recorded` is
ever committed alongside them.

`dvp run --record` produces the other kind. What a live platform returns is real
data about a real estate, so the recorder redacts the configured fields before
writing and marks the manifest `review_required: true` — but the review is a
person's job, not the tool's. Read a recording before committing it, and treat
publishing one to a public repository as the disclosure decision it is.

## Running it safely

Read [`docs/threat-model.md`](docs/threat-model.md) before using `--execute`.
The short version: the pipeline defaults to doing nothing, an empty
`host_allowlist` allows nothing rather than everything, and an authorisation
reference is recorded in every run that executes. If you are unsure whether you
are authorised to run it against a host, you are not.
