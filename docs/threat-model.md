# Threat model

This document is about the risks of running **this tool**, not about the
adversary techniques it validates. A detection validation pipeline is an
unusual piece of software: it holds SIEM credentials, it is designed to execute
attacker-shaped behaviour on real hosts, and it produces the reports leadership
uses to decide whether the security programme is working. Each of those is a
liability.

## Assets

| Asset | Why it matters |
| --- | --- |
| SIEM/EDR credentials | Read access to all security telemetry in the estate. |
| The detection library | Knowing exactly what is detected tells an attacker what is not. |
| Emulation capability | A sanctioned mechanism for running commands on hosts. |
| Run history | The record of which gaps existed and when. Useful to an attacker; also evidence in an audit. |
| Reports | Feed decisions about where security money goes. |

## Adversaries

1. **An attacker who compromises the pipeline host.** Gains SIEM read access, a
   map of every known blind spot, and a mechanism for remote execution.
2. **A malicious or careless insider.** Uses the emulation harness to run
   commands under the cover of "validation".
3. **An attacker who has already compromised the estate.** Reads the run history
   to find the gaps, or edits a rule so the pipeline reports green while the
   detection is quietly broken.
4. **Nobody at all.** The most likely damaging scenario is not an adversary: it
   is a scheduled job pointed at the wrong inventory on a Friday afternoon.

## Risks and what is done about them

### R1 - Emulation runs somewhere it should not

*The one that actually happens.* An inventory typo, a copied config, a profile
that looked lab-scoped.

Controls, all of which must pass before a single command executes:

- **Default deny.** `safety.authorized` is `false` out of the box. With no
  configuration the pipeline plans, replays and reports, and executes nothing.
- **Two independent switches.** Configuration must say `authorized: true` *and*
  the operator must pass `--execute`. Neither alone is sufficient, so a
  scheduled job cannot start executing because someone edited a YAML file.
- **Authorisation must be traceable.** `authorized: true` with an empty
  `authorization_reference` is refused. The reference is stored with every run.
- **Allowlist, not denylist, for hosts.** An empty `host_allowlist` means
  *nothing is permitted*, not "no restriction". This is the inversion that most
  often goes the other way, and it is the difference between a quiet afternoon
  and an incident.
- **Lab heuristic.** Hosts that do not look like lab systems are refused by
  default; hosts matching production naming patterns raise a warning even when
  allowed.
- **Cleanup required.** A test with no cleanup block is refused.

Refusals are never retried and never downgraded. A blocked test reports as
`skipped` with the reason attached, so the report shows plainly that coverage
was *not measured* rather than implying it was measured and passed.

### R2 - The tool causes the damage it is meant to detect

Emulating ransomware means emulating destruction. That is a line this pipeline
does not cross.

- **Impact techniques are permanently denylisted** (T1485, T1486, T1489, T1490,
  T1561) and cannot be enabled by a profile - only by a deliberate edit to
  settings. The `ransomware-precursor` profile validates the *chain that
  precedes* encryption, which is the useful place to detect ransomware anyway:
  by the time files are being encrypted, detection has already failed.
- **Destructive tests need a third opt-in** (`allow_destructive`) on top of
  authorisation.
- **Shipped tests are safe simulations or operator-run.** Where a benign command
  produces telemetry of the same shape - creating and deleting a scheduled task,
  writing and removing a Run key - the test carries that command and is marked
  `safe_mode: true`. Anything that would need real credential dumping or real
  destruction is `executor: manual`: the harness reserves a window and scores
  the result, but a named operator performs the action under their own
  authority. **No offensive payloads ship in this repository.**

### R3 - Credential compromise

- Credentials are never in YAML. `config/backends.yml` uses `${ENV:NAME}`
  placeholders resolved at load time, so the file is safe to commit and a
  missing credential fails at startup rather than mid-run.
- **The emulation subprocess gets a scrubbed environment.** Any variable whose
  name contains `TOKEN`, `SECRET`, `PASSWORD` or `KEY` is stripped before the
  command runs, so a test cannot read the SIEM token it is being validated
  against.
- Backends want **read-only** credentials. Nothing in the pipeline writes to a
  SIEM.
- TLS verification is on by default and can only be disabled explicitly per
  backend.
- Sentinel takes a short-lived bearer token, not a client secret. Token
  acquisition is deliberately out of scope: this tool should not hold one.

### R4 - Sensitive data leaking into reports

Matched events become evidence, and evidence ends up in a database, a report,
and often an email.

- Fields whose names contain any configured redaction term are replaced with
  `[redacted]` before anything is written. Matching is on substring and
  case-insensitive, because the field is as likely to be called `svc_password`
  as `password`.
- `reporting.evidence_limit` caps how many events are retained.
- `storage.store_evidence: false` disables retention entirely, for estates where
  matched content must not leave the platform.
- The dashboard binds to localhost, has no authentication, and serves a
  restrictive Content-Security-Policy. It is a local review tool. **Do not
  expose it.** If you need shared access, put it behind your own authenticating
  proxy and treat the underlying data as security-sensitive.

### R5 - The pipeline lies

A validation tool that reports success incorrectly is worse than no validation
tool, because it converts an unknown risk into a false assurance.

- **The three-state model exists for this reason.** Collapsing `visible` and
  `blind` into "not detected" leads engineers to tune rules against data that is
  not there. See [three-state-model.md](three-state-model.md).
- **Errors are never passes.** A failed query is `error`, excluded from coverage
  arithmetic, and fails the build by default.
- **Skipped is visible.** A test blocked by the safety policy reports as
  `skipped` with its reason, never as a pass.
- **Absence of a probe is admitted, not guessed.** A rule with no telemetry
  declaration gets low confidence and an explicit note.
- **Compilers refuse rather than approximate.** A rule that would lose meaning in
  a target dialect fails to compile.
- **Offline results are labelled.** Replayed cases carry medium confidence, and
  the documentation is explicit about what an offline pass does and does not
  prove.

### R6 - Tampering with content or history

- Rule logic has a fingerprint covering the detection block only, so editing a
  description does not look like a behavioural change - and a behavioural change
  cannot hide inside a documentation edit.
- Runs are immutable; a re-run is a new run.
- Applied migrations are checksummed. A migration edited after application is a
  hard error, because two machines silently running different schemas produce
  results that cannot be compared.
- Rule metadata is denormalised onto each case, so deleting a rule does not
  rewrite history.
- Keep the repository in version control with reviewed pull requests. The
  pipeline validates content; it cannot tell you the content was authorised.

## Deployment guidance

**Do**

- Run against a dedicated lab that mirrors production configuration.
- Use read-only SIEM credentials, scoped to the validation indices.
- Run the pipeline host as an unprivileged service account (see
  `scheduler/systemd/`).
- Keep `host_allowlist` narrow and review it like any other access control.
- Rotate the credentials in `/etc/dvp/environment` on the same schedule as any
  other service credential.

**Do not**

- Enable `--execute` against production endpoints.
- Expose the dashboard.
- Store SIEM credentials in the repository.
- Grant the pipeline write access to any security platform.
- Treat a green offline run as evidence that a detection works in production.

## Residual risk

Accepted, and worth stating plainly:

- **A compromised pipeline host is a serious incident.** It yields SIEM read
  access and a map of known gaps. Monitor this host like a security tool,
  because it is one.
- **Emulation on a lab host is still execution on a host.** The safety policy
  reduces the blast radius; it does not eliminate it.
- **The run history is sensitive.** It is a list of what you cannot see. Protect
  the database accordingly.
- **Coverage is measured against emulated behaviour**, which is a proxy for real
  adversary behaviour and never identical to it. A green board means the things
  you thought to test are working - nothing more.
