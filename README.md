# Detection Validation Pipeline

[![ci](https://github.com/matt869/detection-validation-pipeline/actions/workflows/ci.yml/badge.svg)](https://github.com/matt869/detection-validation-pipeline/actions/workflows/ci.yml)

Prove your detections actually fire — and when they do not, say *why*.

Most detection testing reports pass or fail. That hides the distinction that
matters: a rule that did not fire because its **logic is wrong** needs a
detection engineer, and a rule that did not fire because **the telemetry never
arrived** needs the platform team. Tuning a rule against data that is not there
is worse than doing nothing, because it ends with a green tick next to a gap
that still exists.

So every validation case resolves to one of three states:

| | | |
| --- | --- | --- |
| **`detected`** | The rule matched events the behaviour produced. | The control works. |
| **`visible`** | Telemetry arrived; the rule matched none of it. | **Detection gap** → fix the rule. |
| **`blind`** | No telemetry of the required type arrived. | **Visibility gap** → fix collection. |

Full reasoning in [`docs/three-state-model.md`](docs/three-state-model.md).

## Try it

No SIEM, no lab, no credentials, no configuration. It replays recorded telemetry
and executes nothing:

```console
$ pip install -e .
$ dvp run --profile quick-smoke
```

```
  [+] detected  lsass_memory_access / T1003.001-lsass-handle-open 9.0s
  [+] detected  powershell_encoded_command / T1059.001-powershell-encoded 2.0s
  [x] blind     defender_exclusion_added / T1562.001-defender-path-exclusion
  [!] visible   rdp_logon_from_workstation / T1021.001-rdp-interactive-logon
  [+] detected  run_key_persistence / T1547.001-run-key-appdata 4.0s  noisy(1)
  ...

  detected   18  ######################..  the control works
  visible     1  #.......................  telemetry present, rule silent - detection gap
  blind       1  #.......................  no telemetry - visibility gap

  detection rate      90%   telemetry visibility    95%
  detect latency    p50 3.0s   p95 5m 16s
  noisy rules       2 rule(s) also match quiet-baseline activity

  pass  no-errors            no cases errored
  pass  expectations-met     every case matched its documented expectation
  pass  no-regressions       no regressions against the previous run

PASS  all gates satisfied
```

Neither gap is a failure, and that is the point. `defender_exclusion_added`
declares `expect: blind` because the Defender channel is not onboarded yet.
`rdp_logon_from_workstation` declares `expect: visible` because its exclusion
still swallows all of `10.0.0.0/8` while jump-host segmentation is incomplete —
the 4624 events arrive and the rule deliberately matches none of them. Both are
documented, owned and dated, so they report `pass` while staying in every
coverage report until they are genuinely closed. Change either rule's behaviour
without changing its `expect:` and the build fails, in *both* directions: a gap
that quietly starts working is stale metadata, and stale metadata is how a known
gap becomes a forgotten one.

The `noisy(1)` is a separate finding: that rule also matches a Teams autostart
entry in the quiet baseline window. A rule can be `detected` and noisy at the
same time, and one that is both is not a working control.

## What it does

```
plan ─> baseline ─> emulate ─> settle ─> collect ─> classify ─> score
```

1. **Plan** — resolve a profile into cases (one rule × one emulation test).
2. **Baseline** — run every rule over a quiet window *before* emulating, to
   measure the noise it would produce on its own.
3. **Emulate** — produce the behaviour, under a default-deny safety policy.
4. **Settle** — wait for ingestion (skipped for recorded corpora).
5. **Collect** — two queries per case: the rule's logic, and a telemetry probe.
6. **Classify** — the three-state model.
7. **Score** — coverage vs targets, diff vs the previous run, quality gates.

## Commands

```console
$ dvp doctor --backends           # config, content and connectivity
$ dvp rules lint                  # pre-commit hook material
$ dvp rules compile lsass_memory_access --dialect splunk
$ dvp rules score --explain       # per-rule quality grades
$ dvp run --profile quick-smoke --plan-only
$ dvp coverage --gaps visibility  # what is not being logged
$ dvp coverage --navigator layer.json
$ dvp runs diff                   # what changed since last time
$ dvp report --latest --format html
$ dvp dashboard                   # local read-only review UI
```

Exit codes are stable, so CI can tell "detections regressed" (1) from "the SIEM
was unreachable" (5). See [`docs/architecture.md`](docs/architecture.md#exit-codes).

## Rules

Sigma-shaped YAML with three additions: `telemetry:` (which log sources this
depends on — this is what makes the three-state model possible), `validation:`
(how the rule is proven), and `tuning:` (local exceptions kept out of detection
logic).

```yaml
title: LSASS process memory accessed with credential-dumping rights
severity: critical
attack:
  tactics: [credential-access]
  techniques: [T1003.001]

telemetry:
  - sysmon_process_access

detection:
  selection_handle:
    EventID: 10
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess: ['0x1410', '0x1fffff']
  filter_known_good:
    SourceImage|endswith: ['\MsMpEng.exe', '\wmiprvse.exe']
  condition: selection_handle and not filter_known_good

validation:
  emulation: [T1003.001-lsass-handle-open]
  expect: detected
  max_latency: 3m
```

One rule compiles to every dialect. `rulekit` refuses rather than approximates —
a rule that would silently lose its `not filter` clause fails to compile instead
of deploying.

```console
$ dvp rules compile lsass_memory_access --dialect splunk
index=windows sourcetype="XmlWinEventLog:...Sysmon/Operational" EventCode=10
  (EventID="10" AND TargetImage="*\\lsass.exe" AND (GrantedAccess="0x1410" OR ...))
  AND NOT (SourceImage="*\\MsMpEng.exe" OR SourceImage="*\\wmiprvse.exe")
```

Supported: **Splunk** (SPL), **Elastic/OpenSearch** (Lucene), **Microsoft
Sentinel/Defender** (KQL), and **fixture** — which compiles to a Python
predicate, and is what makes the whole pipeline runnable offline in CI.

## Safety

The pipeline is designed to execute attacker-shaped behaviour, so it defaults to
doing nothing at all. Eight conditions must hold before a single command runs —
including that `host_allowlist` is non-empty (**an empty list allows nothing**),
that an authorisation reference is recorded, and that `--execute` was passed
interactively. Impact techniques (T1485/T1486/T1489/T1490/T1561) are permanently
denylisted and cannot be enabled by a profile.

No offensive payloads ship in this repository. Tests are either benign
simulations that produce telemetry of the same shape, or `executor: manual` —
the harness reserves a window and scores the result, but an operator performs
the action under their own authority.

Read [`docs/threat-model.md`](docs/threat-model.md) before running with
`--execute`.

## Layout

```
detections/       Rules, by platform and tactic
mapping/          ATT&CK reference, telemetry catalogue, coverage targets
fixtures/         Emulation test definitions + recorded event corpora
config/           Settings, backends, validation profiles
baseline/         What "quiet" looks like, and what noise is accepted
harness/          The pipeline: core, backends, emulation, analysis, reporting
rulekit/          Rule parsing, linting, scoring, query compilation
storage/          SQLite schema and migrations
dashboard/        Local read-only review UI
infra/            Sysmon config, auditd rules, CloudTrail terraform
docs/             Architecture, three-state model, threat model, ADRs
```

## Requirements

Python 3.11+. **PyYAML is the only required dependency** — reports, the HTML
renderer and the dashboard are all standard library, so this runs on a hardened
host with no network access. `httpx` is needed only for live SIEM backends
(`pip install -e '.[live]'`). Reasoning in
[ADR 0003](docs/adr/0003-minimal-dependencies.md).

## Development

```console
$ pip install -e '.[dev]'
$ pytest
$ ruff check .
$ dvp rules lint --dialect splunk --dialect elastic
$ pre-commit install             # rule linting on every commit
```

The offline test suite needs no infrastructure. `make ci` runs the same checks
as [`.github/workflows/ci.yml`](.github/workflows/ci.yml), which is the
`pr-smoke` job from `scheduler/jobs.yml` — one manifest, three places that
execute it, and a test that fails if they drift apart.

Adding a detection is documented in [CONTRIBUTING.md](CONTRIBUTING.md); the
rules about what may execute, and how to report a hole in them, are in
[SECURITY.md](SECURITY.md). Changes are in [CHANGELOG.md](CHANGELOG.md).

## License

Apache 2.0.
