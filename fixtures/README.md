# `fixtures/`

Two kinds of content, both reviewable as data rather than code.

```
fixtures/
  emulation/          What behaviour to produce, and how to undo it
    windows.yml
    linux.yml
    cloud.yml
  runs/               Recorded telemetry, replayed offline
    <scenario>/
      manifest.yml
      events.jsonl
```

## Emulation tests

A test says what behaviour to produce, how to reverse it, and which telemetry it
should generate. `dvp tests list` shows them; `dvp tests show <id>` prints the
command in full.

Two properties decide what the harness will do with a test:

| | |
| --- | --- |
| `executor: manual` | The harness reserves a time window, times the detection and scores the result — but **never runs anything**. Correct for anything touching credentials or defences. |
| `safe_mode: true` | The command is a benign stand-in producing telemetry of the same shape. Creating and deleting a scheduled task is real persistence with an inert payload. These are the tests CI can execute in a lab. |

**No offensive payloads ship in this repository.** Tests that would need real
credential dumping reference the public technique documentation and leave the
execution to a named operator under their own authority.

Everything runs through the safety policy regardless — see
[`docs/threat-model.md`](../docs/threat-model.md).

## Recorded corpora

A corpus is JSON Lines, one event per line, tagged with the emulation test that
produced it and an offset in seconds from that test's start:

```json
{"_test":"T1003.001-lsass-handle-open","_offset":9,"Channel":"Microsoft-Windows-Sysmon/Operational","EventID":10,"SourceImage":"C:\\...\\dvp-handle-open.exe","TargetImage":"C:\\Windows\\system32\\lsass.exe","GrantedAccess":"0x1410"}
```

At query time the offsets are rebased onto the *current* run's emulation window.
An offline run today produces the same three-state outcomes, and the same
detection latencies, as the day the corpus was recorded. That is what makes
`dvp run --profile quick-smoke` both fast and meaningful.

Three reserved keys:

| Key | Meaning |
| --- | --- |
| `_test` | Emulation test id, or `__baseline__` |
| `_offset` | Seconds after that test started |
| `_host` | Recording host, for provenance |

### `_test: "__baseline__"`

Events in the `baseline` corpus are anchored to the quiet window sampled *before*
emulation, not to any test. Their job is adversarial: a rule that matches
anything here produces noise in production. The corpus deliberately includes a
Teams autostart entry that `run_key_persistence` matches — a true finding, and
the reason that rule reports `noisy(1)`.

### Absence is data

`T1562.001-defender-path-exclusion` has a recorded Sysmon process event but **no
Defender channel event**, because that channel is not forwarded in this estate.
That absence is what makes `defender_exclusion_added` resolve to `blind` rather
than to a detection failure. Deleting events is sometimes the point.

`dvp fixtures verify` reports tests with no recorded events as information, not
as an error, for exactly this reason.

## Recording your own

Run against a live backend, then capture what it returned:

```console
$ dvp run --profile credential-theft --backend splunk --execute
```

`FixtureBackend.record()` converts absolute timestamps to offsets. Before
committing a corpus:

- **Redact.** Recorded events come from real hosts. Check usernames, hostnames,
  IP addresses and command lines. The examples here use RFC 5737 addresses and
  `example`/`lab.example` names.
- **Keep it small.** A corpus is evidence that a rule matches, not a packet
  capture. Ten well-chosen events beat ten thousand.
- **Include the near-misses.** The credential-theft corpus contains a legitimate
  `MsMpEng.exe` handle open alongside the malicious one, so the rule's exclusion
  logic is exercised rather than assumed.
- **Note what is missing and why**, in the manifest. A future reader needs to
  know whether an absent event is a recording gap or the finding itself.
