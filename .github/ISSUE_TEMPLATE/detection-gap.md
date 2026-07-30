---
name: Detection gap
about: A behaviour that should be caught and is not
title: "[gap] "
labels: detection-gap
---

## The behaviour

What an attacker does, and the ATT&CK technique if you know it.

## Which state is it in

If you have run the pipeline, say what it reported — the answer changes who
picks this up:

- `visible` — the telemetry arrives and no rule matches it. **Detection gap**:
  this is rule work.
- `blind` — no telemetry of the required type arrives. **Visibility gap**: this
  is collection work, and writing a rule first would produce a green tick over
  a hole.
- Not validated at all — say so, that is useful on its own.

```console
$ dvp run --profile quick-smoke
```

## Telemetry

Which log source would carry this, and is it onboarded? Ids are in
`mapping/telemetry_sources.yml`.

## Anything else

Sample events with real hosts, users and addresses removed.
