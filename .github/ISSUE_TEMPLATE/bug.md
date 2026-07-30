---
name: Bug
about: The pipeline itself misbehaves
title: ""
labels: bug
---

<!--
  Anything exploitable goes through the private advisory form instead, not here.
  See SECURITY.md.
-->

## What happened

Include the command and its **exit code** — 1 means a gate failed and the run
completed, 2-8 mean the pipeline itself did not. They are different bugs.

```console
$ dvp ...
```

## What you expected

## Environment

- `dvp --version`, Python version, OS:
- Backend (`fixture`, `splunk`, `elastic`, `sentinel`):
- Output of `dvp doctor`, with credentials removed:
