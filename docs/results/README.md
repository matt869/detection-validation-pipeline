# `docs/results/`

Generated reports land here, one directory per run:

```
docs/results/
  LATEST                          # run id of the most recent run
  run-20260730T145218Z-8bb6a1/
    report.json                   # complete machine-readable record
    report.md                     # for pull requests and email
    report.html                   # self-contained, no external requests
    junit.xml                     # for CI
    navigator-layer.json          # ATT&CK Navigator
```

**This directory is git-ignored.** Runs are reproducible from the database
(`dvp report --run <id>`), and committing reports makes every diff enormous.
Publish them as CI artefacts instead.

## Which format for what

| Format | Use |
| --- | --- |
| `report.json` | The source of truth. Everything else is derived from it. |
| `report.md` | Pull request comments and weekly summaries. Verdict first, failures second, full case table collapsed at the bottom. |
| `report.html` | Self-contained — CSS inlined, no external requests. Attach it to an evidence bundle and it still renders years later on a machine with no network. |
| `junit.xml` | Every CI system already renders it. `ERROR` maps to `<error>`, not `<failure>`, so "we could not tell" never displays as a pass. |
| `navigator-layer.json` | Drop into the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/). Colours encode the three states, and the score is the fraction of cases that *fired* — not the number of rules that exist. |

The Navigator layer is worth loading side by side with one built from rule
counts. The difference between the two is the difference between "we have a
rule" and "the rule works", and it tends to be larger than people expect.

## Regenerating

```console
$ dvp report --latest --format html
$ dvp report --run run-20260730T145218Z-8bb6a1 --format json --format junit
$ dvp coverage --navigator layer.json
```

Reports are rendered from stored data, so re-rendering an old run gives you the
result as it was measured — not as today's rules would classify it.
