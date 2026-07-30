# `detections/_shared/`

Files and directories under `detections/` whose name starts with `_` or `.` are
**not loaded as rules**. This directory holds the things that support rule
authoring without being detections themselves:

| File | Purpose |
| --- | --- |
| `template.yml` | Copy this to start a new rule. It documents every supported key. |
| `filters.md` | House style for exclusion selections. |

## Authoring checklist

1. Copy `template.yml` into the right `detections/<platform>/<tactic>/` folder.
   The filename (without extension) becomes the rule `name`; keep it
   `snake_case` and unique.
2. Generate an id: `python -c "import uuid; print(uuid.uuid4())"`.
3. Declare `telemetry:` using ids from `mapping/telemetry_sources.yml`. Without
   this the harness cannot tell a detection gap from a visibility gap, and
   every result for the rule will be low confidence.
4. Write the `validation:` block *before* the detection logic. If you cannot
   describe how you would prove the rule fires, the rule is not ready.
5. Run `dvp rules lint --rule <name>` and `dvp rules compile <name> --dialect splunk`.

## Rules of thumb

- **Two fields minimum.** A rule resting on one field is a rule an attacker
  defeats with one rename.
- **Prefer `|endswith` to exact paths.** `Image|endswith: '\rundll32.exe'`
  survives the binary being copied elsewhere; `Image: 'C:\Windows\System32\rundll32.exe'`
  does not.
- **Always include an exclusion selection**, even an empty one. Tuning should
  never require editing detection logic, because that is how upstream updates
  silently clobber local exceptions.
- **Escape backslashes as `\\`.** Sigma treats a single backslash as literal
  unless it precedes `*`, `?`, or `\`, so a UNC prefix is written `'\\\\'`.
- **`expect: detected` unless you can justify otherwise.** `visible` and
  `blind` are legitimate - they record a known gap so it reports as PASS rather
  than paging someone - but both require `justification` and `owner`.
