"""Command line interface.

Built on argparse rather than a CLI framework, for the same reason the rest of
the tool has one runtime dependency: this gets installed on machines where
``pip install`` is a change request.

Exit codes are stable and documented in :class:`harness.core.errors.ExitCode`,
so a CI job can tell "detections regressed" (1) apart from "the SIEM was
unreachable" (5).
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from harness import __version__
from harness.core.errors import DvpError, ExitCode, UsageError
from harness.core.logging import bold, configure, dim, get_logger, paint
from harness.core.models import Outcome, Severity
from harness.core.timeutil import format_duration
from harness.core.yamlio import dump_yaml

log = get_logger("cli")

_EPILOG = """\
examples:
  dvp doctor                             check config, backends and content
  dvp rules lint                         lint every rule (use in a pre-commit hook)
  dvp rules compile lsass_memory_access --dialect splunk
  dvp run --profile quick-smoke          offline validation against fixtures
  dvp run --profile credential-theft --backend splunk --execute
  dvp coverage --navigator layer.json    export measured coverage to Navigator
  dvp heartbeat --source sysmon_process_creation   which hosts stopped sending
  dvp report --latest --format html
"""


# ---------------------------------------------------------------- entrypoint


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    configure(level=args.log_level.upper(), fmt=args.log_format)
    if args.no_color:
        os.environ["NO_COLOR"] = "1"

    if args.command is None:
        parser.print_help()
        return ExitCode.USAGE

    try:
        return args.handler(args)
    except UsageError as exc:
        print(f"error: {exc.message}", file=sys.stderr)
        if exc.hint:
            print(f"hint:  {exc.hint}", file=sys.stderr)
        return exc.exit_code
    except DvpError as exc:
        print(f"error: {exc.message}", file=sys.stderr)
        if exc.hint:
            print(f"hint:  {exc.hint}", file=sys.stderr)
        return exc.exit_code
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return ExitCode.INTERRUPTED
    except BrokenPipeError:  # pragma: no cover - `dvp ... | head`
        return ExitCode.OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dvp",
        description="Detection validation pipeline: prove your detections fire.",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"dvp {__version__}")
    parser.add_argument("--root", type=Path, help="project root (default: auto-detect)")
    parser.add_argument(
        "--log-level",
        default="info",
        choices=("debug", "info", "warning", "error"),
        help="log verbosity (default: info)",
    )
    parser.add_argument(
        "--log-format", default="text", choices=("text", "json"), help="log output format"
    )
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    parser.set_defaults(command=None)

    sub = parser.add_subparsers(dest="command", metavar="<command>")
    _add_run(sub)
    _add_rules(sub)
    _add_tests(sub)
    _add_coverage(sub)
    _add_heartbeat(sub)
    _add_report(sub)
    _add_runs(sub)
    _add_db(sub)
    _add_fixtures(sub)
    _add_dashboard(sub)
    _add_doctor(sub)
    return parser


# --------------------------------------------------------------------- run


def _add_run(sub) -> None:
    parser = sub.add_parser(
        "run",
        help="run a validation profile",
        description="Emulate, query, classify, score, and report.",
    )
    parser.add_argument("--profile", "-p", default="quick-smoke", help="profile name")
    parser.add_argument("--backend", "-b", help="override the profile's backend")
    parser.add_argument(
        "--execute",
        action="store_true",
        help="actually run emulation commands (requires safety.authorized "
        "and an authorization_reference in settings)",
    )
    parser.add_argument("--host", help="target host label for the safety policy")
    parser.add_argument(
        "--plan-only", action="store_true", help="show the plan and exit without running"
    )
    parser.add_argument(
        "--format",
        "-f",
        action="append",
        dest="formats",
        help="report format (repeatable): json, markdown, html, junit, navigator",
    )
    parser.add_argument("--output", "-o", type=Path, help="report output directory")
    parser.add_argument(
        "--record",
        metavar="NAME",
        help="capture what the platform saw into fixtures/runs/NAME, so this run "
        "replays offline forever (live backends only)",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="allow --record to replace an existing corpus",
    )
    parser.add_argument("--no-store", action="store_true", help="do not write to the database")
    parser.add_argument("--no-report", action="store_true", help="skip writing report files")
    parser.add_argument(
        "--no-compare", action="store_true", help="skip the diff against the previous run"
    )
    parser.add_argument("--quiet", "-q", action="store_true", help="only print the final summary")
    parser.add_argument("--verbose", "-v", action="store_true", help="include coverage detail")
    parser.set_defaults(handler=_cmd_run)


def _cmd_run(args: argparse.Namespace) -> int:
    from harness.pipeline import Pipeline, Workspace
    from harness.reporting import print_case, print_summary, write_reports

    workspace = Workspace.load(args.root)
    profile = workspace.profiles.require(args.profile)
    _warn_about_content(workspace)

    on_case = None if args.quiet else print_case
    pipeline = Pipeline(workspace, on_case=on_case)

    if not args.quiet:
        print(bold(f"Profile: {profile.name}"))
        if profile.description:
            print(dim(f"  {profile.description}"))
        print()

    result = pipeline.run(
        profile,
        execute=args.execute,
        backend_name=args.backend,
        host=args.host,
        plan_only=args.plan_only,
        compare=not args.no_compare,
        operator=_operator(),
        git_ref=_git_ref(workspace.settings.root),
        record_as=args.record,
        overwrite_recording=args.overwrite,
    )

    if result.plan_only:
        return _print_plan(pipeline, profile)

    if result.emulation and result.emulation.skipped and not args.quiet:
        print()
        print(bold("Emulation skipped"))
        for test_id, reason in result.emulation.skipped.items():
            print(f"  - {test_id}: {dim(reason)}")

    print_summary(
        result.run,
        gates=result.gates,
        coverage=result.coverage,
        diff=result.diff,
        noise=result.noise,
        verbose=args.verbose,
    )

    if result.recorded:
        print()
        print(bold(f"Recorded {result.recorded}"))
        print(
            dim(
                "  Real telemetry. Review it before committing - hostnames, users and "
                "command lines are in there, and the manifest is marked review_required."
            )
        )

    if not args.no_store:
        _store_result(workspace, result)

    if not args.no_report:
        formats = tuple(args.formats or profile.formats or workspace.settings.reporting.formats)
        if workspace.settings.reporting.navigator_layer and "navigator" not in formats:
            formats = (*formats, "navigator")
        written = write_reports(
            result.run,
            args.output or workspace.settings.results_dir,
            formats=formats,
            coverage=result.coverage,
            gates=result.gates,
            diff=result.diff,
            noise=result.noise,
        )
        print()
        for path in written:
            print(dim(f"  wrote {workspace.settings.layout.relative(path)}"))

    if result.run.errors:
        for error in result.run.errors:
            print(f"error: {error}", file=sys.stderr)
        return ExitCode.GATE_FAILED

    return ExitCode.OK if result.passed else ExitCode.GATE_FAILED


def _print_plan(pipeline, profile) -> int:
    cases = pipeline.plan(profile)
    if not cases:
        print("no cases selected by this profile")
        return ExitCode.GATE_FAILED

    tests = sorted({c.emulation_id for c in cases})
    rules = sorted({c.rule_name for c in cases})
    print(bold(f"{len(cases)} case(s), {len(rules)} rule(s), {len(tests)} test(s)"))
    print()
    rows = [
        (
            c.rule_name,
            ", ".join(c.technique_ids) or "-",
            c.emulation_id,
            c.severity.value,
            c.expected.value,
            c.skip_reason or "",
        )
        for c in cases
    ]
    _print_table(["rule", "technique", "test", "severity", "expects", "skip"], rows)
    print()
    print(dim("Nothing was executed. Re-run without --plan-only to validate."))
    return ExitCode.OK


# ------------------------------------------------------------------- rules


def _add_rules(sub) -> None:
    parser = sub.add_parser("rules", help="inspect, lint, compile, and score detection content")
    rules = parser.add_subparsers(dest="rules_command", metavar="<subcommand>")

    listing = rules.add_parser("list", help="list rules")
    _add_selection_flags(listing)
    listing.add_argument("--json", action="store_true", help="emit JSON")
    listing.set_defaults(handler=_cmd_rules_list)

    show = rules.add_parser("show", help="show one rule in full")
    show.add_argument("name")
    show.add_argument("--json", action="store_true")
    show.set_defaults(handler=_cmd_rules_show)

    lint = rules.add_parser("lint", help="lint the rule library")
    _add_selection_flags(lint)
    lint.add_argument(
        "--dialect",
        action="append",
        dest="dialects",
        help="require the rule to compile for this dialect (repeatable)",
    )
    lint.add_argument("--only", action="append", default=[], help="only these codes/prefixes")
    lint.add_argument("--ignore", action="append", default=[], help="suppress these codes")
    lint.add_argument(
        "--level",
        default="info",
        choices=("error", "warning", "info"),
        help="minimum level to report (default: info)",
    )
    lint.add_argument(
        "--max-warnings", type=int, default=-1, help="fail if warnings exceed this count"
    )
    lint.add_argument("--json", action="store_true")
    lint.set_defaults(handler=_cmd_rules_lint)

    compile_parser = rules.add_parser("compile", help="compile a rule to a backend query")
    compile_parser.add_argument("name", nargs="?", help="rule name (default: all)")
    compile_parser.add_argument("--dialect", "-d", default="splunk")
    compile_parser.add_argument(
        "--telemetry", action="store_true", help="show the telemetry probe instead"
    )
    compile_parser.set_defaults(handler=_cmd_rules_compile)

    score = rules.add_parser("score", help="score rule quality")
    _add_selection_flags(score)
    score.add_argument("--json", action="store_true")
    score.add_argument("--explain", action="store_true", help="show per-dimension deductions")
    score.add_argument("--min", type=float, default=0.0, help="fail if any rule scores below this")
    score.set_defaults(handler=_cmd_rules_score)


def _add_selection_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--rule", action="append", dest="names", help="rule name (repeatable)")
    parser.add_argument("--platform", action="append", dest="platforms")
    parser.add_argument("--tactic", action="append", dest="tactics")
    parser.add_argument("--technique", action="append", dest="techniques")
    parser.add_argument("--tag", action="append", dest="tags")
    parser.add_argument("--status", action="append", dest="statuses")
    parser.add_argument("--min-severity", dest="min_severity")


def _select(args: argparse.Namespace, workspace) -> list:
    return workspace.rules.select(
        names=getattr(args, "names", None),
        platforms=getattr(args, "platforms", None),
        tactics=getattr(args, "tactics", None),
        techniques=getattr(args, "techniques", None),
        tags=getattr(args, "tags", None),
        statuses=getattr(args, "statuses", None),
        min_severity=Severity.parse(args.min_severity)
        if getattr(args, "min_severity", None)
        else None,
        include_inactive=True,
    )


def _cmd_rules_list(args: argparse.Namespace) -> int:
    from harness.pipeline import Workspace

    workspace = Workspace.load(args.root)
    rules = _select(args, workspace)

    if args.json:
        print(json.dumps([r.to_dict() for r in rules], indent=2, default=str))
        return ExitCode.OK

    _print_table(
        ["name", "severity", "status", "technique", "tests", "expects", "telemetry"],
        [
            (
                rule.name,
                rule.severity.value,
                rule.status.value,
                ", ".join(rule.technique_ids) or "-",
                str(len(rule.validation.emulation)),
                rule.validation.expect.value,
                ", ".join(rule.telemetry) or "-",
            )
            for rule in rules
        ],
    )
    print()
    stats = workspace.rules.stats()
    print(
        dim(
            f"{len(rules)} shown, {stats['total']} total, "
            f"{stats['production']} production, {stats['techniques']} techniques"
        )
    )
    if workspace.rules.errors:
        print(paint(f"{len(workspace.rules.errors)} file(s) failed to load", "\033[38;5;203m"))
        return ExitCode.RULE
    return ExitCode.OK


def _cmd_rules_show(args: argparse.Namespace) -> int:
    from harness.pipeline import Workspace

    workspace = Workspace.load(args.root)
    rule = workspace.rules.require(args.name)

    if args.json:
        print(json.dumps(rule.to_dict(), indent=2, default=str))
        return ExitCode.OK

    print(bold(rule.title))
    print(dim(f"{rule.name}  {rule.id}"))
    print()
    print(rule.description or dim("(no description)"))
    print()
    _print_kv(
        {
            "status": rule.status.value,
            "severity": rule.severity.value,
            "platforms": ", ".join(rule.platforms) or rule.platform,
            "technique": ", ".join(rule.technique_ids) or "-",
            "tactics": ", ".join(rule.tactics) or "-",
            "telemetry": ", ".join(rule.telemetry) or "-",
            "fields": ", ".join(rule.fields) or "-",
            "author": rule.author or "-",
            "date": rule.date or "-",
            "fingerprint": rule.fingerprint,
            "path": rule.relative_path(workspace.settings.root),
        }
    )
    print()
    print(bold("detection"))
    print(dump_yaml(rule.detection).rstrip())
    print()
    print(bold("validation"))
    _print_kv(
        {
            "emulation": ", ".join(rule.validation.emulation) or "-",
            "expect": rule.validation.expect.value,
            "max latency": format_duration(rule.validation.max_latency_seconds),
            "owner": rule.validation.owner or "-",
            "justification": rule.validation.justification or "-",
        }
    )
    if rule.falsepositives:
        print()
        print(bold("known false positives"))
        for entry in rule.falsepositives:
            print(f"  - {entry}")
    return ExitCode.OK


def _cmd_rules_lint(args: argparse.Namespace) -> int:
    from harness.pipeline import Workspace
    from rulekit.library import RuleLibrary
    from rulekit.linters import (
        Level,
        LintContext,
        filter_findings,
        run_linters,
        summarise,
    )

    workspace = Workspace.load(args.root)
    selected = {r.name for r in _select(args, workspace)}
    subset = RuleLibrary(
        rules={n: r for n, r in workspace.rules.rules.items() if n in selected},
        errors=workspace.rules.errors,
        root=workspace.rules.root,
        catalog=workspace.telemetry,
    )

    dialects = tuple(args.dialects or ())
    context = LintContext(
        catalog=workspace.telemetry,
        known_tests=workspace.tests.ids(),
        attack=workspace.attack.techniques,
        required_dialects=dialects,
        library_names=frozenset(workspace.rules.rules),
        root=workspace.settings.root,
    )

    # Lint at the lowest level and filter for display afterwards, so the
    # summary reports what actually exists. Counting only what passed the
    # level filter would let `--level error` claim zero warnings while two
    # were suppressed - a summary that lies quietly is worse than a noisy one.
    findings = run_linters(subset, context, only=args.only, ignore=args.ignore)
    shown = filter_findings(findings, min_level=Level(args.level))

    if args.json:
        print(json.dumps([f.to_dict() for f in shown], indent=2))
    else:
        for finding in shown:
            print(finding.format(root=workspace.settings.root))

    counts = summarise(findings)
    print()
    summary = (
        f"{counts['error']} error(s), {counts['warning']} warning(s), "
        f"{counts['info']} info across {len(subset)} rule(s)"
    )
    suppressed = len(findings) - len(shown)
    if suppressed:
        summary += f" ({suppressed} below --level {args.level}, not shown)"
    print(summary)

    if counts["error"]:
        return ExitCode.RULE
    if 0 <= args.max_warnings < counts["warning"]:
        print(
            f"error: {counts['warning']} warnings exceeds --max-warnings {args.max_warnings}",
            file=sys.stderr,
        )
        return ExitCode.GATE_FAILED
    return ExitCode.OK


def _cmd_rules_compile(args: argparse.Namespace) -> int:
    from harness.pipeline import Workspace
    from rulekit.compilers import get_compiler

    workspace = Workspace.load(args.root)
    compiler = get_compiler(args.dialect, workspace.telemetry)
    rules = [workspace.rules.require(args.name)] if args.name else list(workspace.rules)

    failures = 0
    for rule in rules:
        try:
            query = compiler.compile_telemetry(rule) if args.telemetry else compiler.compile(rule)
        except DvpError as exc:
            print(f"{rule.name}: {exc.message}", file=sys.stderr)
            failures += 1
            continue

        if query is None:
            print(f"{rule.name}: no telemetry probe for dialect '{args.dialect}'", file=sys.stderr)
            failures += 1
            continue

        if len(rules) > 1:
            print(bold(f"# {rule.name}"))
        print(query.text if not callable(query.payload) else f"<predicate> {query.text}")
        if len(rules) > 1:
            print()

    return ExitCode.RULE if failures else ExitCode.OK


def _cmd_rules_score(args: argparse.Namespace) -> int:
    from harness.pipeline import Workspace
    from rulekit.scorecard import ScoringContext, score_rule
    from rulekit.scorecard.model import LibraryScore

    workspace = Workspace.load(args.root)
    rules = _select(args, workspace)

    outcomes: dict[str, Outcome] = {}
    latencies: dict[str, float] = {}
    noisy: set[str] = set()
    try:
        with workspace.store() as store:
            if store.is_initialised():
                outcomes = {name: Outcome(value) for name, value in store.latest_outcomes().items()}
    except DvpError as exc:
        log.debug("no run history available: %s", exc)

    context = ScoringContext(
        catalog=workspace.telemetry,
        known_tests=workspace.tests.ids(),
        attack=workspace.attack.techniques,
        outcomes=outcomes,
        noisy=frozenset(noisy),
        latencies=latencies,
    )
    library = LibraryScore(rules=[score_rule(rule, context) for rule in rules])

    if args.json:
        print(json.dumps(library.to_dict(), indent=2))
        return ExitCode.GATE_FAILED if library.below(args.min) else ExitCode.OK

    _print_table(
        ["rule", "grade", "score", "weakest dimension", "severity"],
        [
            (
                score.rule_name,
                score.grade,
                f"{score.total:.0f}",
                score.weakest.name if score.weakest else "-",
                score.severity,
            )
            for score in sorted(library.rules, key=lambda s: s.total)
        ],
    )
    print()
    print(
        f"library average {library.average:.1f} ({library.grade})   "
        + "  ".join(f"{k}:{v}" for k, v in library.distribution().items() if v)
    )
    print(dim("by dimension: " + ", ".join(f"{k} {v}" for k, v in library.by_dimension().items())))

    if args.explain:
        for score in sorted(library.rules, key=lambda s: s.total):
            deductions = score.deductions()
            if not deductions:
                continue
            print()
            print(bold(f"{score.rule_name} ({score.total:.0f}, {score.grade})"))
            for text in deductions:
                print(f"  - {text}")

    below = library.below(args.min)
    if below:
        print(file=sys.stderr)
        print(f"error: {len(below)} rule(s) below the {args.min:.0f} threshold", file=sys.stderr)
        return ExitCode.GATE_FAILED
    return ExitCode.OK


# ------------------------------------------------------------------- tests


def _add_tests(sub) -> None:
    parser = sub.add_parser("tests", help="inspect emulation tests")
    tests = parser.add_subparsers(dest="tests_command", metavar="<subcommand>")

    listing = tests.add_parser("list", help="list emulation tests")
    listing.add_argument("--platform")
    listing.add_argument("--technique")
    listing.add_argument("--json", action="store_true")
    listing.set_defaults(handler=_cmd_tests_list)

    show = tests.add_parser("show", help="show one test, including its command")
    show.add_argument("test_id")
    show.set_defaults(handler=_cmd_tests_show)


def _cmd_tests_list(args: argparse.Namespace) -> int:
    from harness.pipeline import Workspace

    workspace = Workspace.load(args.root)
    tests = list(workspace.tests)
    if args.platform:
        tests = [t for t in tests if t.platform == args.platform.lower()]
    if args.technique:
        tests = [
            t
            for t in tests
            if t.technique == args.technique.upper()
            or t.technique.startswith(f"{args.technique.upper()}.")
        ]
    tests.sort(key=lambda t: (t.technique, t.id))

    if args.json:
        print(json.dumps([t.to_dict() for t in tests], indent=2))
        return ExitCode.OK

    by_test = workspace.rules.by_emulation()
    _print_table(
        ["id", "technique", "platform", "executor", "safe", "cleanup", "rules"],
        [
            (
                test.id,
                test.technique,
                test.platform,
                test.executor,
                "yes" if test.safe_mode else "NO",
                "yes" if test.has_cleanup else "-",
                str(len(by_test.get(test.id, []))),
            )
            for test in tests
        ],
    )
    print()
    orphans = [t.id for t in tests if not by_test.get(t.id)]
    if orphans:
        print(dim(f"{len(orphans)} test(s) not referenced by any rule: {', '.join(orphans[:5])}"))
    return ExitCode.OK


def _cmd_tests_show(args: argparse.Namespace) -> int:
    from harness.pipeline import Workspace

    workspace = Workspace.load(args.root)
    test = workspace.tests.require(args.test_id)

    print(bold(test.name))
    print(dim(test.id))
    print()
    print(test.description or dim("(no description)"))
    print()
    _print_kv(
        {
            "technique": test.technique,
            "platform": test.platform,
            "executor": test.executor,
            "safe mode": "yes" if test.safe_mode else "NO - runs the real technique",
            "destructive": "YES" if test.destructive else "no",
            "privileges": test.privileges,
            "duration": format_duration(test.duration_seconds),
            "telemetry": ", ".join(test.expected_telemetry) or "-",
            "atomic ref": test.atomic_ref or "-",
        }
    )
    if test.prerequisites:
        print()
        print(bold("prerequisites"))
        for item in test.prerequisites:
            print(f"  - {item}")
    if test.command:
        print()
        print(bold("command"))
        print(test.command)
    if test.cleanup:
        print()
        print(bold("cleanup"))
        print(test.cleanup)
    if test.notes:
        print()
        print(paint(f"note: {test.notes}", "\033[38;5;214m"))
    if test.requires_operator:
        print()
        print(
            paint(
                "This test is operator-run: the harness reserves a window and "
                "scores the result, but never executes it.",
                "\033[38;5;214m",
            )
        )
    return ExitCode.OK


# --------------------------------------------------------------- heartbeat


def _add_heartbeat(sub) -> None:
    parser = sub.add_parser(
        "heartbeat",
        help="per-host telemetry liveness for a log source",
        description=(
            "Answers the question validation cannot: has a host stopped sending, "
            "between runs? Exits 1 if any host is silent, so it can run from cron."
        ),
    )
    parser.add_argument(
        "--source",
        dest="sources",
        action="append",
        help="telemetry source id (repeatable; default: every source the corpora carry)",
    )
    parser.add_argument("--interval", help="expected gap between events (default: 15m)")
    parser.add_argument(
        "--grace",
        type=float,
        default=None,
        help="intervals overdue before a host is called silent (default: 3)",
    )
    parser.add_argument(
        "--as-of",
        help="evaluate as at this time (default: the newest recorded event)",
    )
    parser.add_argument(
        "--inventory",
        type=Path,
        help="file of expected host names, one per line - lets the report name a host "
        "that never onboarded, which no amount of log data can reveal on its own",
    )
    parser.add_argument("--all", action="store_true", help="list live hosts too, not just gaps")
    parser.add_argument("--json", action="store_true")
    parser.set_defaults(handler=_cmd_heartbeat)


def _cmd_heartbeat(args: argparse.Namespace) -> int:
    from harness.analysis.heartbeat import (
        DEFAULT_GRACE,
        DEFAULT_INTERVAL_SECONDS,
        build_heartbeat,
        format_age,
        observe_corpora,
        parse_interval,
    )
    from harness.backends.fixture import FixtureBackend
    from harness.core.timeutil import parse_ts, utcnow
    from harness.pipeline import Workspace

    workspace = Workspace.load(args.root)
    backend = FixtureBackend(workspace.settings.backend("fixture"), root=workspace.settings.root)
    backend.load()
    corpora = backend.corpora

    wanted = args.sources or [
        source.id for source in workspace.telemetry if source.scope("fixture")
    ]
    unknown = [s for s in wanted if s not in workspace.telemetry]
    if unknown:
        raise UsageError(
            f"unknown telemetry source(s): {', '.join(unknown)}",
            hint="Ids come from mapping/telemetry_sources.yml; `dvp doctor` lists them.",
        )

    interval = parse_interval(args.interval, DEFAULT_INTERVAL_SECONDS)
    grace = args.grace if args.grace is not None else DEFAULT_GRACE
    # Only from a file the operator supplies. Inferring which hosts *should*
    # send a source - from a naming convention, or from the fact that a host
    # sent some other source - manufactures gaps that are artefacts of the
    # inference. A host that never onboarded is real, and knowing about it
    # needs an inventory, not a guess.
    inventory = _read_inventory(args.inventory) if args.inventory else ()

    reports = []
    for source_id in wanted:
        source = workspace.telemetry.require(source_id)
        scope = source.scope("fixture")
        if not isinstance(scope, dict):
            continue
        observations = observe_corpora(corpora, scope)
        # As-of defaults to the end of the recording rather than to now. The
        # corpora are months old; measuring their age against the wall clock
        # would report every host as silent and say nothing about any estate.
        if args.as_of:
            as_of = parse_ts(args.as_of) or utcnow()
        elif observations:
            as_of = max(o.at for o in observations)
        else:
            as_of = utcnow()

        reports.append(
            (
                source_id,
                build_heartbeat(
                    observations,
                    source=source_id,
                    as_of=as_of,
                    interval_seconds=parse_interval(
                        (source.heartbeat or {}).get("interval"), interval
                    ),
                    grace=float((source.heartbeat or {}).get("grace", grace)),
                    expected_hosts=inventory,
                ),
            )
        )

    if args.json:
        print(
            json.dumps(
                {source_id: report.to_dict() for source_id, report in reports},
                indent=2,
            )
        )
    else:
        for source_id, report in reports:
            rows = report.beats if args.all else report.silent() + report.late()
            if not rows:
                print(f"{dim(source_id):48}  {len(report.alive())} host(s) alive")
                continue
            print(bold(source_id))
            print(
                dim(
                    f"  as of {report.as_of.isoformat().replace('+00:00', 'Z')}  "
                    f"interval {format_age(rows[0].interval_seconds)}"
                )
            )
            _print_table(
                ["state", "host", "last seen", "events"],
                [
                    (
                        b.state,
                        b.host,
                        "never" if b.never_seen else f"{format_age(b.age_seconds)} ago",
                        str(b.events),
                    )
                    for b in rows
                ],
            )
            print()

    silent = sum(len(report.silent()) for _, report in reports)
    if silent:
        print(f"{silent} host/source pair(s) silent")
        return ExitCode.GATE_FAILED
    print("every expected host is reporting")
    return ExitCode.OK


def _read_inventory(path: Path) -> tuple[str, ...]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise UsageError(f"could not read inventory {path}: {exc}") from exc
    hosts = [line.strip().lstrip("- ").strip() for line in lines]
    return tuple(h for h in hosts if h and not h.startswith("#"))


# ---------------------------------------------------------------- coverage


def _add_coverage(sub) -> None:
    parser = sub.add_parser("coverage", help="ATT&CK coverage from validation results")
    parser.add_argument("--run", help="run id (default: most recent)")
    parser.add_argument("--navigator", type=Path, help="write a Navigator layer here")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--gaps", choices=("detection", "visibility"), help="list only gaps")
    parser.set_defaults(handler=_cmd_coverage)


def _cmd_coverage(args: argparse.Namespace) -> int:
    from harness.analysis.coverage import build_coverage
    from harness.pipeline import Workspace
    from harness.reporting.navigator import build_layer

    workspace = Workspace.load(args.root)
    run = _load_run(workspace, args.run)
    coverage = build_coverage(run, reference=workspace.attack, targets=workspace.targets)

    if args.navigator:
        args.navigator.parent.mkdir(parents=True, exist_ok=True)
        args.navigator.write_text(
            json.dumps(build_layer(run, coverage), indent=2), encoding="utf-8"
        )
        print(f"wrote {args.navigator}")

    if args.json:
        print(json.dumps(coverage.to_dict(), indent=2))
        return ExitCode.OK

    if args.gaps:
        gaps = coverage.gaps(args.gaps)
        if not gaps:
            print(f"no {args.gaps} gaps")
            return ExitCode.OK
        _print_table(
            ["technique", "name", "priority", "rules", "missing telemetry"],
            [
                (
                    t.technique,
                    t.name[:40],
                    t.priority,
                    ", ".join(t.rules)[:40],
                    ", ".join(t.missing_telemetry)[:40] or "-",
                )
                for t in gaps
            ],
        )
        return ExitCode.OK

    print(bold(f"Coverage from {run.run_id} ({run.profile})"))
    print()
    _print_table(
        ["tactic", "priority", "cases", "detection", "target", "visibility", "target", ""],
        [
            (
                tactic.name or tactic.tactic,
                tactic.priority,
                str(tactic.scoreable),
                f"{tactic.detection_rate:.0%}",
                f"{tactic.target_detected:.0%}",
                f"{tactic.visibility_rate:.0%}",
                f"{tactic.target_visible:.0%}",
                "ok" if tactic.meets_target else "BELOW",
            )
            for tactic in sorted(coverage.tactics.values(), key=lambda t: t.order)
            if tactic.scoreable
        ],
    )
    print()
    print(
        f"overall detection {coverage.detection_rate:.0%}   "
        f"telemetry visibility {coverage.visibility_rate:.0%}"
    )

    for kind, label in (("visibility", "Visibility gaps"), ("detection", "Detection gaps")):
        gaps = coverage.gaps(kind)
        if gaps:
            print()
            print(bold(label))
            for technique in gaps:
                extra = (
                    f"  missing: {', '.join(technique.missing_telemetry)}"
                    if technique.missing_telemetry
                    else ""
                )
                print(f"  {technique.technique}  {technique.name}{dim(extra)}")

    return ExitCode.OK


# ------------------------------------------------------------------ report


def _add_report(sub) -> None:
    parser = sub.add_parser("report", help="re-render a stored run")
    parser.add_argument("--run", help="run id")
    parser.add_argument("--latest", action="store_true", help="use the most recent run")
    parser.add_argument(
        "--format", "-f", action="append", dest="formats", help="repeatable output format"
    )
    parser.add_argument("--output", "-o", type=Path, help="output directory")
    parser.add_argument("--stdout", action="store_true", help="print instead of writing files")
    parser.set_defaults(handler=_cmd_report)


def _cmd_report(args: argparse.Namespace) -> int:
    from harness.analysis.coverage import build_coverage
    from harness.pipeline import Workspace
    from harness.reporting import (
        render_html,
        render_json,
        render_junit,
        render_markdown,
        write_reports,
    )

    workspace = Workspace.load(args.root)
    run = _load_run(workspace, None if args.latest else args.run)
    coverage = build_coverage(run, reference=workspace.attack, targets=workspace.targets)
    formats = tuple(args.formats or workspace.settings.reporting.formats)

    if args.stdout:
        # Only one format can go to stdout. Honour an explicit --format;
        # otherwise default to markdown, which is the readable one.
        chosen = args.formats[0] if args.formats else "markdown"
        renderers = {
            "json": lambda: render_json(run, coverage=coverage),
            "markdown": lambda: render_markdown(run, coverage=coverage),
            "html": lambda: render_html(run, coverage=coverage),
            "junit": lambda: render_junit(run),
        }
        if chosen not in renderers:
            raise UsageError(
                f"'{chosen}' cannot be written to stdout",
                hint=f"Choose one of: {', '.join(renderers)}",
            )
        print(renderers[chosen]())
        return ExitCode.OK

    written = write_reports(
        run,
        args.output or workspace.settings.results_dir,
        formats=formats,
        coverage=coverage,
    )
    for path in written:
        print(workspace.settings.layout.relative(path))
    return ExitCode.OK


# -------------------------------------------------------------------- runs


def _add_runs(sub) -> None:
    parser = sub.add_parser("runs", help="browse stored runs")
    runs = parser.add_subparsers(dest="runs_command", metavar="<subcommand>")

    listing = runs.add_parser("list", help="list recent runs")
    listing.add_argument("--limit", type=int, default=20)
    listing.add_argument("--profile")
    listing.add_argument("--json", action="store_true")
    listing.set_defaults(handler=_cmd_runs_list)

    show = runs.add_parser("show", help="show one run")
    show.add_argument("run_id", nargs="?")
    show.set_defaults(handler=_cmd_runs_show)

    diff = runs.add_parser("diff", help="compare two runs")
    diff.add_argument("current", nargs="?")
    diff.add_argument("previous", nargs="?")
    diff.set_defaults(handler=_cmd_runs_diff)


def _cmd_runs_list(args: argparse.Namespace) -> int:
    from harness.pipeline import Workspace

    workspace = Workspace.load(args.root)
    with workspace.store() as store:
        if not store.is_initialised():
            print("no runs stored yet")
            return ExitCode.OK
        runs = store.list_runs(limit=args.limit, profile=args.profile)

    if args.json:
        print(json.dumps([r.to_dict() for r in runs], indent=2))
        return ExitCode.OK

    _print_table(
        ["run", "profile", "backend", "started", "cases", "det", "vis", "blind", "gates"],
        [
            (
                r.run_id,
                r.profile,
                r.backend,
                (r.started_at or "")[:19],
                str(r.total_cases),
                str(r.detected),
                str(r.visible),
                str(r.blind),
                "-" if r.gates_passed is None else ("pass" if r.gates_passed else "FAIL"),
            )
            for r in runs
        ],
    )
    return ExitCode.OK


def _cmd_runs_show(args: argparse.Namespace) -> int:
    from harness.analysis.coverage import build_coverage
    from harness.pipeline import Workspace
    from harness.reporting import print_case_lines, print_summary

    workspace = Workspace.load(args.root)
    run = _load_run(workspace, args.run_id)
    print_case_lines(run)
    print_summary(
        run,
        coverage=build_coverage(run, reference=workspace.attack, targets=workspace.targets),
        verbose=True,
    )
    return ExitCode.OK


def _cmd_runs_diff(args: argparse.Namespace) -> int:
    from harness.analysis.diff import diff_runs
    from harness.pipeline import Workspace

    workspace = Workspace.load(args.root)
    current = _load_run(workspace, args.current)
    with workspace.store() as store:
        previous = store.load_run(args.previous) if args.previous else store.previous_run(current)

    if previous is None:
        print("no earlier run to compare against")
        return ExitCode.OK

    diff = diff_runs(current, previous)
    print(bold(f"{previous.run_id} -> {current.run_id}"))
    print()
    if not diff.changed:
        print("no changes")
        return ExitCode.OK

    _print_table(
        ["change", "rule", "test", "before", "after", "note"],
        [
            (
                d.kind.value,
                d.rule_name,
                d.emulation_id,
                d.before.value if d.before else "-",
                d.after.value if d.after else "-",
                d.note[:50],
            )
            for d in diff.changed
        ],
    )
    return ExitCode.GATE_FAILED if diff.regressions else ExitCode.OK


# ---------------------------------------------------------------------- db


def _add_db(sub) -> None:
    parser = sub.add_parser("db", help="manage the run database")
    db = parser.add_subparsers(dest="db_command", metavar="<subcommand>")

    migrate = db.add_parser("migrate", help="apply pending migrations")
    migrate.add_argument("--dry-run", action="store_true")
    migrate.set_defaults(handler=_cmd_db_migrate)

    status = db.add_parser("status", help="show database status")
    status.set_defaults(handler=_cmd_db_status)

    prune = db.add_parser("prune", help="delete old runs")
    prune.add_argument("--keep-days", type=int)
    prune.set_defaults(handler=_cmd_db_prune)


def _cmd_db_migrate(args: argparse.Namespace) -> int:
    from harness.pipeline import Workspace

    workspace = Workspace.load(args.root)
    with workspace.store() as store:
        applied = store.migrate(dry_run=args.dry_run)
    if not applied:
        print("database is up to date")
    else:
        verb = "would apply" if args.dry_run else "applied"
        print(f"{verb}: {', '.join(applied)}")
    return ExitCode.OK


def _cmd_db_status(args: argparse.Namespace) -> int:
    from harness.pipeline import Workspace

    workspace = Workspace.load(args.root)
    with workspace.store() as store:
        stats = store.stats()
    _print_kv(dict(stats))
    return ExitCode.OK


def _cmd_db_prune(args: argparse.Namespace) -> int:
    from harness.pipeline import Workspace

    workspace = Workspace.load(args.root)
    keep = args.keep_days or workspace.settings.storage.retention_days
    with workspace.store() as store:
        deleted = store.prune(keep_days=keep)
    print(f"deleted {deleted} run(s) older than {keep} days")
    return ExitCode.OK


# ---------------------------------------------------------------- fixtures


def _add_fixtures(sub) -> None:
    parser = sub.add_parser("fixtures", help="inspect the offline event corpora")
    fixtures = parser.add_subparsers(dest="fixtures_command", metavar="<subcommand>")

    listing = fixtures.add_parser("list", help="list corpora")
    listing.set_defaults(handler=_cmd_fixtures_list)

    verify = fixtures.add_parser("verify", help="check corpora against the emulation catalogue")
    verify.set_defaults(handler=_cmd_fixtures_verify)


def _cmd_fixtures_list(args: argparse.Namespace) -> int:
    from harness.backends.fixture import FixtureCorpus
    from harness.pipeline import Workspace

    workspace = Workspace.load(args.root)
    root = workspace.settings.layout.fixture_runs
    rows = []
    for directory in sorted(p for p in root.iterdir() if p.is_dir()):
        corpus = FixtureCorpus.load(directory)
        rows.append(
            (
                corpus.name,
                str(len(corpus.events)),
                str(len(corpus.test_ids())),
                corpus.description.split("\n")[0][:60],
            )
        )
    _print_table(["scenario", "events", "tests", "description"], rows)
    return ExitCode.OK


def _cmd_fixtures_verify(args: argparse.Namespace) -> int:
    from harness.backends.fixture import FixtureCorpus
    from harness.pipeline import Workspace

    workspace = Workspace.load(args.root)
    root = workspace.settings.layout.fixture_runs
    known = workspace.tests.ids()
    referenced = set(workspace.rules.by_emulation())

    corpus_tests: set[str] = set()
    problems = 0
    for directory in sorted(p for p in root.iterdir() if p.is_dir()):
        corpus = FixtureCorpus.load(directory)
        corpus_tests |= corpus.test_ids()
        for test_id in sorted(corpus.test_ids()):
            if test_id not in known:
                print(f"{corpus.name}: events tagged with unknown test '{test_id}'")
                problems += 1

    # A test with no recorded events is how a BLIND outcome is expressed
    # offline, so it is reported as information, not as an error.
    for test_id in sorted(referenced - corpus_tests - {""}):
        print(
            dim(
                f"no recorded events for '{test_id}' "
                "(expected: this is how a visibility gap is represented offline)"
            )
        )

    print()
    print(
        f"{len(corpus_tests)} test(s) have recorded events; "
        f"{len(referenced)} referenced by rules; {problems} problem(s)"
    )
    return ExitCode.GATE_FAILED if problems else ExitCode.OK


# --------------------------------------------------------------- dashboard


def _add_dashboard(sub) -> None:
    parser = sub.add_parser("dashboard", help="serve the review dashboard")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--open", action="store_true", help="open a browser")
    parser.set_defaults(handler=_cmd_dashboard)


def _cmd_dashboard(args: argparse.Namespace) -> int:
    from dashboard.app import serve
    from harness.pipeline import Workspace

    workspace = Workspace.load(args.root)
    return serve(workspace, host=args.host, port=args.port, open_browser=args.open)


# ------------------------------------------------------------------ doctor


def _add_doctor(sub) -> None:
    parser = sub.add_parser("doctor", help="check configuration, content, and backends")
    parser.add_argument("--backends", action="store_true", help="also health-check every backend")
    parser.set_defaults(handler=_cmd_doctor)


def _cmd_doctor(args: argparse.Namespace) -> int:
    from harness.backends import check_all
    from harness.pipeline import Workspace

    workspace = Workspace.load(args.root)
    settings = workspace.settings
    problems = 0

    print(bold("Layout"))
    _print_kv(
        {
            "root": str(settings.root),
            "detections": _dir_status(settings.layout.detections),
            "fixtures": _dir_status(settings.layout.fixtures),
            "mapping": _dir_status(settings.layout.mapping),
            "profiles": _dir_status(settings.layout.profiles),
            "database": str(settings.database_path),
            "results": str(settings.results_dir),
        }
    )

    print()
    print(bold("Content"))
    stats = workspace.rules.stats()
    _print_kv(
        {
            "rules": f"{stats['total']} ({stats['production']} production)",
            "rules with validation": str(stats["with_validation"]),
            "load errors": str(stats["errors"]),
            "emulation tests": str(len(workspace.tests)),
            "telemetry sources": str(len(workspace.telemetry)),
            "profiles": ", ".join(workspace.profiles.names()) or "none",
            "attack techniques": str(len(workspace.attack.techniques)),
            "baseline profiles": str(len(workspace.baselines)),
        }
    )
    for error in workspace.rules.errors:
        print(paint(f"  ! {error}", "\033[38;5;203m"))
        problems += 1

    # Cross-reference: rules pointing at tests that do not exist.
    unknown = sorted(
        {
            test_id
            for rule in workspace.rules
            for test_id in rule.validation.emulation
            if test_id not in workspace.tests
        }
    )
    if unknown:
        print(paint(f"  ! rules reference {len(unknown)} unknown test(s):", "\033[38;5;203m"))
        for test_id in unknown[:10]:
            print(f"      {test_id}")
        problems += len(unknown)

    print()
    print(bold("Safety"))
    safety = settings.safety
    _print_kv(
        {
            "authorized": str(safety.authorized),
            "authorization reference": safety.authorization_reference or "(none)",
            "host allowlist": ", ".join(safety.host_allowlist) or "(empty - nothing may run)",
            "technique denylist": ", ".join(safety.technique_denylist),
            "allow destructive": str(safety.allow_destructive),
            "require cleanup": str(safety.require_cleanup),
        }
    )
    if not safety.authorized:
        print(dim("  execution is disabled; `dvp run` will plan and replay only"))

    print()
    print(bold("Database"))
    with workspace.store() as store:
        stats = store.stats()
        pending = store.migrate(dry_run=True) if stats.get("initialised") else ["(all)"]
    _print_kv(
        {
            "path": str(settings.database_path),
            "initialised": str(stats.get("initialised", False)),
            "runs": str(stats.get("runs", 0)),
            "pending migrations": ", ".join(pending) or "none",
        }
    )

    if args.backends:
        print()
        print(bold("Backends"))
        for status in check_all(settings):
            mark = "ok  " if status.ok else "FAIL"
            colour = "\033[38;5;41m" if status.ok else "\033[38;5;203m"
            print(f"  {paint(mark, colour)} {status.name:<12} {status.message}")
            if not status.ok and not status.details.get("skipped"):
                problems += 1

    print()
    if problems:
        print(paint(f"{problems} problem(s) found", "\033[38;5;203m"))
        return ExitCode.CONFIG
    print(paint("no problems found", "\033[38;5;41m"))
    return ExitCode.OK


# ----------------------------------------------------------------- helpers


def _load_run(workspace, run_id: str | None):
    from harness.core.errors import StorageError

    with workspace.store() as store:
        if not store.is_initialised():
            raise StorageError(
                "no runs have been stored yet",
                hint="Run `dvp run --profile quick-smoke` first.",
            )
        resolved = run_id or store.latest_run_id()
        if resolved is None:
            raise StorageError("no runs found in the database")
        run = store.load_run(resolved)
        if run is None:
            raise StorageError(f"run '{resolved}' not found")
        return run


def _store_result(workspace, result) -> None:
    from harness.core.errors import StorageError

    scores = {
        rule.name: (rule.fingerprint, 0.0, "")
        for rule in workspace.rules
        if any(r.case.rule_name == rule.name for r in result.run.results)
    }
    try:
        with workspace.store() as store:
            store.save_run(
                result.run,
                coverage=result.coverage,
                gates=result.gates,
                rule_scores=scores,
                findings=[
                    {
                        "kind": "noise",
                        "name": finding.rule,
                        "severity": finding.severity,
                        "rule": finding.rule,
                        "message": finding.describe(),
                        "detail": finding.to_dict(),
                    }
                    for finding in result.noise
                ],
                store_evidence=workspace.settings.storage.store_evidence,
            )
    except StorageError as exc:
        print(f"warning: could not store the run: {exc.message}", file=sys.stderr)


def _warn_about_content(workspace) -> None:
    if workspace.rules.errors:
        print(
            paint(
                f"warning: {len(workspace.rules.errors)} rule file(s) failed to load "
                "and are excluded from this run. Run `dvp rules lint` for detail.",
                "\033[38;5;214m",
            ),
            file=sys.stderr,
        )


def _dir_status(path: Path) -> str:
    if not path.exists():
        return f"{path} (MISSING)"
    count = sum(1 for _ in path.rglob("*") if _.is_file())
    return f"{path} ({count} files)"


def _operator() -> str:
    return (
        os.environ.get("DVP_OPERATOR")
        or os.environ.get("USER")
        or os.environ.get("USERNAME", "unknown")
    )


def _git_ref(root: Path) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return completed.stdout.strip() or None


def _print_table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> None:
    if not rows:
        print(dim("(nothing to show)"))
        return
    widths = [len(h) for h in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(str(cell)))

    print(dim("  ".join(h.upper().ljust(w) for h, w in zip(headers, widths, strict=False))))
    for row in rows:
        print(
            "  ".join(
                str(cell).ljust(width) for cell, width in zip(row, widths, strict=False)
            ).rstrip()
        )


def _print_kv(mapping: dict[str, Any]) -> None:
    if not mapping:
        return
    width = max(len(k) for k in mapping)
    for key, value in mapping.items():
        print(f"  {dim(key.ljust(width))}  {value}")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
