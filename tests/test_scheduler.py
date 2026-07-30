"""Checks on the schedule manifest and the units rendered from it.

``scheduler/jobs.yml`` is the only place a schedule is written down, and the
systemd drop-ins under ``scheduler/systemd/generated/`` are committed so that
an operator can install them without this repository's Python environment. Two
copies of the same fact drift, so the sync check here is the thing that keeps
them honest: edit the manifest without re-rendering and the build fails.

The translation tests matter for a subtler reason. systemd accepts a malformed
``OnCalendar=`` by never firing, so a bad schedule does not fail loudly - it
produces a validation job that silently stops running, which looks exactly like
a healthy estate with nothing to report.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_script():
    """Import scripts/render_systemd.py, which is not an installed module."""
    path = REPO_ROOT / "scripts" / "render_systemd.py"
    spec = importlib.util.spec_from_file_location("render_systemd", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolves annotations through sys.modules, so the module has to
    # be registered before it executes, not after.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


render_systemd = _load_script()
ManifestError = render_systemd.ManifestError


# ------------------------------------------------------------- translation


@pytest.mark.parametrize(
    ("schedule", "expected"),
    [
        ("02:15", "*-*-* 02:15:00"),
        ("2:15", "*-*-* 02:15:00"),
        ("Sun 03:00", "Sun *-*-* 03:00:00"),
        ("Mon..Fri 06:30", "Mon..Fri *-*-* 06:30:00"),
        ("Mon *-*-01..07 04:00", "Mon *-*-01..07 04:00:00"),
        ("*-*-* 02:15:00", "*-*-* 02:15:00"),
        ("daily", "daily"),
    ],
)
def test_schedule_translates_to_a_calendar_expression(schedule, expected):
    assert render_systemd.to_oncalendar(schedule) == expected


@pytest.mark.parametrize("schedule", ["", "   ", "every night", "sometimes"])
def test_unrecognised_schedule_is_refused_not_guessed(schedule):
    # Guessing here would produce a unit that installs cleanly and never fires.
    with pytest.raises(ManifestError):
        render_systemd.to_oncalendar(schedule)


# ---------------------------------------------------------------- rendering


def test_repository_manifest_renders():
    rendered = render_systemd.render(render_systemd.load_jobs())
    assert rendered, "the shipped manifest has timer jobs, so it must render units"


def test_every_timer_job_gets_a_timer_dropin():
    manifest = render_systemd.load_jobs()
    timer_jobs = [j for j in manifest["jobs"] if j.get("trigger") == "timer"]
    rendered = render_systemd.render(manifest)
    timers = [r for r in rendered if r.path.name == "schedule.conf"]
    assert len(timers) == len(timer_jobs)


def test_ci_jobs_do_not_get_a_timer():
    # A CI job runs in a workflow. Rendering a timer for it would put a schedule
    # on a host that nothing on that host owns.
    manifest = render_systemd.load_jobs()
    ci_profiles = {j["profile"] for j in manifest["jobs"] if j.get("trigger") == "ci"}
    timer_profiles = {j["profile"] for j in manifest["jobs"] if j.get("trigger") == "timer"}
    rendered = render_systemd.render(manifest)
    for profile in ci_profiles - timer_profiles:
        assert not any(profile in r.relative for r in rendered)


def test_timer_dropin_clears_the_inherited_schedule():
    # The empty `OnCalendar=` must come first: without it systemd adds the
    # override to the template's default and the job runs twice.
    rendered = render_systemd.render(render_systemd.load_jobs())
    for item in rendered:
        if item.path.name != "schedule.conf":
            continue
        lines = [ln for ln in item.content.splitlines() if ln.startswith("OnCalendar")]
        assert lines[0] == "OnCalendar="
        assert len(lines) == 2
        assert lines[1] != "OnCalendar="


def test_only_executing_jobs_get_a_service_override():
    manifest = render_systemd.load_jobs()
    executing = {j["profile"] for j in manifest["jobs"] if j.get("execute")}
    rendered = render_systemd.render(manifest)
    overrides = {r for r in rendered if r.path.name == "execute.conf"}
    assert {r.path.parent.name.split("@")[1].removesuffix(".service.d") for r in overrides} == (
        executing
    )
    for item in overrides:
        assert "--execute" in item.content


def test_execute_without_authorisation_is_refused():
    manifest = {
        "defaults": {},
        "jobs": [
            {
                "name": "unauthorised",
                "trigger": "timer",
                "profile": "quick-smoke",
                "schedule": "03:00",
                "execute": True,
            }
        ],
    }
    with pytest.raises(ManifestError, match="authorization"):
        render_systemd.render(manifest, profiles={"quick-smoke"})


def test_unknown_profile_is_refused():
    manifest = {
        "jobs": [
            {"name": "ghost", "trigger": "timer", "profile": "no-such-profile", "schedule": "03:00"}
        ]
    }
    with pytest.raises(ManifestError, match="does not exist"):
        render_systemd.render(manifest, profiles={"quick-smoke"})


def test_two_jobs_on_one_profile_are_refused():
    # systemd template instances are keyed on the profile, so the second job
    # would overwrite the first's drop-in without anything reporting it.
    manifest = {
        "jobs": [
            {"name": "a", "trigger": "timer", "profile": "quick-smoke", "schedule": "03:00"},
            {"name": "b", "trigger": "timer", "profile": "quick-smoke", "schedule": "04:00"},
        ]
    }
    with pytest.raises(ManifestError, match="already scheduled"):
        render_systemd.render(manifest, profiles={"quick-smoke"})


def test_timer_job_without_a_schedule_is_refused():
    manifest = {"jobs": [{"name": "a", "trigger": "timer", "profile": "quick-smoke"}]}
    with pytest.raises(ManifestError, match="no schedule"):
        render_systemd.render(manifest, profiles={"quick-smoke"})


# ------------------------------------------------------------------- drift


def test_committed_dropins_match_the_manifest():
    # The check `make ci` runs. If this fails, run:
    #   python scripts/render_systemd.py
    problems = render_systemd.drift(render_systemd.render(render_systemd.load_jobs()))
    assert problems == []


def test_ci_workflow_runs_the_profile_the_manifest_says_it_does():
    """The GitHub workflow and the manifest must not disagree about the gate.

    The workflow cannot be generated - it needs matrices, artifacts and step
    summaries the manifest has no vocabulary for - so it is hand-written and
    checked instead. What must hold is the part a reader relies on: the profile
    the pull-request gate actually validates is the one jobs.yml advertises.
    """
    workflow = yaml.safe_load(
        (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    )
    steps = workflow["jobs"]["validate"]["steps"]
    body = "\n".join(str(step.get("run", "")) for step in steps)

    ci_jobs = [j for j in render_systemd.load_jobs()["jobs"] if j.get("trigger") == "ci"]
    assert ci_jobs, "jobs.yml advertises a CI gate; if that changed, change this test with it"
    for job in ci_jobs:
        assert f"--profile {job['profile']}" in body


def test_write_removes_units_for_deleted_jobs(tmp_path):
    orphan = tmp_path / "dvp-validation@gone.timer.d" / "schedule.conf"
    orphan.parent.mkdir(parents=True)
    orphan.write_text("OnCalendar=daily\n", encoding="utf-8")

    manifest = {
        "jobs": [{"name": "a", "trigger": "timer", "profile": "quick-smoke", "schedule": "03:00"}]
    }
    rendered = render_systemd.render(manifest, profiles={"quick-smoke"})
    # Retarget the rendered paths at the throwaway tree.
    rendered = [
        render_systemd.Rendered(
            path=tmp_path / r.path.relative_to(render_systemd.GENERATED), content=r.content
        )
        for r in rendered
    ]

    render_systemd.write(rendered, root=tmp_path)

    assert not orphan.exists(), "a job removed from the manifest must take its timer with it"
    assert (tmp_path / "dvp-validation@quick-smoke.timer.d" / "schedule.conf").exists()


def test_write_is_idempotent(tmp_path):
    manifest = {
        "jobs": [{"name": "a", "trigger": "timer", "profile": "quick-smoke", "schedule": "03:00"}]
    }
    rendered = [
        render_systemd.Rendered(
            path=tmp_path / r.path.relative_to(render_systemd.GENERATED), content=r.content
        )
        for r in render_systemd.render(manifest, profiles={"quick-smoke"})
    ]
    assert render_systemd.write(rendered, root=tmp_path), "first write reports what it wrote"
    assert render_systemd.write(rendered, root=tmp_path) == [], "second write changes nothing"
