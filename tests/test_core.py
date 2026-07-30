"""Core primitives: time, configuration, models."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from harness.core.config import load_settings
from harness.core.errors import ConfigError
from harness.core.ids import content_fingerprint, new_run_id, slugify, stable_hash
from harness.core.models import Outcome, RunRecord, Severity
from harness.core.timeutil import (
    TimeWindow,
    format_duration,
    parse_duration,
    parse_ts,
    to_iso,
    utcnow,
)

# --------------------------------------------------------------------- time


@pytest.mark.parametrize(
    ("value", "expected_year"),
    [
        ("2026-05-14T09:12:00Z", 2026),
        ("2026-05-14T09:12:00.123Z", 2026),
        ("2026-05-14T09:12:00+02:00", 2026),
        ("2026-05-14 09:12:00", 2026),
        (1778751120, 2026),  # epoch seconds
        (1778751120000, 2026),  # epoch milliseconds
        ("1778751120", 2026),  # numeric string
    ],
)
def test_timestamp_parsing_handles_backend_variety(value, expected_year):
    parsed = parse_ts(value)
    assert parsed is not None
    assert parsed.year == expected_year
    assert parsed.tzinfo is not None


def test_naive_timestamps_are_treated_as_utc():
    # A silent local-time interpretation produces latencies wrong by hours.
    parsed = parse_ts(datetime(2026, 5, 14, 9, 12, 0))
    assert parsed.tzinfo is UTC


def test_unparsable_timestamp_returns_none_rather_than_raising():
    # One bad event must not abort an entire validation run.
    assert parse_ts("not a time") is None
    assert parse_ts(None) is None
    assert parse_ts("") is None


def test_iso_output_uses_a_z_suffix():
    assert to_iso(datetime(2026, 5, 14, 9, 12, tzinfo=UTC)).endswith("Z")


@pytest.mark.parametrize(
    ("text", "seconds"),
    [("90s", 90), ("5m", 300), ("1h", 3600), ("1h30m", 5400), ("2d", 172800), (45, 45)],
)
def test_duration_parsing(text, seconds):
    assert parse_duration(text) == seconds


def test_duration_falls_back_to_the_default_when_unparsable():
    assert parse_duration("banana", default=30.0) == 30.0


def test_duration_without_a_default_raises():
    with pytest.raises(ValueError):
        parse_duration("banana")


@pytest.mark.parametrize(
    ("seconds", "rendered"),
    [(0.25, "250ms"), (4.0, "4.0s"), (125, "2m 05s"), (7200, "2h 00m"), (None, "-")],
)
def test_duration_formatting(seconds, rendered):
    assert format_duration(seconds) == rendered


def test_window_rejects_an_inverted_range():
    now = utcnow()
    with pytest.raises(ValueError, match="precedes start"):
        TimeWindow(now, now - timedelta(seconds=1))


def test_window_widening_is_asymmetric():
    now = utcnow()
    window = TimeWindow(now, now).widen(before=60, after=300)
    assert window.duration_seconds == 360


def test_window_containment_is_inclusive():
    now = utcnow()
    window = TimeWindow(now, now + timedelta(seconds=10))
    assert window.contains(now)
    assert window.contains(now + timedelta(seconds=10))
    assert not window.contains(now + timedelta(seconds=11))
    assert not window.contains(None)


# ----------------------------------------------------------------- identity


def test_run_ids_sort_chronologically():
    early = new_run_id(now=datetime(2026, 1, 1, tzinfo=UTC))
    late = new_run_id(now=datetime(2026, 6, 1, tzinfo=UTC))
    assert early < late


def test_run_ids_are_unique():
    assert len({new_run_id() for _ in range(200)}) == 200


def test_stable_hash_is_deterministic():
    assert stable_hash("abc") == stable_hash("abc")
    assert stable_hash("abc") != stable_hash("abd")


def test_fingerprint_is_order_independent():
    assert content_fingerprint({"a": 1, "b": 2}) == content_fingerprint({"b": 2, "a": 1})


@pytest.mark.parametrize(
    ("raw", "slug"),
    [("LSASS Memory Access", "lsass-memory-access"), ("a  b", "a-b"), ("", "unnamed")],
)
def test_slugify(raw, slug):
    assert slugify(raw) == slug


# ------------------------------------------------------------------ models


def test_severity_is_ordered():
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW


def test_severity_parsing_accepts_aliases():
    assert Severity.parse("info") is Severity.INFORMATIONAL
    assert Severity.parse("nonsense", default=Severity.MEDIUM) is Severity.MEDIUM


def test_outcome_gap_routing():
    assert Outcome.VISIBLE.gap_kind == "detection"
    assert Outcome.BLIND.gap_kind == "visibility"
    assert Outcome.DETECTED.gap_kind is None
    assert Outcome.ERROR.gap_kind is None


def test_run_summary_of_an_empty_run_is_zero_not_an_error():
    summary = RunRecord(run_id="r", profile="p", backend="b", started_at=utcnow()).summarise()
    assert summary.total == 0
    assert summary.detection_rate == 0.0
    assert summary.latency_p50 is None


def test_run_record_round_trips_through_json(run_factory, case_factory):
    from harness.core.models import CaseResult, CaseStatus

    original = run_factory(
        [
            CaseResult(
                case=case_factory(),
                outcome=Outcome.DETECTED,
                status=CaseStatus.PASS,
                latency_seconds=4.0,
            )
        ]
    )
    restored = RunRecord.from_dict(original.to_dict())
    assert restored.run_id == original.run_id
    assert restored.results[0].outcome is Outcome.DETECTED
    assert restored.summarise().detection_rate == 1.0


# --------------------------------------------------------------------- config


def test_shipped_configuration_loads(repo_root):
    settings = load_settings(root=repo_root)
    assert settings.default_backend == "fixture"
    assert "fixture" in settings.backends


def test_fixture_backend_always_exists_even_with_no_config(tmp_path):
    settings = load_settings(root=tmp_path)
    assert "fixture" in settings.backends


def test_env_placeholder_resolution(tmp_path):
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "backends.yml").write_text(
        "backends:\n  x:\n    kind: splunk\n    options:\n      token: ${ENV:MY_TOKEN}\n",
        encoding="utf-8",
    )
    settings = load_settings(root=tmp_path, env={"MY_TOKEN": "secret-value"})
    assert settings.backends["x"].option("token") == "secret-value"


def test_missing_env_placeholder_fails_at_startup(tmp_path):
    # Failing at startup beats a run that reports everything blind because the
    # token was an empty string.
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "backends.yml").write_text(
        "backends:\n  x:\n    kind: splunk\n    options:\n      token: ${ENV:ABSENT_TOKEN}\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="ABSENT_TOKEN"):
        load_settings(root=tmp_path, env={})


def test_env_placeholder_default_is_used(tmp_path):
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "backends.yml").write_text(
        "backends:\n  x:\n    kind: splunk\n    options:\n      url: ${ENV:ABSENT:-https://fallback}\n",
        encoding="utf-8",
    )
    settings = load_settings(root=tmp_path, env={})
    assert settings.backends["x"].option("url") == "https://fallback"


def test_rate_thresholds_accept_percentages(tmp_path):
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "settings.yml").write_text(
        "gates:\n  min_detection_rate: 85%\n  min_visibility_rate: 0.9\n", encoding="utf-8"
    )
    settings = load_settings(root=tmp_path)
    assert settings.gates.min_detection_rate == 0.85
    assert settings.gates.min_visibility_rate == 0.9


def test_env_overrides_beat_the_settings_file(tmp_path):
    # DVP_<SECTION>_<KEY>: the first underscore separates the section, so
    # DVP_TIMING_INGEST_LAG maps to timing.ingest_lag.
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "settings.yml").write_text("timing:\n  ingest_lag: 60s\n")
    settings = load_settings(root=tmp_path, env={"DVP_TIMING_INGEST_LAG": "5s"})
    assert settings.timing.ingest_lag_seconds == 5.0


def test_env_override_of_a_gate_threshold(tmp_path):
    settings = load_settings(root=tmp_path, env={"DVP_GATES_MIN_DETECTION_RATE": "80%"})
    assert settings.gates.min_detection_rate == 0.8


def test_unknown_backend_names_the_alternatives(repo_root):
    settings = load_settings(root=repo_root)
    with pytest.raises(ConfigError, match="unknown backend"):
        settings.backend("nope")


def test_backend_require_reports_the_missing_option(repo_root):
    settings = load_settings(root=repo_root)
    with pytest.raises(ConfigError, match="missing required option"):
        settings.backends["sentinel"].require("workspace_id")


def test_package_version_matches_pyproject(repo_root):
    """Two files declare the version; a release with them disagreeing is a lie.

    `harness.__version__` is what `dvp --version` prints and what is stamped
    into every stored run, so a stale value misattributes results to the wrong
    build long after the release itself is forgotten.
    """
    import tomllib

    import harness

    with (repo_root / "pyproject.toml").open("rb") as handle:
        declared = tomllib.load(handle)["project"]["version"]
    assert harness.__version__ == declared


def test_changelog_documents_the_current_version(repo_root):
    changelog = (repo_root / "CHANGELOG.md").read_text(encoding="utf-8")
    import harness

    assert f"## [{harness.__version__}]" in changelog
