"""Configuration loading, layering, and validation.

Precedence, lowest to highest:

1. Built-in defaults (this module - the pipeline runs with zero config files)
2. ``config/settings.yml``
3. ``DVP_*`` environment variables
4. CLI flags (applied by the caller via :meth:`Settings.override`)

Secrets are never read from YAML directly. ``config/backends.yml`` uses
``${ENV:SPLUNK_TOKEN}`` placeholders that resolve at load time, so the file is
safe to commit and a missing credential fails at startup rather than mid-run.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field, fields, replace
from pathlib import Path
from typing import Any

from harness.core.errors import ConfigError
from harness.core.models import Severity
from harness.core.paths import Layout, layout
from harness.core.timeutil import parse_duration
from harness.core.yamlio import load_yaml

_ENV_REF = re.compile(r"\$\{ENV:(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?::-(?P<default>[^}]*))?\}")
_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}


def _defaults(cls: type) -> dict[str, Any]:
    """A dataclass's declared defaults, keyed by field name.

    Every settings class here is loaded from YAML where any key may be absent,
    so the class's own default is the fallback. ``fields()`` types a default as
    possibly-``MISSING``; each of these classes declares one for every field, so
    that union is noise at the call site and stops here instead.
    """
    return {f.name: f.default for f in fields(cls)}


@dataclass(frozen=True, slots=True)
class TimingSettings:
    """How long to wait for telemetry, and how wide to search.

    Getting these wrong is the single most common cause of false ``BLIND``
    results: query too early and the event has not been indexed yet.
    """

    #: Typical pipeline delay between event generation and searchability.
    ingest_lag_seconds: float = 60.0
    #: How long to keep re-querying before declaring a case blind.
    max_wait_seconds: float = 300.0
    #: Gap between polls while waiting.
    poll_interval_seconds: float = 15.0
    #: Search window padding before emulation start (clock skew tolerance).
    pre_window_seconds: float = 120.0
    #: Search window padding after emulation end.
    post_window_seconds: float = 300.0
    #: Quiet window sampled before emulation to measure baseline noise.
    baseline_window_seconds: float = 3600.0
    #: Pause between consecutive emulation tests, to keep behaviours separable.
    inter_test_delay_seconds: float = 5.0

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> TimingSettings:
        defaults = _defaults(cls)
        return cls(
            **{
                name: parse_duration(data.get(_strip_unit(name), None), default=default)
                for name, default in defaults.items()
            }
        )


def _strip_unit(name: str) -> str:
    return name.removesuffix("_seconds")


@dataclass(frozen=True, slots=True)
class SafetySettings:
    """Guard rails around emulation.

    The default posture is: **do nothing**. ``dvp run`` plans and reports but
    never executes a command until an operator has recorded an authorisation
    reference and explicitly opted in with ``--execute``. See
    ``docs/threat-model.md`` for the reasoning.
    """

    #: Must be true before any command executes. Set by a human, not a script.
    authorized: bool = False
    #: Change ticket / rules-of-engagement reference. Recorded in every run.
    authorization_reference: str = ""
    #: Hosts emulation may target. Empty list means "nothing is allowed".
    host_allowlist: tuple[str, ...] = ()
    #: If non-empty, only these ATT&CK techniques may be emulated.
    technique_allowlist: tuple[str, ...] = ()
    #: Techniques that are never emulated, even if listed in a profile.
    technique_denylist: tuple[str, ...] = ("T1485", "T1486", "T1490", "T1489", "T1561")
    #: Tests flagged ``destructive: true`` require this in addition to authorisation.
    allow_destructive: bool = False
    #: Refuse to run a test that has no cleanup block.
    require_cleanup: bool = True
    #: Abort the whole run after this many emulation failures.
    max_failures: int = 3
    #: Hard ceiling on a single test's runtime.
    command_timeout_seconds: float = 120.0
    #: Refuse to run if the target host looks like a production asset.
    require_lab_tag: bool = True

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> SafetySettings:
        defaults = _defaults(cls)
        return cls(
            authorized=_as_bool(data.get("authorized"), defaults["authorized"]),
            authorization_reference=str(data.get("authorization_reference") or ""),
            host_allowlist=_as_tuple(data.get("host_allowlist")),
            technique_allowlist=_as_tuple(data.get("technique_allowlist")),
            technique_denylist=_as_tuple(
                data.get("technique_denylist"), default=defaults["technique_denylist"]
            ),
            allow_destructive=_as_bool(data.get("allow_destructive"), False),
            require_cleanup=_as_bool(data.get("require_cleanup"), True),
            max_failures=int(data.get("max_failures", defaults["max_failures"])),
            command_timeout_seconds=parse_duration(
                data.get("command_timeout"), default=defaults["command_timeout_seconds"]
            ),
            require_lab_tag=_as_bool(data.get("require_lab_tag"), True),
        )


@dataclass(frozen=True, slots=True)
class GateSettings:
    """Thresholds that turn a run into a pass/fail CI signal."""

    #: Fail if the detection rate across scoreable cases drops below this.
    min_detection_rate: float = 0.0
    #: Fail if telemetry visibility drops below this.
    min_visibility_rate: float = 0.0
    #: Fail when a case that previously detected no longer does.
    fail_on_regression: bool = True
    #: Fail when a rule matches quiet-baseline activity.
    fail_on_noise: bool = False
    #: Only cases at or above this severity can fail the build.
    min_severity: Severity = Severity.MEDIUM
    #: Fail if any case errored (backend down, emulation crash).
    fail_on_error: bool = True
    #: Fail if detection latency exceeds the rule's declared budget.
    fail_on_latency_breach: bool = False
    #: Fail when a high-priority tactic sits below its coverage target.
    #: Off by default: a coverage target is an assertion about the whole estate,
    #: and most profiles validate a subset, where the number means nothing.
    fail_on_coverage_target: bool = False

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> GateSettings:
        return cls(
            min_detection_rate=_as_rate(data.get("min_detection_rate", 0.0)),
            min_visibility_rate=_as_rate(data.get("min_visibility_rate", 0.0)),
            fail_on_regression=_as_bool(data.get("fail_on_regression"), True),
            fail_on_noise=_as_bool(data.get("fail_on_noise"), False),
            min_severity=Severity.parse(data.get("min_severity"), default=Severity.MEDIUM),
            fail_on_error=_as_bool(data.get("fail_on_error"), True),
            fail_on_latency_breach=_as_bool(data.get("fail_on_latency_breach"), False),
            fail_on_coverage_target=_as_bool(data.get("fail_on_coverage_target"), False),
        )


@dataclass(frozen=True, slots=True)
class ReportingSettings:
    formats: tuple[str, ...] = ("json", "markdown")
    output_dir: str = "docs/results"
    #: Max example events attached to a case as evidence.
    evidence_limit: int = 3
    #: Redact these field names from stored evidence.
    redact_fields: tuple[str, ...] = ("password", "token", "secret", "apikey", "api_key")
    #: Also emit an ATT&CK Navigator layer alongside the report.
    navigator_layer: bool = True

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ReportingSettings:
        default = cls()
        return cls(
            formats=_as_tuple(data.get("formats"), default=default.formats),
            output_dir=str(data.get("output_dir", default.output_dir)),
            evidence_limit=int(data.get("evidence_limit", default.evidence_limit)),
            redact_fields=_as_tuple(data.get("redact_fields"), default=default.redact_fields),
            navigator_layer=_as_bool(data.get("navigator_layer"), True),
        )


@dataclass(frozen=True, slots=True)
class StorageSettings:
    path: str = ".dvp/dvp.sqlite3"
    #: Delete run records older than this many days on ``dvp db prune``.
    retention_days: int = 365
    #: Store matched events as evidence (off for regulated data).
    store_evidence: bool = True

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> StorageSettings:
        default = cls()
        return cls(
            path=str(data.get("path", default.path)),
            retention_days=int(data.get("retention_days", default.retention_days)),
            store_evidence=_as_bool(data.get("store_evidence"), True),
        )


@dataclass(frozen=True, slots=True)
class BackendConfig:
    """Connection settings for one telemetry platform."""

    name: str
    kind: str
    enabled: bool = True
    options: dict[str, Any] = field(default_factory=dict)
    #: Extra clause AND-ed into every query (e.g. restrict to the lab index).
    scope_filter: str = ""
    #: Field name holding the event timestamp in this platform.
    time_field: str = "_time"
    #: Per-query timeout.
    timeout_seconds: float = 60.0
    #: Cap on returned events per query.
    max_results: int = 500

    def option(self, key: str, default: Any = None) -> Any:
        return self.options.get(key, default)

    def require(self, key: str) -> Any:
        if key not in self.options or self.options[key] in (None, ""):
            raise ConfigError(
                f"backend '{self.name}': missing required option '{key}'",
                hint=f"Add it under backends.{self.name}.options in config/backends.yml.",
            )
        return self.options[key]


@dataclass(frozen=True, slots=True)
class Settings:
    """Fully resolved configuration for one invocation."""

    layout: Layout
    default_backend: str = "fixture"
    timing: TimingSettings = field(default_factory=TimingSettings)
    safety: SafetySettings = field(default_factory=SafetySettings)
    gates: GateSettings = field(default_factory=GateSettings)
    reporting: ReportingSettings = field(default_factory=ReportingSettings)
    storage: StorageSettings = field(default_factory=StorageSettings)
    backends: dict[str, BackendConfig] = field(default_factory=dict)
    #: Free-form labels attached to every run (team, environment, region).
    labels: dict[str, str] = field(default_factory=dict)

    @property
    def root(self) -> Path:
        return self.layout.root

    @property
    def database_path(self) -> Path:
        path = Path(self.storage.path)
        return path if path.is_absolute() else self.root / path

    @property
    def results_dir(self) -> Path:
        path = Path(self.reporting.output_dir)
        return path if path.is_absolute() else self.root / path

    def backend(self, name: str | None = None) -> BackendConfig:
        """Look up a backend by name, defaulting to ``default_backend``."""
        name = name or self.default_backend
        if name not in self.backends:
            known = ", ".join(sorted(self.backends)) or "none configured"
            raise ConfigError(
                f"unknown backend '{name}' (known: {known})",
                hint="Define it in config/backends.yml, or pass --backend fixture "
                "to run fully offline.",
            )
        return self.backends[name]

    def override(self, **kwargs: Any) -> Settings:
        """Return a copy with top-level fields replaced (used for CLI flags)."""
        return replace(self, **{k: v for k, v in kwargs.items() if v is not None})


def load_settings(
    *,
    root: Path | None = None,
    settings_file: Path | None = None,
    backends_file: Path | None = None,
    env: Mapping[str, str] | None = None,
) -> Settings:
    """Load and layer configuration. Never raises for missing optional files."""
    env = env if env is not None else os.environ
    project = layout(root)

    settings_path = settings_file or _first_existing(
        project.config / "settings.yml",
        project.config / "settings.yaml",
        project.config / "settings.example.yml",
    )
    raw: dict[str, Any] = {}
    if settings_path is not None:
        loaded = load_yaml(settings_path, default={})
        if not isinstance(loaded, dict):
            raise ConfigError(f"{settings_path}: expected a YAML mapping at the top level")
        raw = loaded

    raw = _apply_env_overrides(raw, env)
    raw = _resolve_env_refs(raw, env, source=str(settings_path or "<defaults>"))

    backends_path = backends_file or (project.config / "backends.yml")
    backends = _load_backends(backends_path, env)

    default_backend = str(raw.get("default_backend", "fixture"))
    if default_backend not in backends:
        # A misconfigured default must not stop `dvp rules lint` from working,
        # so fall back to the always-available offline backend.
        backends.setdefault(
            "fixture",
            BackendConfig(name="fixture", kind="fixture", options={"path": "fixtures/runs"}),
        )
        if default_backend not in backends:
            default_backend = "fixture"

    return Settings(
        layout=project,
        default_backend=default_backend,
        timing=TimingSettings.from_dict(raw.get("timing") or {}),
        safety=SafetySettings.from_dict(raw.get("safety") or {}),
        gates=GateSettings.from_dict(raw.get("gates") or {}),
        reporting=ReportingSettings.from_dict(raw.get("reporting") or {}),
        storage=StorageSettings.from_dict(raw.get("storage") or {}),
        backends=backends,
        labels={str(k): str(v) for k, v in (raw.get("labels") or {}).items()},
    )


def _load_backends(path: Path, env: Mapping[str, str]) -> dict[str, BackendConfig]:
    """Parse ``config/backends.yml`` into :class:`BackendConfig` objects.

    Always guarantees a ``fixture`` backend so the pipeline is usable with no
    SIEM at all - that is what makes the test suite and CI runs deterministic.
    """
    result: dict[str, BackendConfig] = {
        "fixture": BackendConfig(
            name="fixture",
            kind="fixture",
            options={"path": "fixtures/runs"},
            time_field="_time",
        )
    }
    if not path.exists():
        return result

    document = load_yaml(path, default={}) or {}
    entries = document.get("backends", document)
    if not isinstance(entries, dict):
        raise ConfigError(f"{path}: 'backends' must be a mapping of name -> config")

    for name, spec in entries.items():
        if not isinstance(spec, dict):
            raise ConfigError(f"{path}: backend '{name}' must be a mapping")
        spec = _resolve_env_refs(spec, env, source=f"{path}:{name}")
        options = spec.get("options") or {}
        if not isinstance(options, dict):
            raise ConfigError(f"{path}: backend '{name}': 'options' must be a mapping")
        result[str(name)] = BackendConfig(
            name=str(name),
            kind=str(spec.get("kind", name)),
            enabled=_as_bool(spec.get("enabled"), True),
            options=dict(options),
            scope_filter=str(spec.get("scope_filter") or ""),
            time_field=str(spec.get("time_field") or "_time"),
            timeout_seconds=parse_duration(spec.get("timeout"), default=60.0),
            max_results=int(spec.get("max_results", 500)),
        )
    return result


def _resolve_env_refs(value: Any, env: Mapping[str, str], *, source: str) -> Any:
    """Recursively expand ``${ENV:NAME}`` / ``${ENV:NAME:-fallback}``."""
    if isinstance(value, dict):
        return {k: _resolve_env_refs(v, env, source=source) for k, v in value.items()}
    if isinstance(value, list):
        return [_resolve_env_refs(v, env, source=source) for v in value]
    if not isinstance(value, str):
        return value

    def _sub(match: re.Match[str]) -> str:
        name = match.group("name")
        fallback = match.group("default")
        if name in env:
            return env[name]
        if fallback is not None:
            return fallback
        raise ConfigError(
            f"{source}: environment variable {name} is referenced but not set",
            hint=f"export {name}=... , or give it a default with ${{ENV:{name}:-value}}.",
        )

    return _ENV_REF.sub(_sub, value)


#: ``DVP_TIMING_INGEST_LAG=30`` -> ``timing.ingest_lag``
_ENV_PREFIX = "DVP_"
_ENV_SECTIONS = ("timing", "safety", "gates", "reporting", "storage")


def _apply_env_overrides(raw: dict[str, Any], env: Mapping[str, str]) -> dict[str, Any]:
    merged = {k: (dict(v) if isinstance(v, dict) else v) for k, v in raw.items()}
    for key, value in env.items():
        if not key.startswith(_ENV_PREFIX) or key in ("DVP_ROOT", "DVP_FORCE_COLOR"):
            continue
        remainder = key[len(_ENV_PREFIX) :].lower()
        section, _, leaf = remainder.partition("_")
        if section in _ENV_SECTIONS and leaf:
            bucket = merged.setdefault(section, {})
            if isinstance(bucket, dict):
                bucket[leaf] = value
        else:
            merged[remainder] = value
    return merged


def _first_existing(*candidates: Path) -> Path | None:
    return next((c for c in candidates if c.exists()), None)


def _as_bool(value: Any, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in _TRUE:
        return True
    if text in _FALSE:
        return False
    return default


def _as_tuple(value: Any, *, default: tuple[str, ...] = ()) -> tuple[str, ...]:
    if value is None:
        return default
    if isinstance(value, str):
        return tuple(part.strip() for part in value.split(",") if part.strip())
    if isinstance(value, (list, tuple, set)):
        return tuple(str(v).strip() for v in value if str(v).strip())
    return default


def _as_rate(value: Any) -> float:
    """Accept ``0.85`` or ``85`` or ``"85%"`` and normalise to a 0..1 fraction."""
    if value is None:
        return 0.0
    text = str(value).strip().rstrip("%")
    try:
        number = float(text)
    except ValueError as exc:
        raise ConfigError(f"invalid rate threshold: {value!r}") from exc
    if number > 1.0:
        number /= 100.0
    return max(0.0, min(1.0, number))
