"""The detection rule model.

Rules are Sigma-shaped YAML with three pipeline-specific additions:

``telemetry:``
    Named log sources from ``mapping/telemetry_sources.yml``. This is what makes
    the three-state model possible: the harness can ask "did the telemetry even
    arrive?" independently of "did the rule fire?".

``validation:``
    Which emulation tests should trigger this rule, what outcome is expected,
    and how long detection is allowed to take.

``tuning:``
    Environment-specific allowlists kept out of the detection logic, so
    upstream rule updates do not clobber local tuning.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

from harness.core.errors import RuleError
from harness.core.ids import content_fingerprint, slugify
from harness.core.models import AttackRef, Outcome, RuleStatus, Severity
from harness.core.timeutil import parse_duration
from harness.core.yamlio import load_yaml
from rulekit.condition import ConditionError, Node, parse_condition, referenced_selections
from rulekit.matcher import MatchError, all_field_names, parse_field_spec, selection_names

__all__ = ["Rule", "TuningSpec", "ValidationSpec"]

_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_REQUIRED_KEYS = ("title", "detection")

#: Recognised top-level keys. Anything else is flagged by the linter rather than
#: rejected, so a rule carrying extra organisational metadata still loads.
_KNOWN_KEYS = frozenset(
    {
        "id",
        "name",
        "title",
        "status",
        "severity",
        "description",
        "author",
        "date",
        "modified",
        "references",
        "attack",
        "platforms",
        "logsource",
        "telemetry",
        "detection",
        "fields",
        "falsepositives",
        "validation",
        "tuning",
        "tags",
        "level",
    }
)


@dataclass(frozen=True, slots=True)
class ValidationSpec:
    """How this rule is proven to work."""

    #: Emulation test ids that should make this rule fire.
    emulation: tuple[str, ...] = ()
    #: The outcome an operator expects today. ``visible`` or ``blind`` document
    #: a *known, accepted* gap so it reports as PASS instead of paging someone.
    expect: Outcome = Outcome.DETECTED
    #: Detection latency budget; exceeding it is reported and can fail a gate.
    max_latency_seconds: float = 300.0
    #: Set false to plan the case but never execute it.
    enabled: bool = True
    #: Why a non-``detected`` expectation is currently acceptable.
    justification: str = ""
    #: Team accountable for closing the gap.
    owner: str = ""

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None, *, context: str) -> ValidationSpec:
        if not data:
            return cls()
        if not isinstance(data, Mapping):
            raise RuleError("'validation' must be a mapping", path=context)

        emulation = data.get("emulation") or data.get("tests") or []
        if isinstance(emulation, str):
            emulation = [emulation]

        try:
            expect = Outcome(str(data.get("expect", "detected")).lower())
        except ValueError as exc:
            raise RuleError(
                f"validation.expect must be one of detected/visible/blind, "
                f"got {data.get('expect')!r}",
                path=context,
            ) from exc
        if expect in (Outcome.ERROR, Outcome.SKIPPED):
            raise RuleError(
                f"validation.expect cannot be '{expect.value}' - "
                "operational states are not expectations",
                path=context,
            )

        spec = cls(
            emulation=tuple(str(e) for e in emulation),
            expect=expect,
            max_latency_seconds=parse_duration(data.get("max_latency"), default=300.0),
            enabled=bool(data.get("enabled", True)),
            justification=str(data.get("justification") or ""),
            owner=str(data.get("owner") or ""),
        )
        if spec.expect is not Outcome.DETECTED and not spec.justification:
            raise RuleError(
                f"validation.expect is '{spec.expect.value}' but no justification is given. "
                "An accepted gap must say why it is accepted",
                path=context,
                hint="Add validation.justification and validation.owner.",
            )
        return spec


@dataclass(frozen=True, slots=True)
class TuningSpec:
    """Local exceptions, kept separate from upstream detection logic."""

    #: Baseline profile whose allowlist entries apply to this rule.
    baseline_profile: str = ""
    #: Free-form suppression notes for the analyst.
    notes: tuple[str, ...] = ()
    #: Expected alert volume per day; large deviations are worth reviewing.
    expected_daily_volume: int | None = None

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None) -> TuningSpec:
        if not data:
            return cls()
        notes = data.get("notes") or []
        if isinstance(notes, str):
            notes = [notes]
        volume = data.get("expected_daily_volume")
        return cls(
            baseline_profile=str(data.get("baseline_profile") or ""),
            notes=tuple(str(n) for n in notes),
            expected_daily_volume=int(volume) if volume is not None else None,
        )


@dataclass(slots=True)
class Rule:
    """A parsed, validated detection rule."""

    name: str
    title: str
    detection: dict[str, Any]
    condition_text: str
    condition: Node
    id: str = ""
    status: RuleStatus = RuleStatus.EXPERIMENTAL
    severity: Severity = Severity.MEDIUM
    description: str = ""
    author: str = ""
    date: str = ""
    modified: str = ""
    references: tuple[str, ...] = ()
    attack: tuple[AttackRef, ...] = ()
    platforms: tuple[str, ...] = ()
    logsource: dict[str, str] = field(default_factory=dict)
    telemetry: tuple[str, ...] = ()
    fields: tuple[str, ...] = ()
    falsepositives: tuple[str, ...] = ()
    validation: ValidationSpec = field(default_factory=ValidationSpec)
    tuning: TuningSpec = field(default_factory=TuningSpec)
    tags: tuple[str, ...] = ()
    path: Path | None = None
    raw: dict[str, Any] = field(default_factory=dict)
    unknown_keys: tuple[str, ...] = ()

    # -- derived -----------------------------------------------------------

    @property
    def selections(self) -> list[str]:
        return list(selection_names(self.detection))

    @property
    def referenced_selections(self) -> set[str]:
        return referenced_selections(self.condition)

    @property
    def unused_selections(self) -> list[str]:
        """Selections defined but never referenced - almost always dead logic."""
        return [s for s in self.selections if s not in self.referenced_selections]

    @property
    def technique_ids(self) -> list[str]:
        return [ref.technique for ref in self.attack]

    @property
    def tactics(self) -> list[str]:
        seen: dict[str, None] = {}
        for ref in self.attack:
            if ref.tactic:
                seen.setdefault(ref.tactic, None)
        return list(seen)

    @property
    def field_names(self) -> list[str]:
        return all_field_names(self.detection)

    @property
    def fingerprint(self) -> str:
        """Hash of the *logic* only. Editing the description does not change it,
        so ``dvp rules diff`` reports behavioural changes and ignores prose."""
        return content_fingerprint(
            {
                "detection": self.detection,
                "logsource": self.logsource,
                "telemetry": list(self.telemetry),
            }
        )

    @property
    def is_active(self) -> bool:
        return self.status not in (RuleStatus.DEPRECATED, RuleStatus.UNSUPPORTED)

    @property
    def platform(self) -> str:
        return self.platforms[0] if self.platforms else str(self.logsource.get("product", "any"))

    def relative_path(self, root: Path | None = None) -> str:
        if self.path is None:
            return "<inline>"
        if root is None:
            return str(self.path)
        try:
            return str(self.path.relative_to(root)).replace("\\", "/")
        except ValueError:
            return str(self.path)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "title": self.title,
            "status": self.status.value,
            "severity": self.severity.value,
            "description": self.description,
            "author": self.author,
            "date": self.date,
            "modified": self.modified,
            "references": list(self.references),
            "attack": [ref.to_dict() for ref in self.attack],
            "platforms": list(self.platforms),
            "logsource": dict(self.logsource),
            "telemetry": list(self.telemetry),
            "detection": self.detection,
            "condition": self.condition_text,
            "fields": list(self.fields),
            "falsepositives": list(self.falsepositives),
            "tags": list(self.tags),
            "fingerprint": self.fingerprint,
            "path": str(self.path) if self.path else None,
            "validation": {
                "emulation": list(self.validation.emulation),
                "expect": self.validation.expect.value,
                "max_latency_seconds": self.validation.max_latency_seconds,
                "enabled": self.validation.enabled,
                "justification": self.validation.justification,
                "owner": self.validation.owner,
            },
        }

    # -- construction ------------------------------------------------------

    @classmethod
    def from_file(cls, path: Path | str) -> Rule:
        path = Path(path)
        document = load_yaml(path)
        if not isinstance(document, dict):
            raise RuleError("rule file must contain a YAML mapping", path=str(path))
        return cls.from_dict(document, path=path)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any], *, path: Path | None = None) -> Rule:
        context = str(path) if path else str(data.get("name") or data.get("title") or "<inline>")

        missing = [key for key in _REQUIRED_KEYS if not data.get(key)]
        if missing:
            raise RuleError(f"missing required key(s): {', '.join(missing)}", path=context)

        detection = data["detection"]
        if not isinstance(detection, dict):
            raise RuleError("'detection' must be a mapping of selections", path=context)
        if "condition" not in detection:
            raise RuleError(
                "'detection' has no 'condition'",
                path=context,
                hint="Add e.g. `condition: selection and not filter_known_good`.",
            )

        condition_text = detection["condition"]
        if isinstance(condition_text, list):
            # Sigma allows a list of conditions meaning OR; normalise to one string.
            condition_text = " or ".join(f"({c})" for c in condition_text)

        names = list(selection_names(detection))
        if not names:
            raise RuleError("'detection' defines no selections", path=context)

        try:
            condition = parse_condition(str(condition_text), names)
        except ConditionError as exc:
            raise RuleError(f"invalid condition: {exc.annotated()}", path=context) from exc

        # Validate every selection key eagerly so a bad modifier fails at load
        # time, not on the first event that happens to reach it.
        for selection_name, selection in detection.items():
            if selection_name == "condition":
                continue
            try:
                _validate_selection_keys(selection)
            except MatchError as exc:
                raise RuleError(f"selection '{selection_name}': {exc}", path=context) from exc

        name = str(data.get("name") or "").strip()
        if not name:
            name = slugify(path.stem if path else str(data["title"]))

        rule = cls(
            name=name,
            title=str(data["title"]).strip(),
            detection=dict(detection),
            condition_text=str(condition_text).strip(),
            condition=condition,
            id=str(data.get("id") or ""),
            status=_parse_status(data.get("status"), context),
            severity=Severity.parse(
                data.get("severity") or data.get("level"), default=Severity.MEDIUM
            ),
            description=str(data.get("description") or "").strip(),
            author=str(data.get("author") or "").strip(),
            date=_parse_date(data.get("date"), context, "date"),
            modified=_parse_date(data.get("modified"), context, "modified"),
            references=_as_tuple(data.get("references")),
            attack=_parse_attack(data.get("attack"), context),
            platforms=_as_tuple(data.get("platforms")),
            logsource={str(k): str(v) for k, v in (data.get("logsource") or {}).items()},
            telemetry=_as_tuple(data.get("telemetry")),
            fields=_as_tuple(data.get("fields")),
            falsepositives=_as_tuple(data.get("falsepositives")),
            validation=ValidationSpec.from_dict(data.get("validation"), context=context),
            tuning=TuningSpec.from_dict(data.get("tuning")),
            tags=_as_tuple(data.get("tags")),
            path=path,
            raw=dict(data),
            unknown_keys=tuple(sorted(set(map(str, data)) - _KNOWN_KEYS)),
        )
        return rule


def _validate_selection_keys(selection: Any) -> None:
    if isinstance(selection, dict):
        for key in selection:
            parse_field_spec(str(key))
    elif isinstance(selection, list):
        for item in selection:
            if isinstance(item, dict):
                _validate_selection_keys(item)


def _parse_status(value: Any, context: str) -> RuleStatus:
    if value is None:
        return RuleStatus.EXPERIMENTAL
    try:
        return RuleStatus(str(value).strip().lower())
    except ValueError as exc:
        allowed = ", ".join(s.value for s in RuleStatus)
        raise RuleError(f"invalid status {value!r} (allowed: {allowed})", path=context) from exc


def _parse_date(value: Any, context: str, key: str) -> str:
    if value in (None, ""):
        return ""
    text = value.isoformat() if isinstance(value, date) else str(value).strip()
    if not _DATE_RE.match(text):
        raise RuleError(f"{key} must be ISO-8601 (YYYY-MM-DD), got {value!r}", path=context)
    return text


def _parse_attack(value: Any, context: str) -> tuple[AttackRef, ...]:
    """Accept either the structured form or a flat list of technique ids."""
    if not value:
        return ()

    refs: list[AttackRef] = []

    if isinstance(value, Mapping):
        tactics = _as_tuple(value.get("tactics"))
        techniques = value.get("techniques") or []
        if isinstance(techniques, str):
            techniques = [techniques]
        for item in techniques:
            if isinstance(item, Mapping):
                refs.append(
                    _attack_ref(
                        item.get("id") or item.get("technique"),
                        item.get("tactic") or (tactics[0] if tactics else None),
                        context,
                        name=item.get("name"),
                    )
                )
            else:
                refs.append(_attack_ref(item, tactics[0] if tactics else None, context))
        # A tactic with no technique is still coverage information.
        if not techniques:
            refs.extend(AttackRef(technique="", tactic=t) for t in tactics)
    elif isinstance(value, (list, tuple)):
        for item in value:
            if isinstance(item, Mapping):
                refs.append(
                    _attack_ref(
                        item.get("id") or item.get("technique"),
                        item.get("tactic"),
                        context,
                        name=item.get("name"),
                    )
                )
            else:
                refs.append(_attack_ref(item, None, context))
    else:
        raise RuleError("'attack' must be a mapping or a list", path=context)

    return tuple(r for r in refs if r.technique or r.tactic)


def _attack_ref(technique: Any, tactic: Any, context: str, *, name: Any = None) -> AttackRef:
    text = str(technique or "").strip().upper()
    if text and not _TECHNIQUE_RE.match(text):
        raise RuleError(
            f"invalid ATT&CK technique id {technique!r} (expected T1234 or T1234.001)",
            path=context,
        )
    tactic_text = str(tactic).strip().lower().replace(" ", "-") if tactic else None
    return AttackRef(
        technique=text,
        tactic=tactic_text,
        subtechnique_of=text.split(".", 1)[0] if "." in text else None,
        name=str(name) if name else None,
    )


def _as_tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple, set)):
        return tuple(str(v) for v in value)
    return (str(value),)
