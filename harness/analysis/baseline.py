"""Baseline profiles: what "quiet" looks like for a class of host.

Before emulation starts, the harness runs every rule's detection logic over a
recent window in which nothing was emulated. Anything that matches is noise the
rule would produce in production.

A profile lets a team record *accepted* noise. A rule known to fire twice a day
on a legitimate updater is not a new finding every single run; it becomes one
again only when the volume changes. Accepting noise is a decision, so it is
recorded in a file with an owner and a review date rather than being silently
tolerated.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from harness.core.models import CaseResult, RunRecord
from harness.core.yamlio import iter_yaml_files, load_yaml

__all__ = ["BaselineProfile", "NoiseFinding", "ProfileLibrary", "assess_noise"]


@dataclass(frozen=True, slots=True)
class AcceptedNoise:
    """A rule whose baseline hits are known and tolerated."""

    rule: str
    max_hits: int
    reason: str = ""
    owner: str = ""
    review_by: str = ""


@dataclass(slots=True)
class BaselineProfile:
    """Expected quiet-period behaviour for a class of host."""

    name: str
    description: str = ""
    #: Glob patterns matching hosts this profile describes.
    hosts: tuple[str, ...] = ()
    #: Length of the quiet window to sample, in seconds.
    window_seconds: float = 3600.0
    accepted: dict[str, AcceptedNoise] = field(default_factory=dict)
    owner: str = ""
    path: Path | None = None

    def matches_host(self, host: str) -> bool:
        lowered = host.lower()
        return any(fnmatch.fnmatch(lowered, pattern.lower()) for pattern in self.hosts)

    def allowance(self, rule_name: str) -> int:
        entry = self.accepted.get(rule_name)
        return entry.max_hits if entry else 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "hosts": list(self.hosts),
            "window_seconds": self.window_seconds,
            "owner": self.owner,
            "accepted": {
                k: {
                    "max_hits": v.max_hits,
                    "reason": v.reason,
                    "owner": v.owner,
                    "review_by": v.review_by,
                }
                for k, v in self.accepted.items()
            },
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any], *, path: Path | None = None) -> BaselineProfile:
        accepted: dict[str, AcceptedNoise] = {}
        entries = data.get("accepted_noise") or []
        if isinstance(entries, Mapping):
            entries = [{"rule": k, **(v or {})} for k, v in entries.items()]
        for entry in entries:
            if not isinstance(entry, Mapping) or not entry.get("rule"):
                continue
            rule = str(entry["rule"])
            accepted[rule] = AcceptedNoise(
                rule=rule,
                max_hits=int(entry.get("max_hits", 0)),
                reason=str(entry.get("reason") or ""),
                owner=str(entry.get("owner") or ""),
                review_by=str(entry.get("review_by") or ""),
            )

        return cls(
            name=str(data.get("name") or (path.stem if path else "unnamed")),
            description=str(data.get("description") or ""),
            hosts=tuple(str(h) for h in (data.get("hosts") or [])),
            window_seconds=float(data.get("window_seconds", 3600)),
            accepted=accepted,
            owner=str(data.get("owner") or ""),
            path=path,
        )


@dataclass(slots=True)
class ProfileLibrary:
    profiles: dict[str, BaselineProfile] = field(default_factory=dict)

    def get(self, name: str) -> BaselineProfile | None:
        return self.profiles.get(name)

    def for_host(self, host: str) -> BaselineProfile | None:
        return next((p for p in self.profiles.values() if p.matches_host(host)), None)

    def allowance(self, profile_name: str, rule_name: str) -> int:
        profile = self.profiles.get(profile_name)
        return profile.allowance(rule_name) if profile else 0

    def __iter__(self):
        return iter(self.profiles.values())

    def __len__(self) -> int:
        return len(self.profiles)

    @classmethod
    def load(cls, directory: Path | str) -> ProfileLibrary:
        library = cls()
        for path in iter_yaml_files(directory):
            document = load_yaml(path, default={}) or {}
            if not isinstance(document, Mapping):
                continue
            profile = BaselineProfile.from_dict(document, path=path)
            library.profiles[profile.name] = profile
        return library

    @classmethod
    def empty(cls) -> ProfileLibrary:
        return cls()


@dataclass(frozen=True, slots=True)
class NoiseFinding:
    """A rule producing more baseline noise than has been accepted."""

    rule: str
    hits: int
    allowance: int
    severity: str
    profile: str = ""
    outcome: str = ""

    @property
    def excess(self) -> int:
        return max(0, self.hits - self.allowance)

    def describe(self) -> str:
        if self.allowance:
            return (
                f"{self.rule}: {self.hits} baseline hit(s), "
                f"{self.allowance} accepted - {self.excess} over"
            )
        return f"{self.rule}: {self.hits} baseline hit(s), none accepted"

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "hits": self.hits,
            "allowance": self.allowance,
            "excess": self.excess,
            "severity": self.severity,
            "profile": self.profile,
            "outcome": self.outcome,
        }


def assess_noise(
    run: RunRecord,
    library: ProfileLibrary,
    *,
    profile_by_rule: Mapping[str, str] | None = None,
) -> list[NoiseFinding]:
    """Find rules whose baseline hits exceed their accepted allowance.

    ``profile_by_rule`` comes from each rule's ``tuning.baseline_profile``. A
    rule with no profile gets an allowance of zero: unaccepted noise is a
    finding, and the way to stop it being one is to write down why it is fine.
    """
    profile_by_rule = profile_by_rule or {}
    findings: list[NoiseFinding] = []
    seen: set[str] = set()

    for result in run.results:
        rule = result.case.rule_name
        if rule in seen or result.baseline_hits <= 0:
            continue
        seen.add(rule)

        profile_name = profile_by_rule.get(rule, "")
        allowance = library.allowance(profile_name, rule) if profile_name else 0
        if result.baseline_hits > allowance:
            findings.append(
                NoiseFinding(
                    rule=rule,
                    hits=result.baseline_hits,
                    allowance=allowance,
                    severity=result.case.severity.value,
                    profile=profile_name,
                    outcome=result.outcome.value,
                )
            )

    findings.sort(key=lambda f: (-f.excess, f.rule))
    return findings


def noisy_rules(results: Iterable[CaseResult]) -> set[str]:
    return {r.case.rule_name for r in results if r.baseline_hits > 0}
