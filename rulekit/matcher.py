"""Field matching semantics shared by every backend compiler.

A Sigma-style selection key carries the field name plus zero or more pipe
modifiers::

    CommandLine|contains|all:
      - " -enc "
      - "FromBase64String"

This module owns exactly one thing: what that *means*. The offline evaluator
uses it to run rules against fixture events; the SIEM compilers consult the
parsed :class:`FieldSpec` to emit an equivalent native clause. Keeping the
semantics in one place is what makes an offline pass a credible predictor of
the live query's behaviour.

Default comparison is case-insensitive, because the platforms these rules
target (Windows event logs, Splunk, KQL) are themselves case-insensitive for
string equality. ``|cased`` opts back into exact comparison.
"""

from __future__ import annotations

import base64
import ipaddress
import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from harness.core.models import Event

__all__ = [
    "FieldSpec",
    "MatchError",
    "SelectionPredicate",
    "build_selection_predicate",
    "expand_values",
    "parse_field_spec",
]


class MatchError(ValueError):
    """A selection uses a modifier combination that has no defined meaning."""


#: Modifiers that choose *how* to compare. At most one may be present.
_COMPARISONS = {
    "contains",
    "startswith",
    "endswith",
    "re",
    "cidr",
    "gt",
    "gte",
    "lt",
    "lte",
}
#: Modifiers that transform the rule-side value before comparison.
_TRANSFORMS = {"base64", "base64offset", "windash"}
#: Modifiers that change quantification or case handling.
_FLAGS = {"all", "cased", "exists"}

_KNOWN_MODIFIERS = _COMPARISONS | _TRANSFORMS | _FLAGS

#: Command-line dash variants Windows accepts interchangeably. Attackers use the
#: unicode forms specifically to slip past rules that only match ASCII hyphen.
#: The non-ASCII spellings are the entire point: attackers use them precisely
#: because rules that only match the ASCII hyphen miss them.
_DASHES = ("-", "/", "–", "—", "―")  # noqa: RUF001 - ambiguous dashes are intentional


@dataclass(frozen=True, slots=True)
class FieldSpec:
    """A parsed ``Field|modifier|modifier`` selection key."""

    field: str
    modifiers: tuple[str, ...] = ()

    @property
    def comparison(self) -> str:
        """One of ``equals``, ``contains``, ``startswith``, ``endswith``,
        ``re``, ``cidr``, ``gt``, ``gte``, ``lt``, ``lte``."""
        found = [m for m in self.modifiers if m in _COMPARISONS]
        return found[0] if found else "equals"

    @property
    def transforms(self) -> tuple[str, ...]:
        return tuple(m for m in self.modifiers if m in _TRANSFORMS)

    @property
    def require_all(self) -> bool:
        """``|all`` turns a value list from OR into AND."""
        return "all" in self.modifiers

    @property
    def cased(self) -> bool:
        return "cased" in self.modifiers

    @property
    def is_numeric_comparison(self) -> bool:
        return self.comparison in ("gt", "gte", "lt", "lte")

    def __str__(self) -> str:
        return "|".join((self.field, *self.modifiers))


def parse_field_spec(key: str) -> FieldSpec:
    """Split ``"Image|endswith"`` into a :class:`FieldSpec`, validating modifiers."""
    parts = [p.strip() for p in str(key).split("|")]
    field = parts[0]
    modifiers = tuple(p.lower() for p in parts[1:] if p)

    if not field:
        raise MatchError(f"selection key {key!r} has an empty field name")

    unknown = [m for m in modifiers if m not in _KNOWN_MODIFIERS]
    if unknown:
        raise MatchError(
            f"{key!r}: unknown modifier(s) {', '.join(unknown)}. "
            f"Supported: {', '.join(sorted(_KNOWN_MODIFIERS))}"
        )

    comparisons = [m for m in modifiers if m in _COMPARISONS]
    if len(comparisons) > 1:
        raise MatchError(
            f"{key!r}: modifiers {', '.join(comparisons)} conflict - "
            "a field can only be compared one way"
        )
    if "cased" in modifiers and "re" in modifiers:
        raise MatchError(f"{key!r}: use an inline '(?-i)' flag instead of |cased with |re")
    if "cidr" in modifiers and len(comparisons) > 1:
        raise MatchError(f"{key!r}: |cidr cannot be combined with another comparison")

    return FieldSpec(field=field, modifiers=modifiers)


def expand_values(spec: FieldSpec, value: Any) -> list[Any]:
    """Normalise the right-hand side of a selection into a list of candidates.

    Applies value transforms (``base64offset``, ``windash``) which each expand
    one authored value into several literals to search for.
    """
    values: list[Any] = list(value) if isinstance(value, (list, tuple)) else [value]

    for transform in spec.transforms:
        expanded: list[Any] = []
        for item in values:
            if item is None:
                expanded.append(item)
            elif transform == "windash":
                expanded.extend(_windash_variants(str(item)))
            elif transform == "base64":
                expanded.append(base64.b64encode(str(item).encode("utf-8")).decode("ascii"))
            elif transform == "base64offset":
                expanded.extend(_base64_offset_variants(str(item)))
        values = expanded

    # Preserve author order while dropping duplicates introduced by transforms.
    seen: set[str] = set()
    unique: list[Any] = []
    for item in values:
        marker = f"{type(item).__name__}:{item}"
        if marker not in seen:
            seen.add(marker)
            unique.append(item)
    return unique


def _windash_variants(value: str) -> list[str]:
    """``-enc`` -> ``-enc``, ``/enc``, and the unicode dash spellings."""
    if not value or value[0] not in _DASHES:
        # Also cover a dash appearing after a leading space, e.g. " -enc".
        stripped = value.lstrip()
        if not stripped or stripped[0] not in _DASHES:
            return [value]
        prefix = value[: len(value) - len(stripped)]
        return [prefix + dash + stripped[1:] for dash in _DASHES]
    return [dash + value[1:] for dash in _DASHES]


def _base64_offset_variants(value: str) -> list[str]:
    """The three base64 encodings of a string at each byte alignment.

    A command line embedded in a larger base64 blob starts at an arbitrary
    offset, so a naive ``base64(value)`` search misses two thirds of cases.
    """
    start_offsets = (0, 2, 3)
    end_offsets = (None, -3, -2)
    raw = value.encode("utf-8")
    variants = []
    for i in range(3):
        encoded = base64.b64encode(b" " * i + raw).decode("ascii")
        variants.append(encoded[start_offsets[i] : end_offsets[(len(raw) + i) % 3]])
    return variants


# ------------------------------------------------------------------ evaluation

SelectionPredicate = Callable[[Event], bool]


def build_selection_predicate(selection: Any) -> SelectionPredicate:
    """Compile one named selection into a predicate over an :class:`Event`.

    * A mapping: every key must match (AND).
    * A list of mappings: any element may match (OR).
    * A list of scalars: keyword search across the whole flattened event.
    """
    if isinstance(selection, dict):
        field_predicates = [_build_field_predicate(k, v) for k, v in selection.items()]
        if not field_predicates:
            # An empty selection matching everything is almost always a typo,
            # and it silently disables the rule's filter logic.
            raise MatchError("selection is empty - it would match every event")
        return lambda event: all(p(event) for p in field_predicates)

    if isinstance(selection, list):
        if not selection:
            raise MatchError("selection list is empty - it would never match")
        if all(isinstance(item, dict) for item in selection):
            alternatives = [build_selection_predicate(item) for item in selection]
            return lambda event: any(p(event) for p in alternatives)
        keywords = [str(item) for item in selection]
        return lambda event: any(_keyword_match(event, kw) for kw in keywords)

    keyword = str(selection)
    return lambda event: _keyword_match(event, keyword)


def _keyword_match(event: Event, keyword: str) -> bool:
    """Unstructured search: does the keyword appear anywhere in the event?"""
    matcher = _string_matcher(keyword, "contains", cased=False)
    return any(matcher(value) for value in _flatten(event.raw))


def _flatten(document: Any, *, depth: int = 0) -> Iterable[str]:
    if depth > 6:
        return
    if isinstance(document, dict):
        for value in document.values():
            yield from _flatten(value, depth=depth + 1)
    elif isinstance(document, (list, tuple)):
        for item in document:
            yield from _flatten(item, depth=depth + 1)
    elif document is not None:
        yield str(document)


def _build_field_predicate(key: str, value: Any) -> SelectionPredicate:
    spec = parse_field_spec(key)

    if "exists" in spec.modifiers:
        want = bool(value)
        return lambda event: event.has(spec.field) is want

    candidates = expand_values(spec, value)

    # `Field: null` means the field must be absent or explicitly null.
    if candidates == [None]:
        return lambda event: _resolve(event, spec.field) in (None, [], "")

    matchers = [_value_matcher(spec, candidate) for candidate in candidates]
    combine = all if spec.require_all else any

    def predicate(event: Event) -> bool:
        observed = _resolve(event, spec.field)
        if observed is None:
            return False
        # Multi-valued fields (Elastic arrays) match if any element matches.
        values = observed if isinstance(observed, list) else [observed]
        return combine(any(match(item) for item in values) for match in matchers)

    return predicate


def _resolve(event: Event, field: str) -> Any:
    return event.get(field)


def _value_matcher(spec: FieldSpec, candidate: Any) -> Callable[[Any], bool]:
    comparison = spec.comparison

    if comparison == "cidr":
        return _cidr_matcher(str(candidate))
    if comparison in ("gt", "gte", "lt", "lte"):
        return _numeric_matcher(comparison, candidate)
    if comparison == "re":
        flags = 0 if spec.cased else re.IGNORECASE
        try:
            pattern = re.compile(str(candidate), flags)
        except re.error as exc:
            raise MatchError(f"{spec}: invalid regular expression {candidate!r}: {exc}") from exc
        return lambda observed: pattern.search(_stringify(observed)) is not None

    if candidate is None:
        return lambda observed: observed is None

    # Numeric literals compare numerically so `EventID: 10` matches "10".
    if (
        comparison == "equals"
        and isinstance(candidate, (int, float))
        and not isinstance(candidate, bool)
    ):
        return _numeric_matcher("eq", candidate)

    return _string_matcher(str(candidate), comparison, cased=spec.cased)


def _stringify(observed: Any) -> str:
    if isinstance(observed, bool):
        return "true" if observed else "false"
    return "" if observed is None else str(observed)


def _string_matcher(candidate: str, comparison: str, *, cased: bool) -> Callable[[Any], bool]:
    """Build a string comparator, upgrading to regex when wildcards are present."""
    if _has_wildcard(candidate):
        pattern = re.compile(
            _wildcard_to_regex(candidate, comparison), 0 if cased else re.IGNORECASE
        )
        return lambda observed: pattern.search(_stringify(observed)) is not None

    needle = _unescape(candidate)
    if not cased:
        needle = needle.casefold()

    def compare(observed: Any) -> bool:
        text = _stringify(observed)
        if not cased:
            text = text.casefold()
        if comparison == "contains":
            return needle in text
        if comparison == "startswith":
            return text.startswith(needle)
        if comparison == "endswith":
            return text.endswith(needle)
        return text == needle

    return compare


def _has_wildcard(value: str) -> bool:
    """True if the value contains an *unescaped* ``*`` or ``?``."""
    index = 0
    while index < len(value):
        char = value[index]
        if char == "\\":
            index += 2
            continue
        if char in "*?":
            return True
        index += 1
    return False


def _wildcard_to_regex(value: str, comparison: str) -> str:
    """Translate Sigma wildcards to a regex anchored per the comparison mode."""
    out: list[str] = []
    index = 0
    while index < len(value):
        char = value[index]
        if char == "\\" and index + 1 < len(value):
            nxt = value[index + 1]
            if nxt in "*?\\":
                out.append(re.escape(nxt))
                index += 2
                continue
            out.append(re.escape(char))
            index += 1
            continue
        if char == "*":
            out.append(".*")
        elif char == "?":
            out.append(".")
        else:
            out.append(re.escape(char))
        index += 1

    body = "".join(out)
    if comparison == "contains":
        return body
    if comparison == "startswith":
        return f"^{body}"
    if comparison == "endswith":
        return f"{body}$"
    return f"^{body}$"


def _unescape(value: str) -> str:
    """Resolve ``\\*``, ``\\?``, ``\\\\`` in a value with no active wildcards."""
    out: list[str] = []
    index = 0
    while index < len(value):
        char = value[index]
        if char == "\\" and index + 1 < len(value) and value[index + 1] in "*?\\":
            out.append(value[index + 1])
            index += 2
            continue
        out.append(char)
        index += 1
    return "".join(out)


def _numeric_matcher(comparison: str, candidate: Any) -> Callable[[Any], bool]:
    threshold = _coerce_number(candidate)
    if threshold is None:
        raise MatchError(f"{comparison} comparison needs a number, got {candidate!r}")

    operators: dict[str, Callable[[float, float], bool]] = {
        "eq": lambda a, b: a == b,
        "gt": lambda a, b: a > b,
        "gte": lambda a, b: a >= b,
        "lt": lambda a, b: a < b,
        "lte": lambda a, b: a <= b,
    }
    operator = operators[comparison]

    def compare(observed: Any) -> bool:
        number = _coerce_number(observed)
        if number is None:
            # Fall back to string equality so `Status: "0x5"` still works.
            return (
                comparison == "eq" and _stringify(observed).casefold() == str(candidate).casefold()
            )
        return operator(number, threshold)

    return compare


def _coerce_number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = _stringify(value).strip()
    if not text:
        return None
    try:
        if text.lower().startswith(("0x", "-0x")):
            return float(int(text, 16))
        return float(text)
    except ValueError:
        return None


def _cidr_matcher(network: str) -> Callable[[Any], bool]:
    try:
        subnet = ipaddress.ip_network(network, strict=False)
    except ValueError as exc:
        raise MatchError(f"invalid CIDR {network!r}: {exc}") from exc

    def compare(observed: Any) -> bool:
        try:
            return ipaddress.ip_address(_stringify(observed).strip()) in subnet
        except ValueError:
            return False

    return compare


def field_names(selection: Any) -> list[str]:
    """Every field name a selection reads. Used by the linter and by telemetry
    requirement checks."""
    names: list[str] = []
    if isinstance(selection, dict):
        names.extend(parse_field_spec(key).field for key in selection)
    elif isinstance(selection, list):
        for item in selection:
            if isinstance(item, dict):
                names.extend(field_names(item))
    return names


def all_field_names(detection: dict[str, Any]) -> list[str]:
    """Ordered, de-duplicated field names across every selection in a rule."""
    seen: dict[str, None] = {}
    for name, selection in detection.items():
        if name == "condition":
            continue
        for field in field_names(selection):
            seen.setdefault(field, None)
    return list(seen)


def selection_names(detection: dict[str, Any]) -> Sequence[str]:
    return [key for key in detection if key != "condition"]
