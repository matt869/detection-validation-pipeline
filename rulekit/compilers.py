"""Backend query compilers.

One rule, four dialects. Each compiler walks the condition AST produced by
:mod:`rulekit.condition` and renders it in a target query language, consulting
:mod:`rulekit.matcher` for the meaning of every field modifier.

Every compiler emits two queries per rule:

``detection``  the full rule logic - "did this fire?"
``telemetry``  the log-source scope only - "did the data even arrive?"

The pair is what the classifier turns into a three-state outcome. A compiler
that cannot express a rule raises :class:`~harness.core.errors.CompileError`
rather than emitting a query that quietly means something else - a rule that
silently loses its ``not filter`` clause is worse than a rule that fails to
deploy.

The ``fixture`` dialect compiles to a Python predicate instead of a string,
which is what makes the whole pipeline runnable offline in CI.
"""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from harness.core.errors import CompileError
from harness.core.models import Event
from rulekit.condition import And, Node, Not, Or, Ref
from rulekit.matcher import (
    FieldSpec,
    MatchError,
    build_selection_predicate,
    expand_values,
    parse_field_spec,
)
from rulekit.rule import Rule
from rulekit.telemetry import TelemetryCatalog

__all__ = [
    "CompiledQuery",
    "ElasticCompiler",
    "FixtureCompiler",
    "KqlCompiler",
    "QueryCompiler",
    "SplunkCompiler",
    "compile_rule",
    "get_compiler",
    "register_compiler",
]


@dataclass(slots=True)
class CompiledQuery:
    """A query ready to hand to a backend.

    ``text`` is always a human-readable rendering (it goes into reports and the
    dashboard so an analyst can paste it into the SIEM). ``payload`` is what the
    backend actually executes - identical to ``text`` for string dialects, and a
    callable for the offline fixture dialect.
    """

    dialect: str
    kind: str  # "detection" | "telemetry"
    text: str
    payload: Any = None
    rule_name: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.payload is None:
            self.payload = self.text

    def __str__(self) -> str:
        return self.text


class QueryCompiler(ABC):
    """Base class: AST walking is shared, rendering is per-dialect."""

    dialect: str = "abstract"

    def __init__(
        self,
        catalog: TelemetryCatalog | None = None,
        *,
        scope_filter: str = "",
    ) -> None:
        self.catalog = catalog or TelemetryCatalog.empty()
        #: Extra clause AND-ed into every query, e.g. restricting to lab hosts.
        self.scope_filter = scope_filter.strip()

    # -- public API --------------------------------------------------------

    def compile(self, rule: Rule) -> CompiledQuery:
        """Render the full detection logic."""
        try:
            body = self._render(rule, rule.condition)
        except MatchError as exc:
            raise CompileError(str(exc), rule_id=rule.name) from exc
        return CompiledQuery(
            dialect=self.dialect,
            kind="detection",
            text=self._assemble(rule, body),
            rule_name=rule.name,
            metadata={"selections": rule.selections},
        )

    def compile_telemetry(self, rule: Rule) -> CompiledQuery | None:
        """Render the log-source presence probe, or ``None`` if unavailable.

        ``None`` means this rule cannot distinguish a detection gap from a
        visibility gap. The classifier degrades confidence rather than guessing.
        """
        scope = self._scope_clause(rule)
        if not scope:
            return None
        return CompiledQuery(
            dialect=self.dialect,
            kind="telemetry",
            text=self._assemble_telemetry(rule, scope),
            rule_name=rule.name,
            metadata={"telemetry": list(rule.telemetry)},
        )

    # -- AST walking -------------------------------------------------------

    def _render(self, rule: Rule, node: Node) -> str:
        if isinstance(node, Ref):
            selection = rule.detection.get(node.name)
            if selection is None:
                raise CompileError(
                    f"condition references undefined selection '{node.name}'",
                    rule_id=rule.name,
                )
            return self._render_selection(selection)
        if isinstance(node, Not):
            return self._not(self._render(rule, node.node))
        if isinstance(node, And):
            return self._and([self._render(rule, child) for child in node.nodes])
        if isinstance(node, Or):
            return self._or([self._render(rule, child) for child in node.nodes])
        raise CompileError(f"unsupported condition node {type(node).__name__}", rule_id=rule.name)

    def _render_selection(self, selection: Any) -> str:
        if isinstance(selection, Mapping):
            parts = [
                self._render_field(parse_field_spec(str(key)), value)
                for key, value in selection.items()
            ]
            return self._and(parts)
        if isinstance(selection, list):
            if all(isinstance(item, Mapping) for item in selection):
                return self._or([self._render_selection(item) for item in selection])
            return self._or([self._keyword(str(item)) for item in selection])
        return self._keyword(str(selection))

    def _render_field(self, spec: FieldSpec, value: Any) -> str:
        candidates = expand_values(spec, value)
        if candidates == [None]:
            return self._null(spec)
        if "exists" in spec.modifiers:
            return self._exists(spec, bool(value))
        clauses = [self._comparison(spec, candidate) for candidate in candidates]
        return self._and(clauses) if spec.require_all else self._or(clauses)

    # -- dialect hooks -----------------------------------------------------

    @abstractmethod
    def _comparison(self, spec: FieldSpec, value: Any) -> str: ...

    @abstractmethod
    def _keyword(self, value: str) -> str: ...

    @abstractmethod
    def _null(self, spec: FieldSpec) -> str: ...

    @abstractmethod
    def _exists(self, spec: FieldSpec, present: bool) -> str: ...

    def _and(self, parts: list[str]) -> str:
        parts = [p for p in parts if p]
        if not parts:
            raise CompileError("empty conjunction")
        return parts[0] if len(parts) == 1 else "(" + " AND ".join(parts) + ")"

    def _or(self, parts: list[str]) -> str:
        parts = [p for p in parts if p]
        if not parts:
            raise CompileError("empty disjunction")
        return parts[0] if len(parts) == 1 else "(" + " OR ".join(parts) + ")"

    def _not(self, part: str) -> str:
        return f"NOT ({part})"

    def _scope_clause(self, rule: Rule) -> str:
        """Combine every declared telemetry source into one selector."""
        scopes: list[str] = []
        for source in self.catalog.resolve(rule.telemetry):
            scope = source.scope(self.dialect)
            if scope:
                scopes.append(str(scope))
        if not scopes:
            return ""
        return scopes[0] if len(scopes) == 1 else self._or([f"({s})" for s in scopes])

    def _assemble(self, rule: Rule, body: str) -> str:
        parts = [p for p in (self._scope_clause(rule), self.scope_filter, body) if p]
        return " AND ".join(parts)

    def _assemble_telemetry(self, rule: Rule, scope: str) -> str:
        parts = [p for p in (scope, self.scope_filter) if p]
        return " AND ".join(parts)


# ------------------------------------------------------------------- fixture


class FixtureCompiler(QueryCompiler):
    """Compiles to a Python predicate for offline evaluation.

    This dialect is the reference implementation of rule semantics. The test
    suite asserts that a rule's offline verdict matches hand-checked fixture
    events, so a semantic regression in :mod:`rulekit.matcher` is caught before
    it can silently change what a live SIEM query means.
    """

    dialect = "fixture"

    def compile(self, rule: Rule) -> CompiledQuery:
        predicate = self._build(rule, rule.condition)
        scope = self._fixture_scope(rule)
        if scope is not None:
            body = predicate

            def scoped(event: Event) -> bool:
                return scope(event) and body(event)

            predicate = scoped
        return CompiledQuery(
            dialect=self.dialect,
            kind="detection",
            text=f"{rule.name}: {rule.condition_text}",
            payload=predicate,
            rule_name=rule.name,
            metadata={"selections": rule.selections},
        )

    def compile_telemetry(self, rule: Rule) -> CompiledQuery | None:
        scope = self._fixture_scope(rule)
        if scope is None:
            return None
        return CompiledQuery(
            dialect=self.dialect,
            kind="telemetry",
            text=f"{rule.name}: telemetry({', '.join(rule.telemetry)})",
            payload=scope,
            rule_name=rule.name,
            metadata={"telemetry": list(rule.telemetry)},
        )

    def _build(self, rule: Rule, node: Node) -> Callable[[Event], bool]:
        if isinstance(node, Ref):
            selection = rule.detection.get(node.name)
            if selection is None:
                raise CompileError(
                    f"condition references undefined selection '{node.name}'", rule_id=rule.name
                )
            try:
                return build_selection_predicate(selection)
            except MatchError as exc:
                raise CompileError(f"selection '{node.name}': {exc}", rule_id=rule.name) from exc
        if isinstance(node, Not):
            inner = self._build(rule, node.node)
            return lambda event: not inner(event)
        if isinstance(node, And):
            children = [self._build(rule, child) for child in node.nodes]
            return lambda event: all(child(event) for child in children)
        if isinstance(node, Or):
            children = [self._build(rule, child) for child in node.nodes]
            return lambda event: any(child(event) for child in children)
        raise CompileError(f"unsupported node {type(node).__name__}", rule_id=rule.name)

    def _fixture_scope(self, rule: Rule) -> Callable[[Event], bool] | None:
        """Fixture scopes are mappings, evaluated with normal selection semantics."""
        predicates: list[Callable[[Event], bool]] = []
        for source in self.catalog.resolve(rule.telemetry):
            scope = source.scope("fixture")
            if isinstance(scope, Mapping) and scope:
                predicates.append(build_selection_predicate(dict(scope)))
        if not predicates:
            return None
        if len(predicates) == 1:
            return predicates[0]
        return lambda event: any(p(event) for p in predicates)

    # Unused for this dialect - the predicate path bypasses string rendering.
    def _comparison(self, spec: FieldSpec, value: Any) -> str:  # pragma: no cover
        raise CompileError("fixture dialect does not render text clauses")

    def _keyword(self, value: str) -> str:  # pragma: no cover
        raise CompileError("fixture dialect does not render text clauses")

    def _null(self, spec: FieldSpec) -> str:  # pragma: no cover
        raise CompileError("fixture dialect does not render text clauses")

    def _exists(self, spec: FieldSpec, present: bool) -> str:  # pragma: no cover
        raise CompileError("fixture dialect does not render text clauses")


# -------------------------------------------------------------------- splunk


class SplunkCompiler(QueryCompiler):
    """Splunk SPL.

    Emits a bare search when the rule only needs equality and wildcards, and
    falls back to ``| where`` with eval functions when it needs regex, CIDR, or
    numeric ranges - search syntax cannot express those. The two modes are never
    mixed, because a partially-applied filter is a silently wrong rule.
    """

    dialect = "splunk"
    _EVAL_ONLY = frozenset({"re", "cidr", "gt", "gte", "lt", "lte"})

    def compile(self, rule: Rule) -> CompiledQuery:
        self._eval_mode = self._needs_eval(rule)
        query = super().compile(rule)
        query.metadata["mode"] = "where" if self._eval_mode else "search"
        return query

    def _needs_eval(self, rule: Rule) -> bool:
        for name, selection in rule.detection.items():
            if name == "condition":
                continue
            for key in _iter_keys(selection):
                if parse_field_spec(key).comparison in self._EVAL_ONLY:
                    return True
        return False

    def _assemble(self, rule: Rule, body: str) -> str:
        scope = " ".join(p for p in (self._scope_clause(rule), self.scope_filter) if p)
        if getattr(self, "_eval_mode", False):
            return f"{scope} | where {body}".strip()
        return f"{scope} {body}".strip()

    def _assemble_telemetry(self, rule: Rule, scope: str) -> str:
        parts = " ".join(p for p in (scope, self.scope_filter) if p)
        return f"{parts} | stats count".strip()

    def _comparison(self, spec: FieldSpec, value: Any) -> str:
        field_name = _splunk_field(spec.field)
        comparison = spec.comparison

        if getattr(self, "_eval_mode", False):
            return self._eval_comparison(field_name, spec, value)

        text = str(value)
        if comparison == "contains":
            text = f"*{text}*"
        elif comparison == "startswith":
            text = f"{text}*"
        elif comparison == "endswith":
            text = f"*{text}"
        return f'{field_name}="{_splunk_escape(text)}"'

    def _eval_comparison(self, field_name: str, spec: FieldSpec, value: Any) -> str:
        comparison = spec.comparison
        text = _splunk_escape(str(value))
        if comparison == "re":
            return f'match({field_name}, "{text}")'
        if comparison == "cidr":
            return f'cidrmatch("{text}", {field_name})'
        if comparison in ("gt", "gte", "lt", "lte"):
            operator = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<="}[comparison]
            return f"{field_name} {operator} {float(value)}"
        pattern = {
            "contains": f"%{value}%",
            "startswith": f"{value}%",
            "endswith": f"%{value}",
        }.get(comparison, str(value))
        # Sigma wildcards translate to SQL-style wildcards inside like().
        pattern = pattern.replace("*", "%").replace("?", "_")
        return f'like({field_name}, "{_splunk_escape(pattern)}")'

    def _keyword(self, value: str) -> str:
        return f'"{_splunk_escape(value)}"'

    def _null(self, spec: FieldSpec) -> str:
        return self._exists(spec, False)

    def _exists(self, spec: FieldSpec, present: bool) -> str:
        field_name = _splunk_field(spec.field)
        if getattr(self, "_eval_mode", False):
            return f"{'isnotnull' if present else 'isnull'}({field_name})"
        # Search mode has no eval functions; `Field=*` is the idiomatic
        # presence test and is index-time efficient.
        return f"{field_name}=*" if present else f"NOT {field_name}=*"


def _splunk_field(name: str) -> str:
    return name if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", name) else f"'{name}'"


def _splunk_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


# ------------------------------------------------------------------- elastic


class ElasticCompiler(QueryCompiler):
    """Elasticsearch / OpenSearch ``query_string`` syntax (Lucene).

    ``query_string`` is chosen over the JSON bool DSL because the output is
    something an analyst can paste straight into Kibana's search bar - which
    matters when a report says "this rule did not fire" and someone needs to go
    look at why.
    """

    dialect = "elastic"
    _LUCENE_SPECIAL = r'+-=&|><!(){}[]^"~:\\/'

    def _assemble_telemetry(self, rule: Rule, scope: str) -> str:
        parts = [p for p in (scope, self.scope_filter) if p]
        return " AND ".join(parts)

    def _comparison(self, spec: FieldSpec, value: Any) -> str:
        field_name = _lucene_field(spec.field)
        comparison = spec.comparison

        if comparison == "re":
            return f"{field_name}:/{value!s}/"
        if comparison == "cidr":
            return f'{field_name}:"{value}"'
        if comparison in ("gt", "gte", "lt", "lte"):
            number = float(value)
            bounds = {
                "gt": f"{{{number} TO *]",
                "gte": f"[{number} TO *]",
                "lt": f"[* TO {number}}}",
                "lte": f"[* TO {number}]",
            }[comparison]
            return f"{field_name}:{bounds}"

        text = str(value)
        if comparison == "contains":
            text = f"*{text}*"
        elif comparison == "startswith":
            text = f"{text}*"
        elif comparison == "endswith":
            text = f"*{text}"

        if _contains_wildcard(text):
            # Wildcards are inert inside a quoted phrase, so escape term-wise.
            return f"{field_name}:{_lucene_escape(text, keep_wildcards=True)}"
        return f'{field_name}:"{_lucene_escape(text)}"'

    def _keyword(self, value: str) -> str:
        return f'"{_lucene_escape(value)}"'

    def _null(self, spec: FieldSpec) -> str:
        return f"NOT _exists_:{_lucene_field(spec.field)}"

    def _exists(self, spec: FieldSpec, present: bool) -> str:
        clause = f"_exists_:{_lucene_field(spec.field)}"
        return clause if present else f"NOT {clause}"


def _lucene_field(name: str) -> str:
    return name.replace(" ", r"\ ")


def _lucene_escape(value: str, *, keep_wildcards: bool = False) -> str:
    out: list[str] = []
    for char in value:
        if char in "*?" and keep_wildcards:
            out.append(char)
        elif char in ElasticCompiler._LUCENE_SPECIAL or char in "*?":
            out.append("\\" + char)
        elif char == " " and keep_wildcards:
            out.append("\\ ")
        else:
            out.append(char)
    return "".join(out)


def _contains_wildcard(value: str) -> bool:
    return "*" in value or "?" in value


# ----------------------------------------------------------------------- kql


class KqlCompiler(QueryCompiler):
    """Kusto (Microsoft Sentinel / Defender Advanced Hunting).

    KQL is table-scoped, so the telemetry source must supply a ``table``. A rule
    whose sources disagree on table is rejected: a union across tables would
    change field semantics silently.
    """

    dialect = "sentinel"

    def _assemble(self, rule: Rule, body: str) -> str:
        table = self._table(rule)
        clauses = [c for c in (self._scope_clause(rule), self.scope_filter, body) if c]
        where = " and ".join(clauses)
        return f"{table}\n| where {where}"

    def _assemble_telemetry(self, rule: Rule, scope: str) -> str:
        table = self._table(rule)
        clauses = [c for c in (scope, self.scope_filter) if c]
        where = " and ".join(clauses)
        return f"{table}\n| where {where}\n| summarize Events = count()"

    def _table(self, rule: Rule) -> str:
        tables = {
            table
            for table in (
                source.table(self.dialect) for source in self.catalog.resolve(rule.telemetry)
            )
            if table
        }
        if len(tables) > 1:
            raise CompileError(
                f"telemetry sources span multiple KQL tables ({', '.join(sorted(tables))}); "
                "split the rule so each version targets one table",
                rule_id=rule.name,
            )
        if not tables:
            raise CompileError(
                "no KQL table defined for this rule's telemetry sources",
                rule_id=rule.name,
                hint="Add backends.sentinel.table to the source in mapping/telemetry_sources.yml.",
            )
        return tables.pop()

    def _and(self, parts: list[str]) -> str:
        parts = [p for p in parts if p]
        if not parts:
            raise CompileError("empty conjunction")
        return parts[0] if len(parts) == 1 else "(" + " and ".join(parts) + ")"

    def _or(self, parts: list[str]) -> str:
        parts = [p for p in parts if p]
        if not parts:
            raise CompileError("empty disjunction")
        return parts[0] if len(parts) == 1 else "(" + " or ".join(parts) + ")"

    def _not(self, part: str) -> str:
        return f"not({part})"

    def _comparison(self, spec: FieldSpec, value: Any) -> str:
        field_name = spec.field
        comparison = spec.comparison
        cased = spec.cased

        if comparison == "re":
            return f'{field_name} matches regex "{_kql_escape(str(value))}"'
        if comparison == "cidr":
            return f'ipv4_is_match({field_name}, "{_kql_escape(str(value))}")'
        if comparison in ("gt", "gte", "lt", "lte"):
            operator = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<="}[comparison]
            return f"toreal({field_name}) {operator} {float(value)}"

        # Kusto is strongly typed: comparing an int column with a string literal
        # is an error, not a coercion. Numeric literals stay numeric.
        if (
            comparison == "equals"
            and isinstance(value, (int, float))
            and not isinstance(value, bool)
        ):
            return f"{field_name} == {value}"

        text = str(value)
        if _contains_wildcard(text):
            return f'{field_name} matches regex "{_kql_escape(_wildcard_regex(text, comparison))}"'

        literal = f'"{_kql_escape(text)}"'
        operators = {
            "contains": "contains_cs" if cased else "contains",
            "startswith": "startswith_cs" if cased else "startswith",
            "endswith": "endswith_cs" if cased else "endswith",
            "equals": "==" if cased else "=~",
        }
        operator = operators[comparison]
        return f"{field_name} {operator} {literal}"

    def _keyword(self, value: str) -> str:
        return f'* contains "{_kql_escape(value)}"'

    def _null(self, spec: FieldSpec) -> str:
        return f"isempty({spec.field})"

    def _exists(self, spec: FieldSpec, present: bool) -> str:
        return f"isnotempty({spec.field})" if present else f"isempty({spec.field})"


def _kql_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _wildcard_regex(value: str, comparison: str) -> str:
    body = "".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in value)
    if comparison == "startswith":
        return f"^{body}"
    if comparison == "endswith":
        return f"{body}$"
    if comparison == "contains":
        return body
    return f"^{body}$"


# ------------------------------------------------------------------ registry

_REGISTRY: dict[str, type[QueryCompiler]] = {
    "fixture": FixtureCompiler,
    "splunk": SplunkCompiler,
    "elastic": ElasticCompiler,
    "opensearch": ElasticCompiler,
    "sentinel": KqlCompiler,
    "defender": KqlCompiler,
}


def register_compiler(dialect: str, compiler: type[QueryCompiler]) -> None:
    """Register a third-party dialect. Overwrites an existing registration."""
    _REGISTRY[dialect] = compiler


def get_compiler(
    dialect: str,
    catalog: TelemetryCatalog | None = None,
    *,
    scope_filter: str = "",
) -> QueryCompiler:
    compiler_class = _REGISTRY.get(dialect)
    if compiler_class is None:
        known = ", ".join(sorted(_REGISTRY))
        raise CompileError(f"no compiler for dialect '{dialect}' (known: {known})")
    # Aliases (opensearch -> elastic, defender -> sentinel) keep the canonical
    # dialect name so telemetry-source lookups resolve against one key.
    return compiler_class(catalog, scope_filter=scope_filter)


def compile_rule(
    rule: Rule,
    dialect: str,
    catalog: TelemetryCatalog | None = None,
    *,
    scope_filter: str = "",
) -> tuple[CompiledQuery, CompiledQuery | None]:
    """Compile both the detection query and the telemetry probe for one rule."""
    compiler = get_compiler(dialect, catalog, scope_filter=scope_filter)
    return compiler.compile(rule), compiler.compile_telemetry(rule)


def _iter_keys(selection: Any) -> Iterable[str]:
    if isinstance(selection, Mapping):
        yield from (str(k) for k in selection)
    elif isinstance(selection, list):
        for item in selection:
            if isinstance(item, Mapping):
                yield from (str(k) for k in item)


def describe(query: CompiledQuery) -> str:
    """Pretty-print a compiled query for the CLI."""
    if callable(query.payload):
        return f"[{query.dialect}/{query.kind}] {query.text}"
    body = query.text if isinstance(query.payload, str) else json.dumps(query.payload, indent=2)
    return f"[{query.dialect}/{query.kind}]\n{body}"
