"""Rule tooling: parse, validate, lint, compile, and score detection content.

``rulekit`` is deliberately independent of the harness runtime. It knows how to
turn a YAML rule into a backend query and how to judge rule quality; it knows
nothing about running emulations or talking to a SIEM. That separation is what
lets ``dvp rules lint`` run in a pre-commit hook with no infrastructure.
"""

from __future__ import annotations

from rulekit.compilers import (
    CompiledQuery,
    ElasticCompiler,
    FixtureCompiler,
    KqlCompiler,
    SplunkCompiler,
    get_compiler,
    register_compiler,
)
from rulekit.condition import ConditionError, parse_condition
from rulekit.library import RuleLibrary, load_library
from rulekit.rule import Rule, ValidationSpec

__all__ = [
    "CompiledQuery",
    "ConditionError",
    "ElasticCompiler",
    "FixtureCompiler",
    "KqlCompiler",
    "Rule",
    "RuleLibrary",
    "SplunkCompiler",
    "ValidationSpec",
    "get_compiler",
    "load_library",
    "parse_condition",
    "register_compiler",
]
