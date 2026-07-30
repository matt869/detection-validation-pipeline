"""Parser for Sigma-style detection ``condition`` expressions.

Grammar (case-insensitive keywords)::

    expression := or_expr
    or_expr    := and_expr ( "or" and_expr )*
    and_expr   := not_expr ( "and" not_expr )*
    not_expr   := "not" not_expr | atom
    atom       := "(" expression ")" | quantifier | IDENT
    quantifier := ( "all" | "1" ) "of" ( IDENT_GLOB | "them" )

The result is a small immutable AST that every backend compiler walks. Parsing
is separated from compiling so a malformed condition is caught by ``dvp rules
lint`` - in a pre-commit hook, with a caret pointing at the offending token -
rather than at 3am when the query is finally sent to the SIEM.

Quantifiers are expanded against the concrete selection names at parse time, so
compilers only ever see ``And``/``Or``/``Not``/``Ref``.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

__all__ = [
    "And",
    "ConditionError",
    "Node",
    "Not",
    "Or",
    "Ref",
    "parse_condition",
    "referenced_selections",
]


class ConditionError(ValueError):
    """A condition string could not be parsed or resolved.

    Carries the original expression and an offset so the CLI can render a caret.
    """

    def __init__(self, message: str, *, expression: str = "", position: int | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.expression = expression
        self.position = position

    def annotated(self) -> str:
        """The message plus a caret line pointing at the failure position."""
        if not self.expression or self.position is None:
            return self.message
        caret = " " * max(0, self.position) + "^"
        return f"{self.message}\n  {self.expression}\n  {caret}"


# --------------------------------------------------------------------------- AST


@dataclass(frozen=True, slots=True)
class Ref:
    """Reference to a named selection in the ``detection`` block."""

    name: str

    def __str__(self) -> str:
        return self.name


@dataclass(frozen=True, slots=True)
class Not:
    node: Node

    def __str__(self) -> str:
        return f"not {_wrap(self.node)}"


@dataclass(frozen=True, slots=True)
class And:
    nodes: tuple[Node, ...]

    def __str__(self) -> str:
        return " and ".join(_wrap(n) for n in self.nodes)


@dataclass(frozen=True, slots=True)
class Or:
    nodes: tuple[Node, ...]

    def __str__(self) -> str:
        return " or ".join(_wrap(n) for n in self.nodes)


Node = Ref | Not | And | Or


def _wrap(node: Node) -> str:
    return f"({node})" if isinstance(node, (And, Or)) else str(node)


def referenced_selections(node: Node) -> set[str]:
    """Every selection name the expression depends on. Used by the linter to
    flag selections that are defined but never referenced."""
    if isinstance(node, Ref):
        return {node.name}
    if isinstance(node, Not):
        return referenced_selections(node.node)
    return set().union(*(referenced_selections(child) for child in node.nodes))


# ----------------------------------------------------------------------- lexer

_TOKEN_RE = re.compile(
    r"""
    (?P<ws>\s+)
  | (?P<lparen>\()
  | (?P<rparen>\))
  | (?P<pipe>\|)
  | (?P<ident>[A-Za-z0-9_][A-Za-z0-9_*?.\-]*)
    """,
    re.VERBOSE,
)
_KEYWORDS = {"and", "or", "not", "of", "them", "all"}


@dataclass(frozen=True, slots=True)
class _Token:
    kind: str  # ident | keyword | lparen | rparen | number | end
    value: str
    position: int


def _tokenize(expression: str) -> list[_Token]:
    tokens: list[_Token] = []
    index = 0
    length = len(expression)
    while index < length:
        match = _TOKEN_RE.match(expression, index)
        if match is None:
            raise ConditionError(
                f"unexpected character {expression[index]!r}",
                expression=expression,
                position=index,
            )
        index = match.end()
        if match.lastgroup == "ws":
            continue
        if match.lastgroup == "pipe":
            # Sigma aggregation (`| count() > 5`) is intentionally unsupported:
            # correlation belongs in the SIEM, not in a portable rule body.
            raise ConditionError(
                "aggregation expressions ('|') are not supported; express "
                "correlation in the platform's own rule engine",
                expression=expression,
                position=match.start(),
            )
        if match.lastgroup == "lparen":
            tokens.append(_Token("lparen", "(", match.start()))
        elif match.lastgroup == "rparen":
            tokens.append(_Token("rparen", ")", match.start()))
        else:
            word = match.group("ident")
            lowered = word.lower()
            if lowered in _KEYWORDS:
                tokens.append(_Token("keyword", lowered, match.start()))
            elif word.isdigit():
                tokens.append(_Token("number", word, match.start()))
            else:
                tokens.append(_Token("ident", word, match.start()))
    tokens.append(_Token("end", "", length))
    return tokens


# ---------------------------------------------------------------------- parser


class _Parser:
    def __init__(self, expression: str, selections: Sequence[str]) -> None:
        self.expression = expression
        self.tokens = _tokenize(expression)
        self.index = 0
        self.selections = list(selections)

    # -- token helpers

    @property
    def current(self) -> _Token:
        return self.tokens[self.index]

    def advance(self) -> _Token:
        token = self.tokens[self.index]
        self.index += 1
        return token

    def accept_keyword(self, word: str) -> bool:
        if self.current.kind == "keyword" and self.current.value == word:
            self.advance()
            return True
        return False

    def fail(self, message: str, token: _Token | None = None) -> ConditionError:
        token = token or self.current
        return ConditionError(message, expression=self.expression, position=token.position)

    # -- grammar

    def parse(self) -> Node:
        if self.current.kind == "end":
            raise self.fail("condition is empty")
        node = self.parse_or()
        if self.current.kind != "end":
            raise self.fail(f"unexpected trailing token {self.current.value!r}")
        return node

    def parse_or(self) -> Node:
        nodes = [self.parse_and()]
        while self.accept_keyword("or"):
            nodes.append(self.parse_and())
        return nodes[0] if len(nodes) == 1 else Or(tuple(nodes))

    def parse_and(self) -> Node:
        nodes = [self.parse_not()]
        while self.accept_keyword("and"):
            nodes.append(self.parse_not())
        return nodes[0] if len(nodes) == 1 else And(tuple(nodes))

    def parse_not(self) -> Node:
        if self.accept_keyword("not"):
            return Not(self.parse_not())
        return self.parse_atom()

    def parse_atom(self) -> Node:
        token = self.current
        if token.kind == "lparen":
            self.advance()
            node = self.parse_or()
            if self.current.kind != "rparen":
                raise self.fail("expected ')'")
            self.advance()
            return node
        if token.kind == "keyword" and token.value == "all":
            self.advance()
            return self.parse_quantifier(token, quantity="all")
        if token.kind == "number":
            self.advance()
            return self.parse_quantifier(token, quantity=token.value)
        if token.kind == "ident":
            self.advance()
            return self.resolve_reference(token)
        if token.kind == "keyword":
            raise self.fail(f"unexpected keyword {token.value!r}", token)
        raise self.fail("expected a selection name, 'not', or '('", token)

    def parse_quantifier(self, start: _Token, *, quantity: str) -> Node:
        if not self.accept_keyword("of"):
            raise self.fail(f"expected 'of' after {quantity!r}")

        target = self.advance()
        if target.kind == "keyword" and target.value == "them":
            names = list(self.selections)
            pattern = "them"
        elif target.kind in ("ident", "number"):
            pattern = target.value
            names = _expand_glob(pattern, self.selections)
        else:
            raise self.fail("expected a selection pattern or 'them' after 'of'", target)

        if not names:
            raise self.fail(
                f"'{quantity} of {pattern}' matches no selection "
                f"(defined: {', '.join(self.selections) or 'none'})",
                start,
            )

        refs = tuple(Ref(name) for name in names)
        if quantity == "all":
            return And(refs) if len(refs) > 1 else refs[0]
        if quantity == "1":
            return Or(refs) if len(refs) > 1 else refs[0]
        raise self.fail(
            f"'{quantity} of ...' is not supported - use '1 of' or 'all of'. "
            "Counting quantifiers cannot be expressed in most query languages",
            start,
        )

    def resolve_reference(self, token: _Token) -> Node:
        name = token.value
        if name in self.selections:
            return Ref(name)
        if any(ch in name for ch in "*?"):
            # A bare glob (`filter*` without a quantifier) means "all of".
            names = _expand_glob(name, self.selections)
            if not names:
                raise self.fail(f"pattern {name!r} matches no selection", token)
            return And(tuple(Ref(n) for n in names)) if len(names) > 1 else Ref(names[0])
        known = ", ".join(self.selections) or "none"
        raise self.fail(f"unknown selection {name!r} (defined: {known})", token)


def _expand_glob(pattern: str, names: Iterable[str]) -> list[str]:
    """Expand ``filter*`` against the defined selection names, order preserved."""
    if not any(ch in pattern for ch in "*?"):
        return [n for n in names if n == pattern]
    return [n for n in names if fnmatch.fnmatchcase(n, pattern)]


def parse_condition(expression: str, selections: Sequence[str]) -> Node:
    """Parse ``expression`` and resolve every reference against ``selections``.

    Raises :class:`ConditionError` with a position for anything malformed or
    unresolvable, including references to selections that do not exist.
    """
    if not isinstance(expression, str):
        raise ConditionError(f"condition must be a string, got {type(expression).__name__}")
    return _Parser(expression.strip(), selections).parse()
