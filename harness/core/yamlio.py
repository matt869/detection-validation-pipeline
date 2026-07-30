"""YAML loading with the safety properties detection content needs.

Two behaviours differ from a bare ``yaml.safe_load``:

* **Duplicate keys are an error.** In a Sigma-style rule, a second ``selection:``
  key silently replaces the first, deleting detection logic with no warning.
  That has shipped broken rules to production before; here it fails loudly.
* **Errors carry the file and line.** A rule library is hundreds of files;
  "mapping values are not allowed here" without a path is not actionable.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import yaml

from harness.core.errors import ConfigError


class StrictLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate mapping keys."""


def _no_duplicates(loader: StrictLoader, node: yaml.MappingNode, deep: bool = False) -> dict:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"duplicate key {key!r} - the later value silently overrides the earlier one",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _no_duplicates)


# Timestamps in rule metadata should stay strings; implicit date coercion turns
# `date: 2026-01-30` into a datetime.date and breaks string comparisons downstream.
def _keep_as_string(loader: yaml.BaseLoader, node: yaml.ScalarNode) -> str:
    return str(loader.construct_scalar(node))


StrictLoader.add_constructor("tag:yaml.org,2002:timestamp", _keep_as_string)


def load_yaml(path: Path | str, *, default: Any = None) -> Any:
    """Load a single YAML document, or ``default`` if the file is missing/empty."""
    path = Path(path)
    if not path.exists():
        if default is not None:
            return default
        raise ConfigError(
            f"file not found: {path}",
            hint="Run `dvp doctor` to check the project layout.",
        )
    text = path.read_text(encoding="utf-8-sig")
    if not text.strip():
        return default if default is not None else {}
    try:
        return yaml.load(text, Loader=StrictLoader)
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path}: invalid YAML: {_describe(exc)}") from exc


def load_yaml_documents(path: Path | str) -> list[Any]:
    """Load a multi-document YAML file (``---`` separated)."""
    path = Path(path)
    text = path.read_text(encoding="utf-8-sig")
    try:
        return [doc for doc in yaml.load_all(text, Loader=StrictLoader) if doc is not None]
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path}: invalid YAML: {_describe(exc)}") from exc


def dump_yaml(data: Any) -> str:
    """Serialise with stable key order and block style, for generated content."""
    return yaml.safe_dump(data, sort_keys=False, default_flow_style=False, allow_unicode=True)


def iter_yaml_files(directory: Path | str, *, recursive: bool = True) -> Iterator[Path]:
    """Yield ``.yml``/``.yaml`` files in deterministic order, skipping hidden and
    underscore-prefixed paths (``_shared/`` holds includes, not rules)."""
    directory = Path(directory)
    if not directory.exists():
        return
    pattern = "**/*" if recursive else "*"
    for path in sorted(directory.glob(pattern)):
        if path.suffix.lower() not in (".yml", ".yaml") or not path.is_file():
            continue
        parts = path.relative_to(directory).parts
        if any(part.startswith((".", "_")) for part in parts):
            continue
        yield path


def _describe(exc: yaml.YAMLError) -> str:
    mark = getattr(exc, "problem_mark", None)
    problem = getattr(exc, "problem", None) or str(exc)
    if mark is not None:
        return f"line {mark.line + 1}, column {mark.column + 1}: {problem}"
    return problem
