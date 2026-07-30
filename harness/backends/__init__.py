"""Backend registry and factory.

Live backends are imported lazily so that a machine without ``httpx`` can still
lint rules, run the fixture backend, and render reports.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from pathlib import Path

from harness.backends.base import Backend, HealthStatus, QueryResult
from harness.backends.fixture import BASELINE_TEST_ID, FixtureBackend
from harness.core.config import BackendConfig, Settings
from harness.core.errors import ConfigError

__all__ = [
    "BASELINE_TEST_ID",
    "Backend",
    "FixtureBackend",
    "HealthStatus",
    "QueryResult",
    "available_kinds",
    "build_backend",
    "check_all",
    "register_backend",
]


def _load_splunk() -> type[Backend]:
    from harness.backends.splunk import SplunkBackend

    return SplunkBackend


def _load_elastic() -> type[Backend]:
    from harness.backends.elastic import ElasticBackend

    return ElasticBackend


def _load_sentinel() -> type[Backend]:
    from harness.backends.sentinel import SentinelBackend

    return SentinelBackend


_REGISTRY: dict[str, Callable[[], type[Backend]]] = {
    "fixture": lambda: FixtureBackend,
    "splunk": _load_splunk,
    "elastic": _load_elastic,
    "opensearch": _load_elastic,
    "sentinel": _load_sentinel,
    "defender": _load_sentinel,
}


def register_backend(kind: str, loader: Callable[[], type[Backend]]) -> None:
    """Register a third-party backend kind."""
    _REGISTRY[kind] = loader


def available_kinds() -> list[str]:
    return sorted(_REGISTRY)


def build_backend(
    settings: Settings,
    name: str | None = None,
    *,
    scenarios: Iterable[str] | None = None,
) -> Backend:
    """Instantiate the backend named ``name`` (or the configured default)."""
    config = settings.backend(name)
    if not config.enabled:
        raise ConfigError(
            f"backend '{config.name}' is disabled in config/backends.yml",
            hint="Set enabled: true, or choose another with --backend.",
        )

    loader = _REGISTRY.get(config.kind)
    if loader is None:
        raise ConfigError(
            f"backend '{config.name}' has unknown kind '{config.kind}'",
            hint=f"Known kinds: {', '.join(available_kinds())}",
        )

    backend_class = loader()
    if backend_class is FixtureBackend:
        return FixtureBackend(config, root=settings.root, scenarios=scenarios)
    return backend_class(config)


def check_all(settings: Settings, *, names: Iterable[str] | None = None) -> list[HealthStatus]:
    """Health-check every configured backend. Used by ``dvp doctor``."""
    targets = list(names) if names else sorted(settings.backends)
    results: list[HealthStatus] = []
    for name in targets:
        config: BackendConfig = settings.backends[name]
        if not config.enabled:
            results.append(
                HealthStatus(name=name, ok=True, message="disabled", details={"skipped": True})
            )
            continue
        try:
            with build_backend(settings, name) as backend:
                results.append(backend.health())
        except Exception as exc:
            results.append(
                HealthStatus(name=name, ok=False, message=f"{type(exc).__name__}: {exc}")
            )
    return results


def fixture_root(settings: Settings) -> Path:
    config = settings.backends.get("fixture")
    base = Path(config.option("path", "fixtures/runs")) if config else Path("fixtures/runs")
    return base if base.is_absolute() else settings.root / base
