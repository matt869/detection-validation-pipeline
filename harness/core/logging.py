"""Console and structured logging.

Two output modes share one call site:

* ``text``  - aligned, optionally coloured, for humans at a terminal.
* ``json``  - one JSON object per line, for shipping runs into a log platform.

Colour is disabled automatically when stdout is not a TTY, when ``NO_COLOR`` is
set, or when running under CI, so report output stays diffable.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from typing import Any, TextIO

from harness.core.models import Outcome
from harness.core.timeutil import to_iso, utcnow

LOGGER_NAME = "dvp"

_LEVEL_COLOURS = {
    "DEBUG": "\033[38;5;244m",
    "INFO": "\033[38;5;39m",
    "WARNING": "\033[38;5;214m",
    "ERROR": "\033[38;5;203m",
    "CRITICAL": "\033[1;38;5;203m",
}
_OUTCOME_COLOURS = {
    Outcome.DETECTED: "\033[38;5;41m",
    Outcome.VISIBLE: "\033[38;5;214m",
    Outcome.BLIND: "\033[38;5;203m",
    Outcome.ERROR: "\033[1;38;5;203m",
    Outcome.SKIPPED: "\033[38;5;244m",
}
_RESET = "\033[0m"
_DIM = "\033[38;5;244m"
_BOLD = "\033[1m"


def colour_enabled(stream: TextIO | None = None) -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("DVP_FORCE_COLOR"):
        return True
    if os.environ.get("CI"):
        return False
    stream = stream or sys.stdout
    return bool(getattr(stream, "isatty", lambda: False)())


def paint(text: str, colour: str, *, stream: TextIO | None = None) -> str:
    """Wrap ``text`` in an ANSI colour when the stream supports it."""
    return f"{colour}{text}{_RESET}" if colour_enabled(stream) else text


def outcome_colour(outcome: Outcome) -> str:
    return _OUTCOME_COLOURS.get(outcome, "")


def dim(text: str, *, stream: TextIO | None = None) -> str:
    return paint(text, _DIM, stream=stream)


def bold(text: str, *, stream: TextIO | None = None) -> str:
    return paint(text, _BOLD, stream=stream)


class TextFormatter(logging.Formatter):
    """``14:22:31  INFO   collector  queried splunk (412 events)``"""

    def format(self, record: logging.LogRecord) -> str:
        stamp = self.formatTime(record, "%H:%M:%S")
        level = record.levelname
        if colour_enabled(sys.stderr):
            level = f"{_LEVEL_COLOURS.get(level, '')}{level:<7}{_RESET}"
        else:
            level = f"{level:<7}"
        component = getattr(record, "component", record.name.rsplit(".", 1)[-1])
        message = record.getMessage()
        if record.exc_info:
            message = f"{message}\n{self.formatException(record.exc_info)}"
        return f"{dim(stamp, stream=sys.stderr)}  {level} {component:<12} {message}"


class JsonFormatter(logging.Formatter):
    """One JSON object per line, with any ``extra`` fields merged in."""

    _RESERVED = frozenset(logging.LogRecord("", 0, "", 0, "", (), None).__dict__) | {
        "message",
        "asctime",
        "taskName",
    }

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": to_iso(utcnow()),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in self._RESERVED and not key.startswith("_"):
                payload[key] = _jsonable(value)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def _jsonable(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool, type(None))):
        return value
    if hasattr(value, "value") and isinstance(value.value, str):
        return value.value  # Enum
    return str(value)


def configure(
    *,
    level: str | int = "INFO",
    fmt: str = "text",
    stream: TextIO | None = None,
) -> logging.Logger:
    """Configure the ``dvp`` logger. Idempotent - safe to call from tests."""
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(level if isinstance(level, int) else level.upper())
    logger.propagate = False

    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    handler = logging.StreamHandler(stream or sys.stderr)
    handler.setFormatter(JsonFormatter() if fmt == "json" else TextFormatter())
    logger.addHandler(handler)
    return logger


def get_logger(component: str | None = None) -> logging.LoggerAdapter:
    """Return a logger tagged with a pipeline component name."""
    base = logging.getLogger(LOGGER_NAME if not component else f"{LOGGER_NAME}.{component}")
    if not logging.getLogger(LOGGER_NAME).handlers:
        configure()
    return logging.LoggerAdapter(base, {"component": component or "dvp"})
