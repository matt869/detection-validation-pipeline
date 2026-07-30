"""Exception hierarchy and process exit codes.

Every failure the pipeline can produce maps to a stable exit code so CI jobs can
distinguish "the pipeline broke" from "detections regressed".
"""

from __future__ import annotations


class ExitCode:
    """Stable process exit codes. Referenced by CI pipelines and the Makefile."""

    OK = 0
    #: A validation gate failed (regressions, coverage below target, lint errors).
    GATE_FAILED = 1
    #: The user asked for something impossible (bad flags, unknown profile).
    USAGE = 2
    #: Configuration could not be loaded or is internally inconsistent.
    CONFIG = 3
    #: A rule failed to parse, validate, or compile.
    RULE = 4
    #: A telemetry backend was unreachable or returned an error.
    BACKEND = 5
    #: Emulation failed to run.
    EMULATION = 6
    #: The safety policy refused to authorise an action.
    SAFETY = 7
    #: Storage/migration failure.
    STORAGE = 8
    #: Interrupted by the operator.
    INTERRUPTED = 130


class DvpError(Exception):
    """Base class for all pipeline errors.

    Carries an exit code and an optional remediation hint that the CLI renders
    beneath the error message.
    """

    exit_code: int = ExitCode.GATE_FAILED

    def __init__(self, message: str, *, hint: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.message


class ConfigError(DvpError):
    exit_code = ExitCode.CONFIG


class RuleError(DvpError):
    """A detection rule is malformed, unresolvable, or fails to compile."""

    exit_code = ExitCode.RULE

    def __init__(
        self,
        message: str,
        *,
        path: str | None = None,
        rule_id: str | None = None,
        hint: str | None = None,
    ) -> None:
        location = path or rule_id
        super().__init__(f"{location}: {message}" if location else message, hint=hint)
        self.path = path
        self.rule_id = rule_id


class CompileError(RuleError):
    """A rule is valid but cannot be expressed in the target query dialect."""


class BackendError(DvpError):
    exit_code = ExitCode.BACKEND


class EmulationError(DvpError):
    exit_code = ExitCode.EMULATION


class SafetyError(DvpError):
    """The safety policy blocked an action. Never retried automatically."""

    exit_code = ExitCode.SAFETY


class StorageError(DvpError):
    exit_code = ExitCode.STORAGE


class UsageError(DvpError):
    exit_code = ExitCode.USAGE


class GateFailure(DvpError):
    """Raised when a run completes but violates a configured quality gate."""

    exit_code = ExitCode.GATE_FAILED
