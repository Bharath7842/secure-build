"""Errors the model gateway distinguishes (DAST-02-010). Plain exceptions so adapters,
the gateway and tests can share them without importing any provider SDK."""

from __future__ import annotations


class ModelError(Exception):
    """A model call failed. The gateway turns every subclass into the task's fallback."""


class ModelTimeout(ModelError):
    pass


class ModelUnavailable(ModelError):
    """Connection refused, provider down, or throttled."""


class ModelAuthError(ModelError):
    pass


class ModelConfigurationError(ModelError):
    """The provider cannot be used as configured. `setting` names what to set."""

    def __init__(self, message: str, setting: str = ""):
        self.setting = setting
        super().__init__(message)


class UnknownTaskError(ValueError):
    """A gateway call named a task that has no routing."""
