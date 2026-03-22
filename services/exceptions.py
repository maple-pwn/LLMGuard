from __future__ import annotations


class SampleImportError(ValueError):
    """Raised when a sample import payload is malformed."""


class EvaluationError(ValueError):
    """Raised when an evaluation request is invalid or too expensive."""


class UnsafeModelArtifactError(RuntimeError):
    """Raised when a model artifact fails trust validation."""


class PolicyBindingResolutionError(ValueError):
    """Raised when a gateway request cannot be mapped to an enabled policy binding."""
