class ASMError(Exception):
    """Base class for application errors that map to a specific HTTP response."""


class InvalidTargetError(ASMError):
    """Raised when an asset value fails type-specific validation."""


class AuthorizationNotConfirmedError(ASMError):
    """Raised when a scan is requested against an asset that has not had
    authorization_confirmed set. This is the guardrail: no scanner module
    — passive or active — runs against a target until this passes.
    """
