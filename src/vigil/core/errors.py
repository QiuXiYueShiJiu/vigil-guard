"""Exception hierarchy.

Every error a user can plausibly hit carries a ``hint``: the CLI prints it
verbatim. Writing the fix next to the failure is worth more than a stack
trace, and it keeps the command modules free of try/except noise.
"""
from __future__ import annotations


class VigilError(Exception):
    """Base class. ``hint`` is shown to the user after the message."""

    def __init__(self, message: str, hint: str = ""):
        super().__init__(message)
        self.message = message
        self.hint = hint

    def render(self) -> str:
        if self.hint:
            return "%s\n  → %s" % (self.message, self.hint)
        return self.message


class ConfigError(VigilError):
    """Configuration missing, malformed, or inconsistent."""


class NotInstalledError(VigilError):
    """The service is not installed yet."""

    def __init__(self, what: str = "vigil"):
        super().__init__(
            "%s is not installed on this host" % what,
            "run `vigil install` first",
        )


class UnsupportedError(VigilError):
    """The host lacks something the requested feature requires."""


class ProviderError(VigilError):
    """A mail provider could not deliver."""


class AuthError(ProviderError):
    """Credentials were rejected by the provider."""


class RateLimitError(ProviderError):
    """Provider quota exhausted; the caller should fall back or queue."""


class CommandError(VigilError):
    """A subprocess failed."""

    def __init__(self, argv, returncode: int, stderr: str = "", hint: str = ""):
        pretty = " ".join(str(a) for a in argv)
        msg = "command failed (exit %s): %s" % (returncode, pretty)
        if stderr.strip():
            msg += "\n  stderr: %s" % stderr.strip()[:500]
        super().__init__(msg, hint)
        self.argv = argv
        self.returncode = returncode
        self.stderr = stderr


class PermissionDenied(VigilError):
    """We are not root (or lack a capability) for something root-only."""

    def __init__(self, what: str = "this operation"):
        super().__init__(
            "root privileges are required for %s" % what,
            "re-run with sudo",
        )
