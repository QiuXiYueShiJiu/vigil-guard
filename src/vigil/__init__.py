"""Vigil -- a portable server security, integrity and alerting guard.

The package is intentionally import-light: every entry point below is a
cheap import so that ``vigil --help`` stays fast and so a broken optional
subsystem cannot stop the CLI from starting.
"""
from .version import NAME, SUMMARY, __version__

__all__ = ["NAME", "SUMMARY", "__version__", "main"]


def main(argv=None):
    """Console-script entry point."""
    from .cli import main as _main
    return _main(argv)
