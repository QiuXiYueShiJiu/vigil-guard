"""CLI command modules.

Each module exposes ``register(subparsers)`` and attaches a ``func`` to its
parser. Nothing is imported eagerly beyond this package, so `vigil --help`
stays fast and a broken optional subsystem cannot stop the CLI from loading.
"""
