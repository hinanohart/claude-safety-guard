"""Single source of truth for the package version.

Kept as a trivial module so tooling that needs the version without importing
the full package (e.g. release automation) can read it without side effects.
"""

__version__ = "0.1.1"
