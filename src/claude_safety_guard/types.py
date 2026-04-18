"""Shared types used by both the pattern catalog and the evaluation engine.

Lives in its own module so :mod:`claude_safety_guard.patterns` can import
:class:`Severity` (its rules declare severity levels) while
:mod:`claude_safety_guard.guard` imports :func:`default_patterns` from the
catalog — without either module requiring a deferred import of the other.
"""

from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    """Severity of a matched rule.

    Using ``str`` as a mixin keeps the values JSON-serialisable without a
    custom encoder, which matters because this package's primary surface is
    a hook that speaks JSON over stdio.
    """

    BLOCK = "block"
    WARN = "warn"
