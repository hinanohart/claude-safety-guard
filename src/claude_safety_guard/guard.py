"""Core evaluation engine.

Takes a shell command string, applies a catalog of :class:`Pattern` rules,
and returns a :class:`Decision`. Decoupled from both the Claude Code hook
protocol and the CLI so the same engine drives every surface.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

from claude_safety_guard.types import Severity

if TYPE_CHECKING:
    from collections.abc import Iterable

    from claude_safety_guard.patterns import Pattern


__all__ = [
    "Decision",
    "EvaluationOptions",
    "Finding",
    "Outcome",
    "Severity",
    "evaluate",
]


class Outcome(str, Enum):
    """Terminal result of an evaluation.

    ALLOW:
        No rule matched, or the command matched only allow-listed rules.
    WARN:
        At least one WARN rule matched; no BLOCK rule matched. Caller
        should surface the warning but proceed.
    BLOCK:
        At least one BLOCK rule matched. Caller must refuse execution.
    """

    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"


@dataclass(frozen=True, slots=True)
class Finding:
    """A single rule that matched a command."""

    pattern_id: str
    category: str
    severity: Severity
    reason: str
    matched_text: str

    def to_dict(self) -> dict[str, str]:
        return {
            "pattern_id": self.pattern_id,
            "category": self.category,
            "severity": self.severity.value,
            "reason": self.reason,
            "matched_text": self.matched_text,
        }


@dataclass(frozen=True, slots=True)
class Decision:
    """Evaluation result.

    Attributes
    ----------
    outcome:
        Aggregate verdict.
    findings:
        Ordered tuple of every rule that matched. Empty for ALLOW outcomes.
    command:
        The command that was evaluated, verbatim.
    """

    outcome: Outcome
    findings: tuple[Finding, ...]
    command: str

    @property
    def blocked(self) -> bool:
        return self.outcome is Outcome.BLOCK

    @property
    def has_warnings(self) -> bool:
        return any(f.severity is Severity.WARN for f in self.findings)

    def to_dict(self) -> dict[str, object]:
        return {
            "outcome": self.outcome.value,
            "command": self.command,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass(frozen=True, slots=True)
class EvaluationOptions:
    """User-tunable evaluation knobs.

    Attributes
    ----------
    allowlist:
        Set of pattern IDs that should be **silently ignored** even if they
        match. Use sparingly; every entry is a named exception.
    dry_run:
        When ``True``, BLOCK findings are downgraded to WARN in the final
        outcome. The findings themselves retain their original severity so
        callers can distinguish "dry-run suppressed" from genuine WARNs.
    """

    allowlist: frozenset[str] = field(default_factory=frozenset)
    dry_run: bool = False


def evaluate(
    command: str,
    patterns: Iterable[Pattern] | None = None,
    options: EvaluationOptions | None = None,
) -> Decision:
    """Evaluate ``command`` against ``patterns`` and return a :class:`Decision`.

    Parameters
    ----------
    command:
        The raw shell command to evaluate. Empty strings yield ALLOW.
    patterns:
        Iterable of :class:`Pattern` to check. If ``None``, loads the default
        catalog from :mod:`claude_safety_guard.patterns`.
    options:
        Optional :class:`EvaluationOptions`. If ``None``, defaults are used
        (no allowlist, no dry-run).
    """

    if patterns is None:
        from claude_safety_guard.patterns import default_patterns

        patterns = default_patterns()
    if options is None:
        options = EvaluationOptions()

    if not command or not command.strip():
        return Decision(outcome=Outcome.ALLOW, findings=(), command=command)

    # Normalise before matching: fold full-width / compatibility forms
    # (NFKC) and strip invisible format chars (category Cf: ZWJ, ZWSP,
    # RLO/LRO, BOM, ...). This closes the "ｒｍ －ｒｆ ／" and
    # "AKIA\u200DIOSFODNN7EXAMPLE" class of bypasses without making every
    # individual regex carry the Unicode weight.
    scan_target = _normalise_for_scan(command)

    findings: list[Finding] = []
    for pattern in patterns:
        if pattern.id in options.allowlist:
            continue
        match = pattern.regex.search(scan_target)
        if match is None:
            continue
        findings.append(
            Finding(
                pattern_id=pattern.id,
                category=pattern.category,
                severity=pattern.severity,
                reason=pattern.reason,
                matched_text=match.group(0),
            )
        )

    outcome = _aggregate(findings, dry_run=options.dry_run)
    return Decision(outcome=outcome, findings=tuple(findings), command=command)


def _normalise_for_scan(command: str) -> str:
    """Fold compatibility forms and drop invisible format chars.

    Implements two complementary defences against Unicode-based matcher
    evasion:

    * NFKC normalisation collapses full-width / small-form / Roman-numeral
      compatibility codepoints into their ASCII equivalents, so ``ｒｍ``
      becomes ``rm``.
    * Removing category ``Cf`` (format) characters strips zero-width
      joiners, zero-width spaces, RTL/LTR overrides, byte-order marks, and
      other invisibles that shells happily ignore but regexes do not.
    """

    normalised = unicodedata.normalize("NFKC", command)
    return "".join(ch for ch in normalised if unicodedata.category(ch) != "Cf")


def _aggregate(findings: list[Finding], *, dry_run: bool) -> Outcome:
    if not findings:
        return Outcome.ALLOW
    has_block = any(f.severity is Severity.BLOCK for f in findings)
    has_warn = any(f.severity is Severity.WARN for f in findings)
    if has_block and not dry_run:
        return Outcome.BLOCK
    if has_block and dry_run:
        return Outcome.WARN
    if has_warn:
        return Outcome.WARN
    return Outcome.ALLOW
