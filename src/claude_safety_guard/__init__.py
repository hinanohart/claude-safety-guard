"""claude-safety-guard — a Claude Code PreToolUse guard that blocks destructive
shell commands before they run.

Public API is deliberately minimal. The package is usable as:

  * A Claude Code hook (``claude-safety-guard hook`` reads JSON from stdin and
    writes a decision to stdout).
  * A standalone CLI (``claude-safety-guard check "rm -rf /"``).
  * A library (``from claude_safety_guard import evaluate, Decision``).
"""

from claude_safety_guard._version import __version__
from claude_safety_guard.guard import Decision, Finding, Severity, evaluate
from claude_safety_guard.patterns import Pattern, default_patterns

__all__ = [
    "Decision",
    "Finding",
    "Pattern",
    "Severity",
    "__version__",
    "default_patterns",
    "evaluate",
]
