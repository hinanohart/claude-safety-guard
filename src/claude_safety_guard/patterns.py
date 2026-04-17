"""Catalog of dangerous shell-command patterns that :mod:`claude_safety_guard`
will block or warn about.

Each pattern has:

* a stable ``id`` that users can allowlist in their config,
* a ``category`` for grouping in reports,
* a ``severity`` — BLOCK or WARN,
* a compiled regular expression,
* a human-readable ``reason`` explaining why the pattern is dangerous.

The catalog is **additive** and versioned: new patterns are added in minor
releases, and existing pattern IDs never change their meaning. Users can
disable individual rules by ID without losing coverage of newer rules.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

from claude_safety_guard.guard import Severity


@dataclass(frozen=True, slots=True)
class Pattern:
    """A single dangerous-command detector.

    Parameters
    ----------
    id:
        Stable kebab-case identifier (e.g. ``"rm-rf-home"``). Used in config
        allowlists, logs, and test assertions.
    category:
        Short grouping label for reporting (e.g. ``"filesystem"``,
        ``"secrets"``).
    severity:
        :class:`Severity` level. ``BLOCK`` denies the command; ``WARN``
        surfaces it but allows execution.
    regex:
        Compiled pattern applied to the full command string. Patterns are
        intentionally forgiving of whitespace and common flag orderings.
    reason:
        Human-readable sentence shown to the user when the rule fires.
    """

    id: str
    category: str
    severity: Severity
    regex: re.Pattern[str]
    reason: str


def _re(pattern: str) -> re.Pattern[str]:
    """Compile ``pattern`` with IGNORECASE + DOTALL for readability."""
    return re.compile(pattern, re.IGNORECASE | re.DOTALL)


# ---------------------------------------------------------------------------
# Catalog
# ---------------------------------------------------------------------------

# Naming convention: <category>-<short-name>. Add new entries; never rename.
_CATALOG: Final[tuple[Pattern, ...]] = (
    # --- Filesystem destruction -------------------------------------------
    Pattern(
        id="fs-rm-rf-root",
        category="filesystem",
        severity=Severity.BLOCK,
        # rm with -r/-R + -f (any flag order) targeting / or /home
        regex=_re(
            r"\brm\s+(?:-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*|-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*"
            r"|(?:-r|--recursive)\s+(?:-f|--force)|(?:-f|--force)\s+(?:-r|--recursive))"
            r"""\s+(?:/(?:[\s'"`;|&]|$)|/\*|/home(?:/[a-z_.-]*\s*$|[\s'"`;|&]|$))"""
        ),
        reason=(
            "Recursive force-delete targeting the filesystem root or /home. "
            "One typo away from wiping the entire system."
        ),
    ),
    Pattern(
        id="fs-rm-rf-home-var",
        category="filesystem",
        severity=Severity.BLOCK,
        regex=_re(
            r"\brm\s+(?:-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*|-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*)"
            r"\s+(?:~/?\s*$|~\s*$|\$HOME\s*$|\"\$HOME\"\s*$|'\$HOME'\s*$)"
        ),
        reason=(
            "Recursive force-delete of $HOME. Unrecoverable; even when intended "
            "this should be a deliberate interactive action, not an agent call."
        ),
    ),
    Pattern(
        id="fs-rm-rf-cwd",
        category="filesystem",
        severity=Severity.BLOCK,
        regex=_re(
            r"\brm\s+(?:-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*|-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*)"
            r"""\s+\.(?:[\s'"`;|&]|$)"""
        ),
        reason=(
            "Recursive force-delete of the current directory. If the agent's cwd "
            "is ever wrong, this silently destroys the wrong project."
        ),
    ),
    Pattern(
        id="fs-rm-rf-wildcard-at-root",
        category="filesystem",
        severity=Severity.BLOCK,
        regex=_re(
            r"\brm\s+(?:-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*|-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*)"
            r"\s+/\*"
        ),
        reason="Recursive force-delete of / with glob. Near-certain system destruction.",
    ),
    Pattern(
        id="fs-disk-format",
        category="filesystem",
        severity=Severity.BLOCK,
        regex=_re(r"\b(?:mkfs(?:\.\w+)?|format)\s+/dev/"),
        reason="Filesystem format of a block device. Destroys all data on the device.",
    ),
    Pattern(
        id="fs-dd-to-device",
        category="filesystem",
        severity=Severity.BLOCK,
        regex=_re(r"\bdd\s+(?:[^|&;]*\s)?of=/dev/(?:sd[a-z]|nvme|disk|hd[a-z])"),
        reason="dd write directly to a block device. Bypasses filesystem; irrecoverable.",
    ),
    Pattern(
        id="fs-chmod-777-root",
        category="filesystem",
        severity=Severity.BLOCK,
        regex=_re(r"\bchmod\s+(?:-R\s+)?0*777\s+/\s*$"),
        reason="World-writable permissions on /. Makes the entire system a single trust boundary.",
    ),
    # --- Git destruction --------------------------------------------------
    Pattern(
        id="git-force-push-mainline",
        category="git",
        severity=Severity.BLOCK,
        regex=_re(
            r"\bgit\s+push\s+(?:[^|&;]*\s)?(?:--force|--force-with-lease|-f)\b"
            r"(?:[^|&;]*\b(?:main|master|trunk|release)\b)"
        ),
        reason=(
            "Force push to a protected branch. Can destroy upstream history and "
            "co-workers' commits. Use --force-with-lease only on your own feature "
            "branches if you absolutely must."
        ),
    ),
    Pattern(
        id="git-reset-hard-origin",
        category="git",
        severity=Severity.WARN,
        regex=_re(r"\bgit\s+reset\s+--hard\s+origin/"),
        reason=(
            "git reset --hard discards uncommitted changes silently. Agents should "
            "prefer git stash + reset to allow recovery."
        ),
    ),
    Pattern(
        id="git-clean-fdx",
        category="git",
        severity=Severity.WARN,
        regex=_re(r"\bgit\s+clean\s+(?:-[a-zA-Z]*f[a-zA-Z]*x|-[a-zA-Z]*d[a-zA-Z]*f)"),
        reason=(
            "git clean -fdx removes untracked AND gitignored files. Often deletes "
            ".env, venv/, node_modules/ that the user wanted to keep."
        ),
    ),
    Pattern(
        id="git-credential-read",
        category="git",
        severity=Severity.BLOCK,
        regex=_re(r"\bgit\s+credential(?:-\w+)?\s+fill\b"),
        reason="git credential fill prints stored credentials to stdout.",
    ),
    # --- Secret exfiltration ---------------------------------------------
    Pattern(
        id="secrets-pipe-to-curl",
        category="secrets",
        severity=Severity.BLOCK,
        regex=_re(
            r"\b(?:cat|less|more|head|tail)\s+[^|]*"
            r"(?:\.env|\.ssh/id[_-]|\.ssh/[a-zA-Z0-9_-]+_key|credentials?|client_secret|"
            r"\.pem|\.key|\.gpg|\.age|\.token)"
            r"[^|]*\|\s*(?:curl|wget|nc|ncat|httpie)\b"
        ),
        reason=(
            "Piping a secret file into a network client. This is the classic exfiltration shape."
        ),
    ),
    Pattern(
        id="secrets-curl-post-secret",
        category="secrets",
        severity=Severity.BLOCK,
        regex=_re(
            r"\b(?:curl|wget|httpie)\s+[^|&;]*(?:-d|--data(?:-\w+)?|--form|-F)"
            r"\s+@?[^|&;]*(?:\.env|\.ssh/id_|\.ssh/.*_key|credential|client_secret|"
            r"\.pem|\.key|\.gpg|\.age|\.token)\b"
        ),
        reason="Uploading a secret file via an HTTP client. Classic exfiltration shape.",
    ),
    Pattern(
        id="secrets-env-to-curl",
        category="secrets",
        severity=Severity.BLOCK,
        regex=_re(r"\b(?:printenv|env)\b[^|&;]*\|\s*(?:curl|wget|nc|ncat|httpie)"),
        reason="Dumping the process environment to a network client. Exposes every secret in env.",
    ),
    # --- Arbitrary code from the internet --------------------------------
    Pattern(
        id="supply-curl-bash",
        category="supply-chain",
        severity=Severity.BLOCK,
        regex=_re(r"\b(?:curl|wget|fetch)\s+[^|&;]*\|\s*(?:sudo\s+)?(?:ba|z|k)?sh\b"),
        reason=(
            "Piping a downloaded script directly into a shell. No integrity check, "
            "no human review, full code execution."
        ),
    ),
    Pattern(
        id="supply-curl-python",
        category="supply-chain",
        severity=Severity.BLOCK,
        regex=_re(r"\b(?:curl|wget|fetch)\s+[^|&;]*\|\s*(?:sudo\s+)?python3?\b"),
        reason=(
            "Piping a downloaded script directly into a Python interpreter. "
            "Same risk shape as curl|sh, different runtime."
        ),
    ),
    Pattern(
        id="supply-pip-from-url",
        category="supply-chain",
        severity=Severity.WARN,
        regex=_re(r"\bpip3?\s+install\s+(?:-[a-zA-Z]+\s+)*(?:https?://|git\+https?://)"),
        reason="pip install from a raw URL bypasses the index's typo-squat protections.",
    ),
    # --- Privilege / kernel ----------------------------------------------
    Pattern(
        id="priv-sudo-passwd-stdin",
        category="privilege",
        severity=Severity.BLOCK,
        regex=_re(r"\becho\s+[^|&;]+\|\s*sudo\s+(?:-S\b|--stdin\b)"),
        reason="Hard-coding a sudo password on stdin. Password ends up in shell history and logs.",
    ),
    Pattern(
        id="priv-fork-bomb",
        category="privilege",
        severity=Severity.BLOCK,
        regex=_re(r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}"),
        reason="Classic fork bomb. Exhausts process table within seconds.",
    ),
    # --- Destruction via package managers --------------------------------
    Pattern(
        id="pkg-apt-purge-all",
        category="package-manager",
        severity=Severity.BLOCK,
        regex=_re(r"\bapt(?:-get)?\s+(?:-y\s+)?(?:purge|remove)\s+(?:-y\s+)?\*"),
        reason=(
            "Purging all apt packages with glob. Near-certain to uninstall "
            "essential system packages."
        ),
    ),
)


def default_patterns() -> tuple[Pattern, ...]:
    """Return the immutable default catalog of patterns."""

    return _CATALOG


def all_pattern_ids() -> frozenset[str]:
    """Return the set of all default pattern IDs — useful for config validation."""

    return frozenset(p.id for p in _CATALOG)
