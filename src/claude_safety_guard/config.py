"""User configuration loader.

Uses the standard-library :mod:`tomllib` (Python 3.11+) when available, and
falls back to a minimal TOML subset parser for Python 3.10. The config is
intentionally small — the package is security-critical, and a complex
configuration surface is its own security risk.

Default config path, in order of precedence:

1. ``$CLAUDE_SAFETY_GUARD_CONFIG``
2. ``~/.config/claude-safety-guard/config.toml``
3. Empty defaults.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from claude_safety_guard.patterns import all_pattern_ids

if sys.version_info >= (3, 11):
    import tomllib  # pragma: no cover - stdlib since 3.11
else:  # pragma: no cover - only exercised on 3.10 CI matrix
    import tomli as tomllib  # type: ignore[no-redef, unused-ignore]


@dataclass(frozen=True, slots=True)
class Config:
    """Parsed user configuration.

    Attributes
    ----------
    allowlist:
        Pattern IDs the user has explicitly chosen to ignore.
    dry_run:
        If True, BLOCK findings become WARN. Useful for onboarding or
        auditing what would be blocked without breaking existing flows.
    ask_on_warn:
        If True, the hook emits ``ask`` (prompt the user) on WARN instead
        of ``allow``. Off by default to avoid prompt fatigue.
    """

    allowlist: frozenset[str] = field(default_factory=frozenset)
    dry_run: bool = False
    ask_on_warn: bool = False


def default_config_path() -> Path:
    override = os.environ.get("CLAUDE_SAFETY_GUARD_CONFIG")
    if override:
        return Path(override)
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "claude-safety-guard" / "config.toml"


def load_config(path: Path | None = None) -> Config:
    """Load the config from ``path`` (or the default location).

    Missing files are not an error — the default :class:`Config` is returned.
    Malformed files are also not an error; they are logged (stderr) and the
    default config is returned. A broken config must not brick the hook.
    """

    if path is None:
        path = default_config_path()

    if not path.is_file():
        return Config()

    try:
        with path.open("rb") as f:
            data = tomllib.load(f)
    except (tomllib.TOMLDecodeError, OSError) as exc:
        print(
            f"claude-safety-guard: failed to parse {path}: {exc}; using defaults.",
            file=sys.stderr,
        )
        return Config()

    return _from_dict(data)


def _from_dict(data: dict[str, Any]) -> Config:
    raw_allow = data.get("allowlist", [])
    allowlist: frozenset[str]
    if isinstance(raw_allow, list):
        known = all_pattern_ids()
        items = [str(x) for x in raw_allow if isinstance(x, str)]
        unknown = [i for i in items if i not in known]
        if unknown:
            print(
                f"claude-safety-guard: ignoring unknown pattern IDs in allowlist: {unknown}",
                file=sys.stderr,
            )
        allowlist = frozenset(i for i in items if i in known)
    else:
        allowlist = frozenset()

    return Config(
        allowlist=allowlist,
        dry_run=bool(data.get("dry_run", False)),
        ask_on_warn=bool(data.get("ask_on_warn", False)),
    )
