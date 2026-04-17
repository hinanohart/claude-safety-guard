"""Command-line interface.

Subcommands:

* ``check <command>`` — evaluate a command and print the result. Exit
  status 0 for ALLOW/WARN, 1 for BLOCK. Useful in CI, scripts, and
  manual testing.
* ``hook`` — run the Claude Code PreToolUse hook (reads stdin, writes
  stdout, returns 0).
* ``list-rules`` — print the catalog of patterns as a table.
* ``version`` — print the version.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from claude_safety_guard._version import __version__
from claude_safety_guard.config import Config, load_config
from claude_safety_guard.guard import EvaluationOptions, Outcome, evaluate
from claude_safety_guard.hook import run_hook
from claude_safety_guard.patterns import default_patterns


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="claude-safety-guard",
        description="Block destructive shell commands before a Claude Code agent runs them.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        help=(
            "Path to a TOML config file "
            "(default: $XDG_CONFIG_HOME/claude-safety-guard/config.toml)."
        ),
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_check = sub.add_parser("check", help="Evaluate a command and print the result.")
    p_check.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of a human summary.",
    )
    p_check.add_argument(
        "--dry-run",
        action="store_true",
        help="Never exit non-zero; downgrade BLOCK findings to WARN.",
    )
    # argparse.REMAINDER consumes every remaining token verbatim, including
    # dash-prefixed flags like "-rf". This lets users write:
    #     claude-safety-guard check -- rm -rf /
    # or, equivalently:
    #     claude-safety-guard check rm -rf /
    p_check.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="The command to evaluate. Use '--' before flags if needed.",
    )

    sub.add_parser(
        "hook",
        help="Run as a Claude Code PreToolUse hook (reads JSON from stdin).",
    )
    sub.add_parser("list-rules", help="Print the catalog of patterns.")
    sub.add_parser("version", help="Print the version.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    config = load_config(args.config)

    if args.cmd == "check":
        return _cmd_check(args, config)
    if args.cmd == "hook":
        return run_hook(config=config)
    if args.cmd == "list-rules":
        return _cmd_list_rules()
    if args.cmd == "version":
        print(__version__)
        return 0
    parser.error(f"unknown command: {args.cmd}")
    return 2  # pragma: no cover — argparse exits first


def _cmd_check(args: argparse.Namespace, config: Config) -> int:
    tokens = [t for t in args.command if t != "--"]
    if not tokens:
        sys.stderr.write("claude-safety-guard: 'check' requires a command\n")
        return 2
    command = " ".join(tokens)
    options = EvaluationOptions(
        allowlist=frozenset(config.allowlist),
        dry_run=args.dry_run or config.dry_run,
    )
    decision = evaluate(command, options=options)

    if args.json:
        sys.stdout.write(json.dumps(decision.to_dict(), indent=2) + "\n")
    else:
        _render_human(decision)

    if decision.outcome is Outcome.BLOCK:
        return 1
    return 0


def _render_human(decision: Any) -> None:
    banner = {
        Outcome.ALLOW: "ALLOW  ",
        Outcome.WARN: "WARN   ",
        Outcome.BLOCK: "BLOCK  ",
    }[decision.outcome]
    sys.stdout.write(f"{banner} {decision.command}\n")
    for f in decision.findings:
        sys.stdout.write(f"  - [{f.severity.value:<5}] {f.pattern_id:<28} {f.reason}\n")
        sys.stdout.write(f"    matched: {f.matched_text!r}\n")


def _cmd_list_rules() -> int:
    sys.stdout.write(f"{'ID':<30} {'CATEGORY':<16} {'SEVERITY':<8} REASON\n")
    sys.stdout.write("-" * 100 + "\n")
    for p in default_patterns():
        sys.stdout.write(f"{p.id:<30} {p.category:<16} {p.severity.value:<8} {p.reason}\n")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
