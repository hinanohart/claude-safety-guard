"""Claude Code PreToolUse hook adapter.

Claude Code invokes pre-tool-use hooks with a JSON envelope on stdin:

.. code-block:: json

    {
      "tool_name": "Bash",
      "tool_input": {"command": "rm -rf /"}
    }

The hook is expected to write a single JSON line to stdout with one of:

.. code-block:: json

    {
      "hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny" | "allow" | "ask",
        "permissionDecisionReason": "..."
      },
      "reason": "..."
    }

This module converts a :class:`~claude_safety_guard.guard.Decision` into that
shape and handles the stdin/stdout plumbing.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from claude_safety_guard.config import Config, load_config
from claude_safety_guard.guard import Decision, EvaluationOptions, Outcome, evaluate

if TYPE_CHECKING:
    from collections.abc import Mapping


@dataclass(frozen=True, slots=True)
class HookOutput:
    """Structured Claude Code PreToolUse response."""

    decision: str  # "allow" | "deny" | "ask"
    reason: str

    def to_envelope(self) -> dict[str, Any]:
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": self.decision,
                "permissionDecisionReason": self.reason,
            },
            "reason": self.reason,
        }


def extract_command(envelope: Mapping[str, Any]) -> str:
    """Pull the shell command out of a Claude Code PreToolUse envelope.

    Returns an empty string if the envelope does not refer to a Bash tool
    call (other tools do not carry a shell command and should be let
    through).
    """

    tool_name = envelope.get("tool_name", "")
    if tool_name not in {"Bash", "bash"}:
        return ""
    tool_input = envelope.get("tool_input", {})
    if not isinstance(tool_input, dict):
        return ""
    command = tool_input.get("command", "")
    return command if isinstance(command, str) else ""


def decide(decision_obj: Decision, *, config: Config) -> HookOutput:
    """Translate a :class:`Decision` into a :class:`HookOutput`.

    * ``Outcome.BLOCK`` → ``deny`` with the top finding's reason.
    * ``Outcome.WARN``  → ``allow`` with a warning-prefixed reason (Claude Code
      surfaces the reason to the user even for allow decisions), unless the
      user has opted into ``ask`` for warnings.
    * ``Outcome.ALLOW`` → ``allow`` with empty reason.
    """

    if decision_obj.outcome is Outcome.BLOCK:
        primary = decision_obj.findings[0]
        return HookOutput(
            decision="deny",
            reason=f"[{primary.pattern_id}] {primary.reason}",
        )
    if decision_obj.outcome is Outcome.WARN:
        if not decision_obj.findings:
            return HookOutput(decision="allow", reason="")
        primary = decision_obj.findings[0]
        prefix = "[dry-run would-block]" if config.dry_run else "[warn]"
        hook_decision = "ask" if config.ask_on_warn else "allow"
        return HookOutput(
            decision=hook_decision,
            reason=f"{prefix} [{primary.pattern_id}] {primary.reason}",
        )
    return HookOutput(decision="allow", reason="")


def run_hook(
    stdin: Any | None = None,
    stdout: Any | None = None,
    config: Config | None = None,
) -> int:
    """Run the hook end-to-end: read stdin JSON, write stdout JSON, return exit code.

    Parameters
    ----------
    stdin, stdout:
        Streams to read/write. Default to :data:`sys.stdin` / :data:`sys.stdout`.
    config:
        :class:`Config` to use. If ``None``, loads from the standard config
        location.
    """

    if stdin is None:
        stdin = sys.stdin
    if stdout is None:
        stdout = sys.stdout
    if config is None:
        config = load_config()

    try:
        raw = stdin.read()
    except OSError:
        return _emit_error(stdout, "failed to read stdin")
    if not raw.strip():
        return _emit_allow(stdout)

    try:
        envelope = json.loads(raw)
    except json.JSONDecodeError:
        return _emit_error(stdout, "stdin was not valid JSON")
    if not isinstance(envelope, dict):
        return _emit_error(stdout, "stdin JSON was not an object")

    command = extract_command(envelope)
    if not command:
        return _emit_allow(stdout)

    options = EvaluationOptions(
        allowlist=frozenset(config.allowlist),
        dry_run=config.dry_run,
    )
    decision_obj = evaluate(command, options=options)
    hook_output = decide(decision_obj, config=config)

    stdout.write(json.dumps(hook_output.to_envelope()) + "\n")
    return 0


def _emit_allow(stdout: Any) -> int:
    stdout.write(json.dumps(HookOutput(decision="allow", reason="").to_envelope()) + "\n")
    return 0


def _emit_error(stdout: Any, message: str) -> int:
    # Fail open, not closed: a broken hook must not brick the agent.
    # The message is surfaced to the user so they can fix the configuration.
    stdout.write(
        json.dumps(
            HookOutput(
                decision="allow",
                reason=f"[claude-safety-guard warning] {message}",
            ).to_envelope()
        )
        + "\n"
    )
    return 0
