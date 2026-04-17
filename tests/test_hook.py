"""Tests for the Claude Code PreToolUse hook adapter."""

from __future__ import annotations

import io
import json

import pytest

from claude_safety_guard.config import Config
from claude_safety_guard.guard import Decision, Finding, Outcome, Severity
from claude_safety_guard.hook import HookOutput, decide, extract_command, run_hook


def envelope(command: str, tool_name: str = "Bash") -> str:
    return json.dumps({"tool_name": tool_name, "tool_input": {"command": command}})


def run(stdin_text: str, config: Config | None = None) -> dict:
    stdin = io.StringIO(stdin_text)
    stdout = io.StringIO()
    rc = run_hook(stdin=stdin, stdout=stdout, config=config or Config())
    assert rc == 0
    return json.loads(stdout.getvalue())


# ---------- extract_command ---------------------------------------------------


def test_extract_command_reads_bash_tool() -> None:
    env = {"tool_name": "Bash", "tool_input": {"command": "ls -la"}}
    assert extract_command(env) == "ls -la"


def test_extract_command_lowercase_bash_is_accepted() -> None:
    env = {"tool_name": "bash", "tool_input": {"command": "ls"}}
    assert extract_command(env) == "ls"


def test_extract_command_non_bash_tool_returns_empty() -> None:
    env = {"tool_name": "Read", "tool_input": {"file_path": "/etc/hosts"}}
    assert extract_command(env) == ""


def test_extract_command_missing_tool_input_returns_empty() -> None:
    assert extract_command({"tool_name": "Bash"}) == ""


def test_extract_command_non_string_command_returns_empty() -> None:
    env = {"tool_name": "Bash", "tool_input": {"command": 42}}
    assert extract_command(env) == ""


# ---------- decide ------------------------------------------------------------


def _mock_decision(outcome: Outcome, findings: tuple[Finding, ...] = ()) -> Decision:
    return Decision(outcome=outcome, findings=findings, command="test")


def test_decide_block_returns_deny_with_reason() -> None:
    finding = Finding(
        pattern_id="p1",
        category="c",
        severity=Severity.BLOCK,
        reason="boom",
        matched_text="x",
    )
    out = decide(_mock_decision(Outcome.BLOCK, (finding,)), config=Config())
    assert out.decision == "deny"
    assert "p1" in out.reason and "boom" in out.reason


def test_decide_warn_returns_allow_by_default() -> None:
    finding = Finding(
        pattern_id="p1",
        category="c",
        severity=Severity.WARN,
        reason="careful",
        matched_text="x",
    )
    out = decide(_mock_decision(Outcome.WARN, (finding,)), config=Config())
    assert out.decision == "allow"
    assert "[warn]" in out.reason


def test_decide_warn_returns_ask_when_configured() -> None:
    finding = Finding(
        pattern_id="p1",
        category="c",
        severity=Severity.WARN,
        reason="careful",
        matched_text="x",
    )
    out = decide(
        _mock_decision(Outcome.WARN, (finding,)),
        config=Config(ask_on_warn=True),
    )
    assert out.decision == "ask"


def test_decide_warn_from_dry_run_mentions_dry_run() -> None:
    finding = Finding(
        pattern_id="p1",
        category="c",
        severity=Severity.BLOCK,
        reason="would block",
        matched_text="x",
    )
    out = decide(
        _mock_decision(Outcome.WARN, (finding,)),
        config=Config(dry_run=True),
    )
    assert "dry-run" in out.reason


def test_decide_allow_returns_allow() -> None:
    out = decide(_mock_decision(Outcome.ALLOW, ()), config=Config())
    assert out.decision == "allow"
    assert out.reason == ""


# ---------- run_hook ---------------------------------------------------------


def test_run_hook_blocks_dangerous_command() -> None:
    out = run(envelope("rm -rf /"))
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_run_hook_allows_safe_command() -> None:
    out = run(envelope("ls -la"))
    assert out["hookSpecificOutput"]["permissionDecision"] == "allow"


def test_run_hook_allows_non_bash_tool() -> None:
    non_bash = json.dumps({"tool_name": "Read", "tool_input": {"file_path": "/x"}})
    out = run(non_bash)
    assert out["hookSpecificOutput"]["permissionDecision"] == "allow"


def test_run_hook_allows_empty_stdin() -> None:
    out = run("")
    assert out["hookSpecificOutput"]["permissionDecision"] == "allow"


def test_run_hook_fails_open_on_bad_json() -> None:
    out = run("{this is not json")
    # Fail open: broken hook must not brick the agent.
    assert out["hookSpecificOutput"]["permissionDecision"] == "allow"
    assert "warning" in out["reason"]


def test_run_hook_fails_open_on_non_object_json() -> None:
    out = run("[1, 2, 3]")
    assert out["hookSpecificOutput"]["permissionDecision"] == "allow"


def test_run_hook_allowlist_suppresses_block() -> None:
    # rm -rf / matches fs-rm-rf-root; allowlist silences it entirely.
    out = run(
        envelope("rm -rf /"),
        config=Config(allowlist=frozenset({"fs-rm-rf-root"})),
    )
    assert out["hookSpecificOutput"]["permissionDecision"] == "allow"


def test_run_hook_dry_run_downgrades_block() -> None:
    out = run(envelope("rm -rf /"), config=Config(dry_run=True))
    # In dry-run, a BLOCK becomes an allow (with a dry-run reason).
    assert out["hookSpecificOutput"]["permissionDecision"] == "allow"
    assert "dry-run" in out["reason"]


def test_run_hook_returns_claude_code_envelope_shape() -> None:
    out = run(envelope("rm -rf /"))
    assert "hookSpecificOutput" in out
    hook = out["hookSpecificOutput"]
    assert hook["hookEventName"] == "PreToolUse"
    assert "permissionDecision" in hook
    assert "permissionDecisionReason" in hook
    assert "reason" in out


def test_hookoutput_envelope_roundtrip() -> None:
    env = HookOutput(decision="deny", reason="boom").to_envelope()
    s = json.dumps(env)
    back = json.loads(s)
    assert back == env


@pytest.mark.parametrize(
    "command",
    [
        "rm -rf /",
        "rm -rf $HOME",
        "git push --force origin main",
        ":(){ :|: & };:",
    ],
)
def test_run_hook_blocks_known_dangerous_commands(command: str) -> None:
    out = run(envelope(command))
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny", (
        f"expected deny for {command!r}, got: {out}"
    )
