"""Tests for the evaluation engine itself, independent of the catalog."""

from __future__ import annotations

import dataclasses
import json
import re

import pytest

from claude_safety_guard.guard import (
    Decision,
    EvaluationOptions,
    Finding,
    Outcome,
    Severity,
    evaluate,
)
from claude_safety_guard.patterns import Pattern


def make_pattern(
    pid: str = "test-pat",
    severity: Severity = Severity.BLOCK,
    regex: str = r"DANGER",
) -> Pattern:
    return Pattern(
        id=pid,
        category="test",
        severity=severity,
        regex=re.compile(regex),
        reason="test reason",
    )


def test_empty_command_returns_allow() -> None:
    decision = evaluate("")
    assert decision.outcome is Outcome.ALLOW
    assert decision.findings == ()


def test_whitespace_only_command_returns_allow() -> None:
    decision = evaluate("   \t  \n")
    assert decision.outcome is Outcome.ALLOW


def test_single_block_pattern_blocks() -> None:
    decision = evaluate("rm DANGER now", patterns=[make_pattern()])
    assert decision.outcome is Outcome.BLOCK
    assert decision.blocked is True
    assert len(decision.findings) == 1
    assert decision.findings[0].pattern_id == "test-pat"


def test_single_warn_pattern_warns() -> None:
    decision = evaluate("watch DANGER", patterns=[make_pattern(severity=Severity.WARN)])
    assert decision.outcome is Outcome.WARN
    assert decision.has_warnings is True
    assert decision.blocked is False


def test_block_plus_warn_is_block() -> None:
    patterns = [
        make_pattern("block-pat", Severity.BLOCK, r"KILL"),
        make_pattern("warn-pat", Severity.WARN, r"watch"),
    ]
    decision = evaluate("KILL and watch me", patterns=patterns)
    assert decision.outcome is Outcome.BLOCK
    ids = {f.pattern_id for f in decision.findings}
    assert ids == {"block-pat", "warn-pat"}


def test_no_match_returns_allow() -> None:
    decision = evaluate("safe command", patterns=[make_pattern()])
    assert decision.outcome is Outcome.ALLOW


def test_allowlist_silences_specific_pattern() -> None:
    patterns = [make_pattern()]
    options = EvaluationOptions(allowlist=frozenset({"test-pat"}))
    decision = evaluate("rm DANGER", patterns=patterns, options=options)
    assert decision.outcome is Outcome.ALLOW
    assert decision.findings == ()


def test_allowlist_does_not_silence_other_patterns() -> None:
    patterns = [
        make_pattern("allowed-pat", Severity.BLOCK, r"DANGER"),
        make_pattern("not-allowed-pat", Severity.BLOCK, r"KILL"),
    ]
    options = EvaluationOptions(allowlist=frozenset({"allowed-pat"}))
    decision = evaluate("DANGER + KILL", patterns=patterns, options=options)
    assert decision.outcome is Outcome.BLOCK
    ids = {f.pattern_id for f in decision.findings}
    assert ids == {"not-allowed-pat"}


def test_dry_run_downgrades_block_to_warn_outcome() -> None:
    options = EvaluationOptions(dry_run=True)
    decision = evaluate("DANGER", patterns=[make_pattern()], options=options)
    assert decision.outcome is Outcome.WARN
    # But the finding itself retains its original severity so callers can
    # tell "dry-run suppressed BLOCK" from "actually WARN."
    assert decision.findings[0].severity is Severity.BLOCK


def test_dry_run_preserves_genuine_warn() -> None:
    options = EvaluationOptions(dry_run=True)
    decision = evaluate(
        "DANGER",
        patterns=[make_pattern(severity=Severity.WARN)],
        options=options,
    )
    assert decision.outcome is Outcome.WARN
    assert decision.findings[0].severity is Severity.WARN


def test_finding_to_dict_is_json_safe() -> None:
    finding = Finding(
        pattern_id="id",
        category="cat",
        severity=Severity.BLOCK,
        reason="r",
        matched_text="m",
    )
    data = finding.to_dict()
    assert json.loads(json.dumps(data)) == data


def test_decision_to_dict_is_json_safe() -> None:
    decision = evaluate("DANGER", patterns=[make_pattern()])
    data = decision.to_dict()
    assert json.loads(json.dumps(data)) == data


def test_decision_is_immutable() -> None:
    decision = evaluate("")
    with pytest.raises(dataclasses.FrozenInstanceError):
        decision.outcome = Outcome.BLOCK  # type: ignore[misc]


def test_default_patterns_are_used_when_none_passed() -> None:
    # 'rm -rf /' should match a default pattern without passing patterns=
    decision = evaluate("rm -rf /")
    assert decision.outcome is Outcome.BLOCK


def test_empty_pattern_list_never_blocks() -> None:
    decision = evaluate("rm -rf /", patterns=[])
    assert decision.outcome is Outcome.ALLOW
    assert isinstance(decision, Decision)
