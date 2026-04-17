"""Tests for the command-line interface."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from claude_safety_guard._version import __version__
from claude_safety_guard.cli import main


def test_check_dangerous_command_returns_exit_1(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["check", "rm", "-rf", "/"])
    out = capsys.readouterr().out
    assert rc == 1
    assert "BLOCK" in out


def test_check_safe_command_returns_exit_0(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["check", "ls", "-la"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "ALLOW" in out


def test_check_warn_command_returns_exit_0(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["check", "git", "reset", "--hard", "origin/main"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "WARN" in out


def test_check_json_mode_emits_json(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["check", "--json", "rm", "-rf", "/"])
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert rc == 1
    assert payload["outcome"] == "block"
    assert payload["command"] == "rm -rf /"
    assert len(payload["findings"]) >= 1


def test_check_dry_run_downgrades_block(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["check", "--dry-run", "rm", "-rf", "/"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "WARN" in out


def test_list_rules_prints_every_pattern(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["list-rules"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "fs-rm-rf-root" in out
    assert "secrets-pipe-to-curl" in out


def test_version_prints_version(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["version"])
    out = capsys.readouterr().out
    assert rc == 0
    assert __version__ in out


def test_missing_command_argument_errors() -> None:
    with pytest.raises(SystemExit):
        main([])


def test_check_respects_config_allowlist(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cfg = tmp_path / "config.toml"
    cfg.write_text('allowlist = ["fs-rm-rf-root"]\n', encoding="utf-8")
    rc = main(["--config", str(cfg), "check", "rm", "-rf", "/"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "ALLOW" in out
