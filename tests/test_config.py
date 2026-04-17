"""Tests for the config loader."""

from __future__ import annotations

from pathlib import Path

import pytest

from claude_safety_guard.config import Config, default_config_path, load_config


def test_missing_file_returns_default_config(tmp_path: Path) -> None:
    path = tmp_path / "no-such-file.toml"
    cfg = load_config(path)
    assert cfg == Config()


def test_empty_file_returns_default_config(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text("", encoding="utf-8")
    cfg = load_config(path)
    assert cfg == Config()


def test_allowlist_is_loaded(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text(
        'allowlist = ["fs-rm-rf-root", "git-reset-hard-origin"]\n',
        encoding="utf-8",
    )
    cfg = load_config(path)
    assert "fs-rm-rf-root" in cfg.allowlist
    assert "git-reset-hard-origin" in cfg.allowlist


def test_dry_run_flag_is_loaded(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text("dry_run = true\n", encoding="utf-8")
    cfg = load_config(path)
    assert cfg.dry_run is True


def test_ask_on_warn_flag_is_loaded(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text("ask_on_warn = true\n", encoding="utf-8")
    cfg = load_config(path)
    assert cfg.ask_on_warn is True


def test_unknown_allowlist_entries_are_dropped(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "config.toml"
    path.write_text(
        'allowlist = ["fs-rm-rf-root", "this-does-not-exist"]\n',
        encoding="utf-8",
    )
    cfg = load_config(path)
    assert "fs-rm-rf-root" in cfg.allowlist
    assert "this-does-not-exist" not in cfg.allowlist
    err = capsys.readouterr().err
    assert "this-does-not-exist" in err


def test_malformed_toml_is_tolerated(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "config.toml"
    path.write_text("this is = broken === toml [\n", encoding="utf-8")
    cfg = load_config(path)
    assert cfg == Config()
    err = capsys.readouterr().err
    assert "failed to parse" in err


def test_default_config_path_uses_env_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CLAUDE_SAFETY_GUARD_CONFIG", "/custom/path.toml")
    assert default_config_path() == Path("/custom/path.toml")


def test_default_config_path_uses_xdg_config_home(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CLAUDE_SAFETY_GUARD_CONFIG", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", "/xdg/home")
    assert default_config_path() == Path("/xdg/home/claude-safety-guard/config.toml")


def test_default_config_path_falls_back_to_home(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CLAUDE_SAFETY_GUARD_CONFIG", raising=False)
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.setenv("HOME", "/fake/home")
    assert default_config_path() == Path("/fake/home/.config/claude-safety-guard/config.toml")
