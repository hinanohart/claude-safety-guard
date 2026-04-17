# Changelog

All notable changes to `claude-safety-guard` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Pattern IDs are considered part of the **stable public API**: existing
IDs will never change meaning. New patterns may be added in any minor
release.

## [Unreleased]

## [0.1.0] — 2026-04-18

### Added

* Initial public release.
* Core engine (`evaluate`), frozen result dataclasses (`Decision`,
  `Finding`, `Pattern`, `Severity`, `Outcome`, `EvaluationOptions`).
* Claude Code PreToolUse hook adapter (`claude-safety-guard hook`),
  fail-open on errors so a broken guard never bricks the agent.
* CLI with `check`, `hook`, `list-rules`, `version` subcommands.
* TOML config loader with XDG-compliant discovery
  (`$CLAUDE_SAFETY_GUARD_CONFIG` → `$XDG_CONFIG_HOME` → `~/.config`),
  `allowlist`, `dry_run`, and `ask_on_warn` keys.
* Pattern catalog (20 rules across filesystem / git / secrets /
  supply-chain / privilege / package-manager), each with a stable
  kebab-case ID and a positive+negative test case.
* Zero runtime dependencies; Python 3.10+.
