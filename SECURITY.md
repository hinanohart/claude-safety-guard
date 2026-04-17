# Security policy

## Reporting a vulnerability

Please report security issues privately by email to
**`hinanohart@gmail.com`** with the subject prefix
`[claude-safety-guard security]`.

I aim to acknowledge within 72 hours and to ship a fix (or publish an
advisory explaining the trade-off) within 14 days for high-severity
issues.

## What counts as security-relevant

* A **bypass**: a shell command that the catalog clearly intends to
  block but that escapes the current regex (e.g. via unusual whitespace,
  quoting, or flag ordering).
* A **crash-on-untrusted-input** in the hook: any input from
  `tool_input.command` that causes `claude-safety-guard hook` to exit
  non-zero, hang, or consume unbounded memory. The hook is designed to
  fail open; a crash that turns this into a denial-of-service against
  the user's Claude Code workflow is in scope.
* **Supply-chain concerns** with the packaging (signed releases,
  Trusted Publishing configuration, CI token scope, etc.).

## What is not in scope

* Rules you disagree with. Allowlist them and, if you have a case study
  for why the shape is sometimes safe, open a regular issue.
* Root-level compromise of the user's machine. If the attacker can edit
  `~/.claude/settings.json`, they can disable the guard entirely; the
  guard is a safety net against agent mistakes, not privileged
  adversaries.
* The fundamental regex-not-shell-parser design trade-off (see the
  "Threat model & non-goals" section in the README).

## Disclosure

Coordinated disclosure preferred. Once a fix is released, a short
advisory is added to [CHANGELOG.md](CHANGELOG.md) crediting the reporter
(unless they prefer to remain anonymous).
