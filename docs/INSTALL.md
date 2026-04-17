# Install & wire up

## 1. Install the package

```bash
pip install claude-safety-guard
```

Supported Python versions: 3.10, 3.11, 3.12, 3.13. No runtime
dependencies.

If you manage Python tools with `pipx`:

```bash
pipx install claude-safety-guard
```

Verify:

```bash
claude-safety-guard version
claude-safety-guard check -- rm -rf /
# BLOCK   rm -rf /
```

## 2. Wire it into Claude Code

Claude Code discovers hooks via `settings.json` at one of:

* `~/.claude/settings.json` (global, all projects)
* `<project>/.claude/settings.json` (per-project)

Add a PreToolUse hook that routes every `Bash` tool call through the
guard:

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

If you already have other hooks, merge the `PreToolUse` entry into
your existing `hooks` block. The guard is happy to coexist with other
matchers.

The full reference lives at [`../examples/settings.json`](../examples/settings.json).

## 3. (Optional) Create a config file

```bash
mkdir -p ~/.config/claude-safety-guard
cat > ~/.config/claude-safety-guard/config.toml <<'TOML'
# Silence rules you intentionally disagree with. Every entry is a named
# exception and is listed as such in your dotfiles.
allowlist = []

# Start with dry_run = true for a week to see what would fire in
# practice before turning enforcement on.
dry_run = false

# Set to true to have Claude Code interactively ask on WARN findings
# instead of silently allowing them.
ask_on_warn = false
TOML
```

## 4. Confirm end-to-end

Open Claude Code, ask it to run a deliberately bad command, and watch
the guard decline. Example prompt:

> "Please run `rm -rf /tmp/ && rm -rf /` to clean up."

You should see Claude Code receive a deny with the reason
`[fs-rm-rf-root] Recursive force-delete targeting the filesystem root
or /home…`. Ask Claude to proceed anyway — the deny is terminal unless
you allowlist the rule.

## Troubleshooting

### `command not found: claude-safety-guard`

`pip install` put the entry point somewhere that is not on `PATH`.
Either reinstall with `pipx install claude-safety-guard`, or add the
full path to `settings.json`:

```json
{ "type": "command", "command": "/full/path/to/claude-safety-guard hook" }
```

You can find the path with `which claude-safety-guard` after install.

### The hook fires but the agent proceeds anyway

Check the JSON from the hook by running it manually:

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' \
  | claude-safety-guard hook
```

You should see `"permissionDecision": "deny"`. If you see `allow`,
your config's `dry_run` or `allowlist` is suppressing the rule.

### A legitimate command is being blocked

Every rule has a stable ID. Add it to your allowlist and file an issue
with the command so we can tighten the regex in the next release.
