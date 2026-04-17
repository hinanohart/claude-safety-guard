# Pattern catalog

Every rule in `claude-safety-guard` has a stable ID, a category, a
severity (BLOCK or WARN), and a plain-English reason. IDs are
**stable across releases** so you can reference them from your config
allowlist without worrying about silent meaning changes.

To print the live catalog from your installed version:

```bash
claude-safety-guard list-rules
```

## Severity

| Severity | Effect in the hook | Effect in `check`  |
|----------|--------------------|--------------------|
| BLOCK    | `permissionDecision: deny` | exit 1 |
| WARN     | `permissionDecision: allow` (or `ask` if `ask_on_warn = true`); reason surfaced | exit 0 |

`dry_run = true` downgrades BLOCK to WARN globally.

## Categories

### Filesystem destruction

| ID                        | Severity | What fires it                                         |
|---------------------------|----------|-------------------------------------------------------|
| `fs-rm-rf-root`           | BLOCK    | `rm -rf` targeting `/` or `/home` (any flag order)    |
| `fs-rm-rf-home-var`       | BLOCK    | `rm -rf ~`, `rm -rf $HOME`, quoted variants           |
| `fs-rm-rf-cwd`            | BLOCK    | `rm -rf .` — catastrophic if cwd is ever wrong        |
| `fs-rm-rf-wildcard-at-root`| BLOCK   | `rm -rf /*`                                           |
| `fs-disk-format`          | BLOCK    | `mkfs.*` or `format` against `/dev/*`                 |
| `fs-dd-to-device`         | BLOCK    | `dd of=/dev/sdX` (or nvme/hd/disk)                    |
| `fs-chmod-777-root`       | BLOCK    | `chmod 777 /` (with optional `-R`)                    |

### Git destruction

| ID                        | Severity | What fires it                                         |
|---------------------------|----------|-------------------------------------------------------|
| `git-force-push-mainline` | BLOCK    | `git push -f` / `--force-with-lease` to main/master/trunk/release |
| `git-reset-hard-origin`   | WARN     | `git reset --hard origin/…` — silently drops WIP      |
| `git-clean-fdx`           | WARN     | `git clean -fdx` / `-xdf` — removes gitignored files  |
| `git-credential-read`     | BLOCK    | `git credential fill` — prints stored creds to stdout |

### Secret exfiltration

| ID                         | Severity | What fires it                                        |
|----------------------------|----------|------------------------------------------------------|
| `secrets-pipe-to-curl`     | BLOCK    | `cat .env \| curl …` or similar with key/pem/token files |
| `secrets-curl-post-secret` | BLOCK    | `curl -d @.env …`                                    |
| `secrets-env-to-curl`      | BLOCK    | `printenv \| curl …`, `env \| nc …`                  |

### Supply chain

| ID                  | Severity | What fires it                                        |
|---------------------|----------|------------------------------------------------------|
| `supply-curl-bash`  | BLOCK    | `curl … \| sh` / `\| bash`                           |
| `supply-curl-python`| BLOCK    | `curl … \| python`                                   |
| `supply-pip-from-url`| WARN    | `pip install https://…` or `git+https://…`           |

### Privilege / kernel

| ID                      | Severity | What fires it                                    |
|-------------------------|----------|--------------------------------------------------|
| `priv-sudo-passwd-stdin`| BLOCK    | `echo … \| sudo -S`                              |
| `priv-fork-bomb`        | BLOCK    | Classic `:(){ :\|: & };:` shape                  |

### Package managers

| ID                 | Severity | What fires it                                  |
|--------------------|----------|------------------------------------------------|
| `pkg-apt-purge-all`| BLOCK    | `apt(-get) purge *` / `remove *`               |

## Allowlisting

Disable individual rules in your config:

```toml
# ~/.config/claude-safety-guard/config.toml
allowlist = ["git-clean-fdx", "supply-pip-from-url"]
```

Unknown IDs are dropped with a warning on stderr at load time — typos
will not silently disable all rules.

## Proposing a new rule

New rules are very welcome, but each one must justify itself against a
single question: **has this shape actually damaged a real system, and is
the regex tight enough that legitimate commands will not trigger it?**

See [`../CONTRIBUTING.md`](../CONTRIBUTING.md) for the exact
positive/negative test requirements.
