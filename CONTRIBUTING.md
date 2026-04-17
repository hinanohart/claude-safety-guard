# Contributing

Thanks for considering a contribution. This project is small on purpose
— the point is a **loud, narrow, auditable** safety net — so the bar
for new rules is high but not unfriendly.

## Development setup

```bash
git clone https://github.com/hinanohart/claude-safety-guard.git
cd claude-safety-guard

python -m venv .venv
source .venv/bin/activate

pip install -e '.[dev]'
pytest
```

All tests are in `tests/` and run in under a second. No network, no
external processes, no fixtures to manage.

## Adding a new pattern

Every new pattern MUST come with:

1. A stable kebab-case `id` in the form `<category>-<short-name>` (e.g.
   `git-rebase-main`).
2. A one-sentence human-readable `reason` that tells a future reader
   *why* the shape is dangerous.
3. A `Severity` (BLOCK for near-certain data loss or credential
   exposure; WARN for "usually bad, sometimes fine").
4. A regex that is as tight as possible — think "false positives are
   worse than false negatives here, because users will disable the
   guard entirely if it cries wolf."
5. At least **one positive test case** in `tests/test_patterns.py`
   (`POSITIVE_CASES`) showing a command that rightly fires it.
6. At least **one negative test case** in `NEGATIVE_CASES` showing a
   command that looks similar but must NOT fire.
7. A one-line row in `docs/PATTERNS.md`.

The test
`test_every_catalog_pattern_has_at_least_one_positive_case` will fail
CI if you forget (5).

### What a good PR looks like

> **Add `pkg-npm-publish-force` to block `npm publish --force`.**
>
> Real incident: a maintainer accidentally force-published a stale
> tarball over a just-published good release, breaking downstream
> installs for ~2 hours. The `--force` flag on `npm publish`
> overrides the registry's immutability guarantee.
>
> Regex targets `npm\s+publish` with any `--force` flag present.
> Negative: plain `npm publish`, `npm publish --dry-run`.

## What will not get merged

* **ML / heuristics.** Every rule must be an auditable regex.
* **Rules that require shell parsing to match correctly.** The guard
  is a shape-matcher on purpose.
* **"Just in case" rules.** If you cannot point to a real-world
  incident or a well-known failure mode, the rule does not clear the
  bar.
* **Renames of existing IDs.** Pattern IDs are part of the public API;
  users reference them from config. New shapes need new IDs even when
  they subsume old ones.

## Code style

* Python 3.10+, type hints throughout.
* `from __future__ import annotations` at the top of every module.
* Frozen dataclasses for all public types.
* Zero runtime dependencies. Dev dependencies (pytest, ruff, mypy) are
  fine.
* `ruff check` and `mypy --strict src/` must both pass.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Do not open a public issue for a
security-relevant bypass — email first.

## License

By contributing you agree that your contribution will be distributed
under the Apache License 2.0, the same license as the rest of the
project.
