"""Allow ``python -m claude_safety_guard`` to invoke the CLI."""

from claude_safety_guard.cli import main

raise SystemExit(main())
