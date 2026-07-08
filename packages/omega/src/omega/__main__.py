"""``python -m omega`` entry point — delegates to the CLI (Stage 6)."""

from omega.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
