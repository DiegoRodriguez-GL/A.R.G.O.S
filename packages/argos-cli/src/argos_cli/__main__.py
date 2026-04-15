"""Console-scripts entry point: installed as ``argos`` on the PATH."""

from __future__ import annotations

import sys

from argos_cli.app import app


def main() -> int:
    try:
        app()
    except SystemExit as exc:
        return int(exc.code or 0)
    return 0


if __name__ == "__main__":
    sys.exit(main())
