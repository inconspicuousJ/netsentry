"""Allow ``python -m netsentry``."""

from .cli import main

raise SystemExit(main())
