#!/usr/bin/env python3
from __future__ import annotations

import asyncio

from platform_backend.assets.ingest.worker import run_worker


def main() -> None:
    asyncio.run(run_worker())


if __name__ == "__main__":
    main()
