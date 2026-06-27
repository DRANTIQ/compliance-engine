#!/usr/bin/env python3
"""Run the Platform V2 policy evaluation worker."""

from __future__ import annotations

import asyncio

from platform_backend.policy.worker import run_worker


def main() -> None:
    asyncio.run(run_worker())


if __name__ == "__main__":
    main()
