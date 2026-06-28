"""Load repo .env files into os.environ (does not override existing vars)."""

from __future__ import annotations

import os
from pathlib import Path

_SCRIPTS_DIR = Path(__file__).resolve().parent
_BACKEND_ROOT = _SCRIPTS_DIR.parent
_COLLECTORS_ENV = _BACKEND_ROOT.parent / "platform-collectors" / ".env"


def load_dotenv_file(path: Path) -> None:
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"')
        os.environ.setdefault(key, value)


def load_repo_dotenv() -> None:
    load_dotenv_file(_BACKEND_ROOT / ".env")


def load_collectors_dotenv() -> None:
    load_dotenv_file(_COLLECTORS_ENV)
