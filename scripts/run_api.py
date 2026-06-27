from __future__ import annotations

import uvicorn

from platform_backend.api.main import create_app
from platform_backend.config.settings import get_settings


def main() -> None:
    settings = get_settings()
    uvicorn.run(
        "platform_backend.api.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=False,
        factory=False,
    )


if __name__ == "__main__":
    main()
