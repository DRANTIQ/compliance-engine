from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import RedirectResponse

router = APIRouter(include_in_schema=False)


@router.get("/swagger")
async def swagger_redirect() -> RedirectResponse:
    """Alias for Swagger UI at /docs."""
    return RedirectResponse(url="/docs", status_code=307)
