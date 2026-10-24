"""Local HTTP contract-test harness for the inline-hook adapter (tests only; FastAPI is not a runtime
dependency of the deployed agent, and nothing at runtime imports this module).

    app = make_app(InlineHookAdapter(), evaluate=lambda event: "ALLOW")
    TestClient(app).post("/hook", content=raw, headers=signed_headers)
"""

from typing import Any, Callable

# no `from __future__ import annotations` here: FastAPI must see the real Request class in the signature


def make_app(adapter: Any, evaluate: Callable[[Any], Any]) -> Any:
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse

    app = FastAPI(title="AgentShield inline-hook contract harness (synthetic)")

    @app.post("/hook")
    async def hook(request: Request) -> JSONResponse:
        raw = await request.body()   # raw bytes: the signature covers exactly these
        status, body = adapter.handle(raw, dict(request.headers), evaluate)
        return JSONResponse(body, status_code=status)

    return app
