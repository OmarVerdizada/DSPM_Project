"""M13 (roadmap 1.5): the perimeter refuses an over-cap request body before any
handler parses it, in bounded memory - and passes a normal body through intact."""

from __future__ import annotations

import asyncio
import unittest

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from backend.app import BodySizeLimitMiddleware


def _client(cap: int) -> TestClient:
    app = FastAPI()
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=cap)

    @app.post("/echo")
    async def echo(request: Request) -> dict:
        body = await request.body()
        return {"len": len(body)}

    @app.get("/ping")
    async def ping() -> dict:
        return {"ok": True}

    return TestClient(app)


class ContentLengthTests(unittest.TestCase):
    def test_oversized_content_length_is_refused(self) -> None:
        client = _client(1000)
        response = client.post("/echo", content=b"x" * 2000)  # Content-Length 2000 > 1000
        self.assertEqual(response.status_code, 413)

    def test_normal_body_passes_and_is_intact(self) -> None:
        client = _client(1000)
        response = client.post("/echo", content=b"x" * 500)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["len"], 500)  # replay preserved the body

    def test_body_exactly_at_cap_allowed(self) -> None:
        client = _client(1000)
        response = client.post("/echo", content=b"x" * 1000)
        self.assertEqual(response.status_code, 200)

    def test_get_request_unaffected(self) -> None:
        self.assertEqual(_client(1000).get("/ping").status_code, 200)

    def test_zero_disables_the_limit(self) -> None:
        client = _client(0)
        self.assertEqual(client.post("/echo", content=b"x" * 100000).status_code, 200)


class StreamedFloodTests(unittest.TestCase):
    def test_chunked_flood_is_bounded_and_rejected(self) -> None:
        # No Content-Length header (chunked / lying CL). The middleware must abort
        # at the cap WITHOUT reading the whole flood -> constant memory + 413.
        middleware = BodySizeLimitMiddleware(app=None, max_bytes=1000)
        scope = {"type": "http", "headers": []}
        reads = {"n": 0}

        async def receive() -> dict:
            reads["n"] += 1
            return {"type": "http.request", "body": b"x" * 400, "more_body": True}

        sent: list[dict] = []

        async def send(message: dict) -> None:
            sent.append(message)

        asyncio.run(middleware(scope, receive, send))
        self.assertEqual(sent[0]["status"], 413)          # refused
        self.assertLessEqual(reads["n"], 4)               # stopped near the cap, not unbounded


class RealAppWiringTests(unittest.TestCase):
    def test_middleware_is_installed_on_the_app(self) -> None:
        from backend.app import app

        names = [m.cls.__name__ for m in app.user_middleware]
        self.assertIn("BodySizeLimitMiddleware", names)


if __name__ == "__main__":
    unittest.main()
