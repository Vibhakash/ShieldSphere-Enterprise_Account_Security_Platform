import os
import sys
import unittest
from pathlib import Path

import httpx


BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))
os.environ.setdefault("DATABASE_URL", "postgresql+psycopg://test:test@localhost/test")
os.environ.setdefault("JWT_SECRET", "test-access-secret-with-sufficient-length")
os.environ.setdefault("JWT_REFRESH_SECRET", "test-refresh-secret-with-sufficient-length")

from app.services.outbound_http import (  # noqa: E402
    UnsafeOutboundTarget,
    safe_public_get,
    validate_public_url,
)


class OutboundUrlSafetyTests(unittest.IsolatedAsyncioTestCase):
    async def test_public_ip_is_allowed(self):
        self.assertEqual(await validate_public_url("https://8.8.8.8/path"), "https://8.8.8.8/path")

    async def test_private_and_loopback_targets_are_rejected(self):
        for url in (
            "http://127.0.0.1/admin",
            "http://10.0.0.5/",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]/",
            "http://localhost/",
        ):
            with self.subTest(url=url):
                with self.assertRaises(UnsafeOutboundTarget):
                    await validate_public_url(url)

    async def test_non_http_and_embedded_credentials_are_rejected(self):
        with self.assertRaises(UnsafeOutboundTarget):
            await validate_public_url("file:///etc/passwd")
        with self.assertRaises(UnsafeOutboundTarget):
            await validate_public_url("https://user:password@8.8.8.8/")

    async def test_redirect_to_private_target_is_rejected(self):
        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(302, headers={"location": "http://127.0.0.1/private"})

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            with self.assertRaises(UnsafeOutboundTarget):
                await safe_public_get("https://8.8.8.8/start", client=client)


if __name__ == "__main__":
    unittest.main()
