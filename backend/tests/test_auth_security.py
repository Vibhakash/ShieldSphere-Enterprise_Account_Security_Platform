import os
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch
from uuid import uuid4

from fastapi import HTTPException
from starlette.requests import Request


BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))
os.environ.setdefault("DATABASE_URL", "postgresql+psycopg://test:test@localhost/test")
os.environ.setdefault("JWT_SECRET", "test-access-secret-with-sufficient-length")
os.environ.setdefault("JWT_REFRESH_SECRET", "test-refresh-secret-with-sufficient-length")

from app.core.deps import get_current_user  # noqa: E402
from app.core.config import BACKEND_DIR, settings  # noqa: E402
from app.core.security import create_access_token, decode_access_token  # noqa: E402
from app.api.v1.auth import _record_unknown_account_attempt  # noqa: E402
from app.api.v1.threats import alerts_router  # noqa: E402


def make_request(token: str) -> Request:
    return Request({
        "type": "http",
        "method": "GET",
        "path": "/api/v1/auth/me",
        "headers": [(b"authorization", f"Bearer {token}".encode())],
    })


class AuthenticationBoundaryTests(unittest.IsolatedAsyncioTestCase):
    def test_static_alert_route_precedes_dynamic_alert_route(self):
        patch_routes = [
            route.path
            for route in alerts_router.routes
            if "PATCH" in getattr(route, "methods", set())
        ]
        self.assertLess(
            patch_routes.index("/alerts/read-all"),
            patch_routes.index("/alerts/{alert_id}/read"),
        )

    def test_relative_geoip_path_is_resolved_from_backend(self):
        self.assertTrue(Path(settings.GEOLITE2_DB_PATH).is_absolute())
        self.assertEqual(Path(settings.GEOLITE2_DB_PATH).parent, BACKEND_DIR / "data")

    def test_access_token_round_trip(self):
        user_id = str(uuid4())
        session_id = str(uuid4())
        token = create_access_token({"sub": user_id, "session_id": session_id})

        payload = decode_access_token(token)

        self.assertEqual(payload["sub"], user_id)
        self.assertEqual(payload["session_id"], session_id)
        self.assertEqual(payload["type"], "access")

    async def test_2fa_pending_token_cannot_access_protected_routes(self):
        token = create_access_token({"sub": str(uuid4()), "2fa_pending": True})
        db = AsyncMock()

        with patch("app.core.deps.decode_access_token", return_value=decode_access_token(token)):
            with self.assertRaises(HTTPException) as raised:
                await get_current_user(make_request(token), db)

        self.assertEqual(raised.exception.status_code, 401)
        db.execute.assert_not_awaited()

    async def test_session_query_is_scoped_to_token_user(self):
        user_id = str(uuid4())
        session_id = str(uuid4())
        token = create_access_token({"sub": user_id, "session_id": session_id})
        result = Mock()
        result.scalar_one_or_none.return_value = None
        db = AsyncMock()
        db.execute.return_value = result

        with self.assertRaises(HTTPException):
            await get_current_user(make_request(token), db)

        statement = db.execute.await_args.args[0]
        compiled = statement.compile()
        sql = str(compiled)
        self.assertIn("sessions.user_id", sql)
        self.assertIn(user_id, compiled.params.values())

    async def test_unknown_account_attempt_is_hashed_and_can_block_ip(self):
        db = AsyncMock()
        db.add = Mock()
        no_existing_block = Mock()
        no_existing_block.scalar_one_or_none.return_value = None
        db.execute.return_value = no_existing_block

        pipeline = Mock()
        pipeline.zremrangebyscore.return_value = pipeline
        pipeline.zadd.return_value = pipeline
        pipeline.zcard.return_value = pipeline
        pipeline.expire.return_value = pipeline
        pipeline.execute = AsyncMock(return_value=[0, 1, settings.BRUTE_FORCE_THRESHOLD, True])
        redis_client = Mock()
        redis_client.pipeline.return_value = pipeline
        redis_client.set = AsyncMock()
        request = Request({
            "type": "http", "method": "POST", "path": "/login",
            "headers": [], "client": ("203.0.113.10", 12345),
        })

        await _record_unknown_account_attempt(
            db, redis_client, "Missing.User@example.com", request
        )

        attempt = db.add.call_args_list[0].args[0]
        self.assertIsNone(attempt.user_id)
        self.assertEqual(attempt.failure_reason, "unknown_account")
        self.assertEqual(len(attempt.attempted_identifier_hash), 64)
        self.assertNotIn("missing.user", attempt.attempted_identifier_hash)
        self.assertEqual(db.add.call_count, 2)
        redis_client.set.assert_awaited_once()


if __name__ == "__main__":
    unittest.main()
