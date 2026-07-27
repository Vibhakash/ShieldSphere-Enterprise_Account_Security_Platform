"""Real local PostgreSQL and Redis integration coverage.

Set RUN_BACKEND_INTEGRATION_TESTS=1 to enable. Each test owns uniquely named
records and removes them in teardown.
"""
import os
import sys
import asyncio
import unittest
from pathlib import Path
from uuid import uuid4

from sqlalchemy import delete, select


if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))
# Integration tests intentionally use backend/.env, unless the caller supplies
# real service credentials through environment variables. They must never
# inherit the placeholder database URL used by the isolated unit-test modules.

from app.core.config import settings  # noqa: E402
from app.db.models.device import Device  # noqa: E402
from app.db.models.security import SecurityScore  # noqa: E402
from app.db.models.session import UserSession  # noqa: E402
from app.db.models.user import User  # noqa: E402
from app.db.session import AsyncSessionLocal  # noqa: E402
from app.services.security_score import recalculate_security_score  # noqa: E402
import redis.asyncio as aioredis  # noqa: E402


@unittest.skipUnless(
    os.getenv("RUN_BACKEND_INTEGRATION_TESTS") == "1",
    "set RUN_BACKEND_INTEGRATION_TESTS=1 to run local PostgreSQL/Redis integration tests",
)
class PostgreSqlRedisIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.token = uuid4().hex
        self.user_id = uuid4()
        self.redis_key = f"shieldsphere:integration:{self.token}"
        self.db = AsyncSessionLocal()
        self.redis = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
        try:
            await self.redis.ping()
            self.user = User(
                id=self.user_id,
                email=f"integration-{self.token}@example.invalid",
                username=f"int_{self.token[:20]}",
                hashed_password="integration-test-only-not-a-login-secret",
                totp_enabled=True,
                totp_secret="integration-test-totp-secret",
                password_breached=False,
            )
            self.db.add(self.user)
            await self.db.commit()
        except Exception:
            await self.redis.aclose()
            await self.db.close()
            raise

    async def asyncTearDown(self):
        try:
            await self.redis.delete(self.redis_key)
            await self.db.execute(delete(User).where(User.id == self.user_id))
            await self.db.commit()
        finally:
            await self.redis.aclose()
            await self.db.close()

    async def test_postgres_security_score_persists_real_related_rows(self):
        self.db.add(Device(
            user_id=self.user_id,
            device_id=f"trusted-{self.token}",
            is_trusted=True,
        ))
        self.db.add(UserSession(
            user_id=self.user_id,
            device_id=f"session-{self.token}",
            is_active=True,
        ))
        await self.db.commit()

        score = await recalculate_security_score(self.db, self.user)
        result = await self.db.execute(
            select(SecurityScore).where(SecurityScore.id == score.id)
        )
        persisted = result.scalar_one()

        self.assertEqual(persisted.score, 95)
        self.assertEqual(persisted.factors["trusted_devices"]["count"], 1)
        self.assertEqual(persisted.factors["active_sessions"]["count"], 1)

    async def test_redis_sorted_set_window_operations_are_available(self):
        await self.redis.zadd(self.redis_key, {"attempt-1": 1, "attempt-2": 2})
        await self.redis.zremrangebyscore(self.redis_key, 0, 1)

        self.assertEqual(await self.redis.zcard(self.redis_key), 1)
        self.assertEqual(await self.redis.zrange(self.redis_key, 0, -1), ["attempt-2"])


if __name__ == "__main__":
    unittest.main()
