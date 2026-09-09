"""Live PostgreSQL coverage for synthetic simulator persistence.

Set RUN_SYNTHETIC_POSTGRES_TESTS=1 to run.  The test creates a uniquely named
user and relies on the database's cascade deletes to remove the simulation and
its events during teardown.
"""
import os
import sys
import unittest
import asyncio
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from sqlalchemy import delete, select


if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from app.core.config import settings  # noqa: E402
from app.db.models.simulation import AttackSimulation, SimulationEvent  # noqa: E402
from app.db.models.user import User  # noqa: E402
from app.db.session import AsyncSessionLocal, engine  # noqa: E402
from app.services.sandbox_manager import run_simulation  # noqa: E402


@unittest.skipUnless(
    os.getenv("RUN_SYNTHETIC_POSTGRES_TESTS") == "1",
    "set RUN_SYNTHETIC_POSTGRES_TESTS=1 to run live PostgreSQL synthetic simulator coverage",
)
class SyntheticSimulatorPostgresTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.token = uuid4().hex
        self.user_id = uuid4()
        self._engine_echo = engine.echo
        engine.echo = False
        self.db = AsyncSessionLocal()
        self.user = User(
            id=self.user_id,
            email=f"synthetic-simulator-{self.token}@example.invalid",
            username=f"syn_{self.token[:20]}",
            hashed_password="synthetic-simulator-test-only",
            totp_enabled=True,
            totp_secret="synthetic-simulator-test-totp-secret",
            password_breached=False,
        )
        self.db.add(self.user)
        await self.db.commit()

    async def asyncTearDown(self):
        try:
            await self.db.execute(delete(User).where(User.id == self.user_id))
            await self.db.commit()
        finally:
            await self.db.close()
            engine.echo = self._engine_echo

    async def test_synthetic_xss_persists_staged_events_without_docker_or_redis(self):
        simulation = AttackSimulation(
            user_id=self.user_id,
            sim_type="xss",
            params={
                "target_url": "http://sandbox-target:5000",
                "payloads": ["<script>alert('sandbox-test')</script>"],
            },
            status="queued",
        )
        self.db.add(simulation)
        await self.db.commit()
        await self.db.refresh(simulation)

        async def no_detection(*args, **kwargs):
            return None

        with (
            patch.object(settings, "SIMULATOR_MODE", "synthetic"),
            patch("app.services.sandbox_manager._record_simulation_detection", new=no_detection),
        ):
            await run_simulation(self.db, simulation, redis_client=None)

        events = (await self.db.execute(
            select(SimulationEvent)
            .where(SimulationEvent.simulation_id == simulation.id)
            .order_by(SimulationEvent.timestamp.asc())
        )).scalars().all()

        self.assertEqual(simulation.status, "completed")
        self.assertTrue(any(event.event_type == "xss_payload" for event in events))
        self.assertEqual(simulation.raw_output["provider"], "synthetic")
