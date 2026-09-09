import asyncio
import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from uuid import uuid4


BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))
os.environ.setdefault("DATABASE_URL", "postgresql+psycopg://test:test@localhost/test")
os.environ.setdefault("JWT_SECRET", "test-access-secret-with-sufficient-length")
os.environ.setdefault("JWT_REFRESH_SECRET", "test-refresh-secret-with-sufficient-length")

from app.services.sandbox_manager import (  # noqa: E402
    DockerSimulationProvider,
    SyntheticSimulationProvider,
    get_simulation_provider,
    run_simulation,
)
from app.core.config import settings  # noqa: E402
from app.db.models.simulation import SimulationEvent  # noqa: E402


class SimulationProviderSelectionTests(unittest.TestCase):
    def test_synthetic_mode_selects_the_non_docker_provider(self):
        provider = get_simulation_provider("synthetic")

        self.assertIsInstance(provider, SyntheticSimulationProvider)

    def test_docker_mode_selects_the_existing_docker_provider(self):
        provider = get_simulation_provider("docker")

        self.assertIsInstance(provider, DockerSimulationProvider)

    def test_unknown_mode_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "SIMULATOR_MODE"):
            get_simulation_provider("unsupported")


class SyntheticSimulationBehaviorTests(unittest.IsolatedAsyncioTestCase):
    async def _run(self, sim_type, params):
        simulation = SimpleNamespace(
            id=uuid4(),
            user_id=uuid4(),
            sim_type=sim_type,
            params=params,
            target_url=None,
            raw_output=None,
        )
        db = SimpleNamespace(commit=AsyncMock())
        events = []

        async def emit(event_type, payload, severity="info", details=None):
            events.append({
                "type": event_type,
                "payload": payload,
                "severity": severity,
                "details": details or {},
            })

        await SyntheticSimulationProvider().run(simulation, None, emit, db, None)
        return simulation, events

    async def test_every_non_login_scenario_replays_safe_reference_telemetry(self):
        cases = [
            ("sqli", {"target_url": "http://sandbox-target:5000", "payloads": ["' OR '1'='1' --"]}, "sqli_payload"),
            ("xss", {"target_url": "http://sandbox-target:5000", "payloads": ["<script>alert('sandbox-test')</script>"]}, "xss_payload"),
            ("port_scan", {"target": "sandbox-target", "ports": "1-1024"}, "port_scan"),
            ("vuln_scan", {}, "vulnerability_headers"),
            ("phishing", {"urls": [{"url": "https://micros0ft.test/login", "description": "look-alike"}], "legitimate_domains": ["microsoft.test"]}, "phishing_prompt"),
            ("packet_capture", {"duration_seconds": 1}, "packet_capture_complete"),
            ("social_engineering", {"user_role": "employee"}, "scenario_generated"),
        ]

        for sim_type, params, expected_attack_event in cases:
            with self.subTest(sim_type=sim_type):
                simulation, events = await self._run(sim_type, params)
                event_types = [event["type"] for event in events]

                self.assertEqual(event_types[:3], ["network_created", "starting_target", "target_ready"])
                self.assertIn(expected_attack_event, event_types)
                self.assertEqual(event_types[-1], "cleanup")
                self.assertEqual(simulation.raw_output["provider"], "synthetic")

    async def test_brute_force_replays_each_failed_login_without_a_network_request(self):
        async def record_detection(db, simulation, redis_client, emit):
            await emit("threat_triggered", "Brute-force threat detected", severity="critical")

        with patch("app.services.sandbox_manager._record_brute_force_event", new=record_detection):
            simulation, events = await self._run("brute_force", {
                "attacker_ip": "198.51.100.23",
                "attempts": 3,
                "username": "sandbox-user",
            })

        login_events = [event for event in events if event["type"] == "login_attempt"]
        self.assertEqual(len(login_events), 3)
        self.assertTrue(all(event["details"]["status_code"] == 401 for event in login_events))
        self.assertEqual(simulation.raw_output["provider"], "synthetic")


class _MemoryDb:
    def __init__(self):
        self.added = []

    def add(self, item):
        self.added.append(item)

    async def commit(self):
        return None


class _RecordingQueue:
    def __init__(self):
        self.items = []

    async def put(self, item):
        self.items.append(item)


class SyntheticSimulationRunTests(unittest.IsolatedAsyncioTestCase):
    def _simulation(self, sim_type, params):
        return SimpleNamespace(
            id=uuid4(),
            user_id=uuid4(),
            sim_type=sim_type,
            params=params,
            target_url=None,
            raw_output=None,
            status="queued",
            started_at=None,
            ended_at=None,
            error_message=None,
        )

    async def test_synthetic_run_persists_and_streams_the_same_event_sequence(self):
        simulation = self._simulation("xss", {
            "target_url": "http://sandbox-target:5000",
            "payloads": ["<script>alert('sandbox-test')</script>"],
        })
        db = _MemoryDb()
        queue = _RecordingQueue()

        async def no_detection(*args, **kwargs):
            return None

        with (
            patch.object(settings, "SIMULATOR_MODE", "synthetic"),
            patch("app.services.sandbox_manager.get_event_queue", return_value=queue),
            patch("app.services.sandbox_manager.cleanup_event_queue"),
            patch("app.services.sandbox_manager._record_simulation_detection", new=no_detection),
        ):
            await run_simulation(db, simulation, None)

        persisted = [item for item in db.added if isinstance(item, SimulationEvent)]
        event_types = [event.event_type for event in persisted]
        stream_types = [event["type"] for event in queue.items[:-1]]
        self.assertEqual(simulation.status, "completed")
        self.assertIn("xss_payload", event_types)
        self.assertEqual(stream_types, event_types)
        self.assertIsNone(queue.items[-1])

    async def test_concurrent_synthetic_runs_keep_events_and_results_isolated(self):
        first = self._simulation("sqli", {
            "target_url": "http://sandbox-target:5000",
            "payloads": ["' OR '1'='1' --"],
        })
        second = self._simulation("port_scan", {"target": "sandbox-target", "ports": "5000"})
        first_db, second_db = _MemoryDb(), _MemoryDb()
        queues = {}

        def queue_for(sim_id):
            return queues.setdefault(sim_id, _RecordingQueue())

        async def no_detection(*args, **kwargs):
            return None

        with (
            patch.object(settings, "SIMULATOR_MODE", "synthetic"),
            patch("app.services.sandbox_manager.get_event_queue", side_effect=queue_for),
            patch("app.services.sandbox_manager.cleanup_event_queue"),
            patch("app.services.sandbox_manager._record_simulation_detection", new=no_detection),
        ):
            await asyncio.gather(
                run_simulation(first_db, first, None),
                run_simulation(second_db, second, None),
            )

        first_payloads = [event.payload for event in first_db.added if isinstance(event, SimulationEvent)]
        second_payloads = [event.payload for event in second_db.added if isinstance(event, SimulationEvent)]
        self.assertEqual(first.status, "completed")
        self.assertEqual(second.status, "completed")
        self.assertNotEqual(first.raw_output, second.raw_output)
        self.assertTrue(any("SQL injection" in (payload or "") for payload in first_payloads))
        self.assertTrue(any("nmap scan completed" in (payload or "") for payload in second_payloads))
        self.assertEqual(set(queues), {str(first.id), str(second.id)})
