import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock
from uuid import uuid4


BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))
os.environ.setdefault("DATABASE_URL", "postgresql+psycopg://test:test@localhost/test")
os.environ.setdefault("JWT_SECRET", "test-access-secret-with-sufficient-length")
os.environ.setdefault("JWT_REFRESH_SECRET", "test-refresh-secret-with-sufficient-length")

from app.services.security_score import recalculate_security_score  # noqa: E402


def scalar_result(value):
    result = Mock()
    result.scalar_one.return_value = value
    return result


class SecurityScoreTests(unittest.IsolatedAsyncioTestCase):
    async def test_score_uses_current_security_state_and_persists_factors(self):
        user = SimpleNamespace(
            id=uuid4(),
            totp_enabled=True,
            password_breached=False,
            password_breach_count=0,
        )
        db = AsyncMock()
        db.add = Mock()
        # unresolved threats, trusted devices, active sessions
        db.execute.side_effect = [scalar_result(2), scalar_result(1), scalar_result(7)]

        record = await recalculate_security_score(db, user)

        self.assertEqual(record.score, 69)
        self.assertEqual(record.factors["unresolved_threats"]["penalty"], -20)
        self.assertEqual(record.factors["active_sessions"]["penalty"], -6)
        db.add.assert_called_once_with(record)
        db.commit.assert_awaited_once()
        db.refresh.assert_awaited_once_with(record)


if __name__ == "__main__":
    unittest.main()
