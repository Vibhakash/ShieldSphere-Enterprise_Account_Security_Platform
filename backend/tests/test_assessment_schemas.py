import os
import sys
import unittest
from pathlib import Path

from pydantic import ValidationError


BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))
os.environ.setdefault("DATABASE_URL", "postgresql+psycopg://test:test@localhost/test")
os.environ.setdefault("JWT_SECRET", "test-access-secret-with-sufficient-length")
os.environ.setdefault("JWT_REFRESH_SECRET", "test-refresh-secret-with-sufficient-length")

from app.schemas.common import IpReputationRequest  # noqa: E402


class IpReputationRequestTests(unittest.TestCase):
    def test_ipv4_is_accepted(self):
        self.assertEqual(IpReputationRequest(ip="8.8.8.8").ip, "8.8.8.8")

    def test_ipv6_is_normalized(self):
        self.assertEqual(IpReputationRequest(ip="2001:0db8::1").ip, "2001:db8::1")

    def test_hostnames_are_rejected(self):
        with self.assertRaises(ValidationError):
            IpReputationRequest(ip="localhost")


if __name__ == "__main__":
    unittest.main()
