import os
import sys
import unittest
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))
os.environ.setdefault("DATABASE_URL", "postgresql+psycopg://test:test@localhost/test")
os.environ.setdefault("JWT_SECRET", "test-access-secret-with-sufficient-length")
os.environ.setdefault("JWT_REFRESH_SECRET", "test-refresh-secret-with-sufficient-length")

from app.services.sandbox_manager import _levenshtein_distance  # noqa: E402
from app.api.v1.simulator import (  # noqa: E402
    _score_phishing_answers,
    _score_social_engineering_answer,
)


class SimulatorUtilityTests(unittest.TestCase):
    def test_levenshtein_distance_matches_expected_domain_similarity(self):
        self.assertEqual(_levenshtein_distance("paypa1.com", "paypal.com"), 1)
        self.assertEqual(_levenshtein_distance("example.com", "example.com"), 0)
        self.assertEqual(_levenshtein_distance("abc", "xyz"), 3)

    def test_scores_social_choice_from_persisted_scenario(self):
        raw_output = {"scenario": {"options": [
            {"id": "A", "is_correct": False, "explanation": "Unsafe"},
            {"id": "B", "is_correct": True, "explanation": "Safe"},
        ]}}

        correct, total, feedback = _score_social_engineering_answer(raw_output, {"choice": "b"})

        self.assertEqual((correct, total), (1, 1))
        self.assertTrue(feedback[0]["correct"])

    def test_scores_every_persisted_phishing_challenge_item(self):
        raw_output = {"challenge_items": [
            {"id": "url_1", "expected": "phishing", "domain": "paypa1.com", "levenshtein_distance": 1},
            {"id": "url_2", "expected": "legitimate", "domain": "paypal.com", "levenshtein_distance": 0},
        ]}

        correct, total, feedback = _score_phishing_answers(raw_output, {
            "url_1": "phishing", "url_2": "legitimate",
        })

        self.assertEqual((correct, total), (2, 2))
        self.assertEqual(len(feedback), 2)


if __name__ == "__main__":
    unittest.main()
