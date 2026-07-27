"""Manual smoke test for login and key API routes.

Supply credentials through environment variables; never commit test passwords.
"""

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request


BASE = os.getenv("SMOKE_TEST_API_BASE", "http://127.0.0.1:8000/api/v1").rstrip("/")
TEST_EMAIL = os.getenv("SMOKE_TEST_EMAIL")
TEST_PASSWORD = os.getenv("SMOKE_TEST_PASSWORD")


def request(method, path, data=None, token=None, params=None):
    url = f"{BASE}{path}"
    if params:
        url = f"{url}?{urllib.parse.urlencode(params)}"
    payload = json.dumps(data).encode() if data is not None else None
    headers = {"Content-Type": "application/json"} if payload else {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=payload, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


if not TEST_EMAIL or not TEST_PASSWORD:
    raise SystemExit(
        "Set SMOKE_TEST_EMAIL and SMOKE_TEST_PASSWORD in your shell. "
        "Never store credentials in this file."
    )

print("=== Testing ShieldSphere API ===")
started = time.time()
status, body = request(
    "POST",
    "/auth/login",
    {"email": TEST_EMAIL, "password": TEST_PASSWORD},
)
token = body.get("access_token") if status == 200 else None
if not token:
    raise SystemExit(f"Login failed with HTTP {status} in {time.time() - started:.2f}s.")
print(f"Login succeeded in {time.time() - started:.2f}s.")

endpoints = [
    ("/dashboard/stats", None),
    ("/dashboard/security-score", None),
    ("/threats", {"page": 1, "per_page": 5}),
    ("/sessions", {"page": 1, "per_page": 5}),
    ("/compliance/audit-logs", {"per_page": 5}),
    ("/reports", None),
    ("/assessment/url-scans", None),
    ("/assessment/ip-reputation", None),
]
failed = []
for endpoint, params in endpoints:
    status, _ = request("GET", endpoint, token=token, params=params)
    print(f"GET {endpoint}: HTTP {status}")
    if status != 200:
        failed.append(endpoint)

if failed:
    raise SystemExit(f"Smoke test failed for {len(failed)} endpoint(s).")
print("=== Smoke test passed ===")
