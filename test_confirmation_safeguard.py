"""
test_confirmation_safeguard.py
Verifies the confirmation safeguard layer for ZeroTrace sanitization operations.

Test cases:
  (a) Wrong typed confirmation text  → 403, no job created
  (b) Correct text, wrong PIN        → 403, no job created
  (c) Both correct                   → 201, job created, WIPE_AUTHORIZED in audit log
  (d) Audit log contains WIPE_DENIED for failure cases (a) and (b)
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from fastapi.testclient import TestClient
from zerotrace_backend_core_service import app, db


client = TestClient(app)

# Known good values from the seeded data
TARGET_PATH = "/dev/sdb"          # Seagate IronWolf 4TB
METHOD      = "NIST 800-88 Overwrite (3-Pass)"
OPERATOR    = "ZT-OPERATOR-01"
CORRECT_PIN = "801001"


def count_custody_events(event_type: str) -> int:
    """Count how many custody log entries exist for a given event type."""
    return sum(1 for e in db.custody_logs if e.event_type == event_type)


def count_jobs() -> int:
    return len(db.jobs)


# ──────────────────────────────────────────────────────────────────────────────
# Test (a): Wrong typed confirmation → 403, no job
# ──────────────────────────────────────────────────────────────────────────────
def test_wrong_typed_confirmation_rejects():
    jobs_before = count_jobs()
    denied_before = count_custody_events("WIPE_DENIED")

    res = client.post("/api/jobs/confirm", json={
        "target_path":        TARGET_PATH,
        "method":             METHOD,
        "operator_id":        OPERATOR,
        "typed_confirmation": "WIPE /dev/WRONG",   # ← intentionally wrong
        "security_pin":       CORRECT_PIN
    })

    assert res.status_code == 403, f"Expected 403, got {res.status_code}"
    body = res.json()
    assert body["detail"]["error"] == "TYPED_CONFIRMATION_MISMATCH"

    # No job should have been created
    assert count_jobs() == jobs_before, "Job was created despite wrong confirmation text!"

    # A WIPE_DENIED audit entry should exist
    assert count_custody_events("WIPE_DENIED") == denied_before + 1, \
        "WIPE_DENIED was not logged for wrong typed confirmation"

    print("  [PASS] (a) Wrong typed confirmation correctly rejected — no job created")


# ──────────────────────────────────────────────────────────────────────────────
# Test (b): Correct text, wrong PIN → 403, no job
# ──────────────────────────────────────────────────────────────────────────────
def test_correct_text_wrong_pin_rejects():
    jobs_before = count_jobs()
    denied_before = count_custody_events("WIPE_DENIED")

    res = client.post("/api/jobs/confirm", json={
        "target_path":        TARGET_PATH,
        "method":             METHOD,
        "operator_id":        OPERATOR,
        "typed_confirmation": f"WIPE {TARGET_PATH}",   # ← correct
        "security_pin":       "999999"                  # ← wrong PIN
    })

    assert res.status_code == 403, f"Expected 403, got {res.status_code}"
    body = res.json()
    assert body["detail"]["error"] == "SECURITY_PIN_FAILED"

    # No job should have been created
    assert count_jobs() == jobs_before, "Job was created despite wrong PIN!"

    # A WIPE_DENIED audit entry should exist
    assert count_custody_events("WIPE_DENIED") == denied_before + 1, \
        "WIPE_DENIED was not logged for wrong PIN"

    print("  [PASS] (b) Correct text + wrong PIN correctly rejected — no job created")


# ──────────────────────────────────────────────────────────────────────────────
# Test (c): Both correct → 201, job created, WIPE_AUTHORIZED logged
# ──────────────────────────────────────────────────────────────────────────────
def test_both_correct_creates_job():
    jobs_before = count_jobs()
    authorized_before = count_custody_events("WIPE_AUTHORIZED")

    res = client.post("/api/jobs/confirm", json={
        "target_path":        TARGET_PATH,
        "method":             METHOD,
        "operator_id":        OPERATOR,
        "typed_confirmation": f"WIPE {TARGET_PATH}",
        "security_pin":       CORRECT_PIN
    })

    assert res.status_code == 201, f"Expected 201, got {res.status_code}"
    body = res.json()
    assert body["status"] == "AUTHORIZED"
    assert "job_id" in body
    assert body["target_path"] == TARGET_PATH

    # Exactly one new job should have been created
    assert count_jobs() == jobs_before + 1, "Job was NOT created after valid confirmation!"

    # A WIPE_AUTHORIZED audit entry should exist
    assert count_custody_events("WIPE_AUTHORIZED") == authorized_before + 1, \
        "WIPE_AUTHORIZED was not logged"

    print(f"  [PASS] (c) Both checks passed — job {body['job_id']} created, WIPE_AUTHORIZED logged")


# ──────────────────────────────────────────────────────────────────────────────
# Test (d): Summary audit-log verification for WIPE_DENIED across (a) and (b)
# ──────────────────────────────────────────────────────────────────────────────
def test_audit_log_contains_denial_entries():
    denied_count = count_custody_events("WIPE_DENIED")
    assert denied_count >= 2, \
        f"Expected at least 2 WIPE_DENIED entries from tests (a)+(b), found {denied_count}"
    print(f"  [PASS] (d) Audit log contains {denied_count} WIPE_DENIED entries as expected")


# ──────────────────────────────────────────────────────────────────────────────
# Runner
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("  ZEROTRACE — Confirmation Safeguard Test Suite")
    print("=" * 70 + "\n")

    test_wrong_typed_confirmation_rejects()
    test_correct_text_wrong_pin_rejects()
    test_both_correct_creates_job()
    test_audit_log_contains_denial_entries()

    print("\n" + "-" * 70)
    print("  ALL 4 TESTS PASSED")
    print("-" * 70 + "\n")
