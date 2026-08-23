"""Database + migrations tests."""
from app.core.database import Database


def test_migrations_and_case_roundtrip(tmp_path):
    db = Database(tmp_path / "t.db")
    cid = db.next_case_id()
    assert cid.startswith("CASE-")
    db.save_case({"id": cid, "sender": "a@b.com", "severity": "HIGH",
                  "risk_score": 77, "domains": ["x.com"], "urls": ["http://x"],
                  "tags": ["phishing"], "notes": "n1"})
    case = db.get_case(cid)
    assert case["sender"] == "a@b.com"
    assert case["tags"] == ["phishing"]
    db.delete_case(cid)
    assert db.get_case(cid) is None


def test_dashboard_stats(tmp_path):
    db = Database(tmp_path / "t.db")
    stats = db.dashboard_stats()
    assert {"cases", "emails", "malicious"} <= set(stats.keys())
