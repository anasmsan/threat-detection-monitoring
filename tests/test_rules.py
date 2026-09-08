"""
Tests unitaires du moteur de détection, sans dépendre d'un vrai cluster
Elasticsearch : un faux client (FakeES) rejoue des réponses de recherche
construites à la main, pour vérifier la logique des règles en isolation.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "detection_engine"))

from rules import rule_ssh_brute_force, rule_web_scanning, rule_injection_attempts  # noqa: E402


class FakeES:
    def __init__(self, hits):
        self._hits = hits

    def search(self, index, query, size=1000, sort=None):
        return {"hits": {"hits": [{"_source": h} for h in self._hits]}}


def _ssh_line(status: str, ip: str) -> str:
    if status == "failed":
        return f"Sep 08 10:00:00 host sshd[1]: Failed password for admin from {ip} port 12345 ssh2"
    return f"Sep 08 10:00:00 host sshd[1]: Accepted password for admin from {ip} port 12345 ssh2"


def test_ssh_brute_force_triggers_above_threshold():
    hits = [{"log_source": "ssh", "message": _ssh_line("failed", "10.0.0.5")} for _ in range(6)]
    es = FakeES(hits)
    alerts = rule_ssh_brute_force(es)
    assert len(alerts) == 1
    assert alerts[0]["source_ip"] == "10.0.0.5"
    assert alerts[0]["mitre_technique"].startswith("T1110")
    assert alerts[0]["account_compromised"] is False


def test_ssh_brute_force_flags_compromise_when_followed_by_success():
    hits = [{"log_source": "ssh", "message": _ssh_line("failed", "10.0.0.5")} for _ in range(6)]
    hits.append({"log_source": "ssh", "message": _ssh_line("success", "10.0.0.5")})
    es = FakeES(hits)
    alerts = rule_ssh_brute_force(es)
    assert alerts[0]["account_compromised"] is True
    assert alerts[0]["severity"] == "critical"


def test_ssh_brute_force_does_not_trigger_below_threshold():
    hits = [{"log_source": "ssh", "message": _ssh_line("failed", "10.0.0.5")} for _ in range(2)]
    es = FakeES(hits)
    assert rule_ssh_brute_force(es) == []


def test_web_scanning_triggers_on_many_404s_from_same_ip():
    hits = [{"log_source": "webapp", "status": 404, "client_ip": "1.2.3.4", "path": f"/x{i}"} for i in range(10)]
    es = FakeES(hits)
    alerts = rule_web_scanning(es)
    assert len(alerts) == 1
    assert alerts[0]["mitre_technique"].startswith("T1595")


def test_injection_detected_even_when_url_encoded_with_plus_signs():
    hits = [{"log_source": "webapp", "path": "/search", "client_ip": "9.9.9.9",
             "query": "q=%27+OR+%271%27%3D%271"}]
    es = FakeES(hits)
    alerts = rule_injection_attempts(es)
    assert len(alerts) == 1
    assert alerts[0]["mitre_technique"].startswith("T1190")


def test_no_false_positive_on_legitimate_query():
    hits = [{"log_source": "webapp", "path": "/search", "client_ip": "9.9.9.9", "query": "q=clavier+sans+fil"}]
    es = FakeES(hits)
    assert rule_injection_attempts(es) == []
