"""
Moteur de détection : interroge Elasticsearch à la demande (on pourrait aussi
le lancer en boucle toutes les X secondes via un cron) et applique des règles
explicites, chacune reliée à une technique documentée du référentiel
MITRE ATT&CK — un standard de l'industrie qui catalogue les techniques
d'attaque connues, pour que chaque détection ait un nom et une source
reconnus plutôt qu'être une intuition ad hoc.

Chaque alerte détectée est à la fois affichée et indexée dans Elasticsearch
(index "security-alerts"), pour pouvoir être visualisée dans Kibana/Grafana
comme n'importe quelle autre donnée.
"""
import re
from collections import defaultdict
from datetime import datetime, timezone
from urllib.parse import unquote_plus

from elasticsearch import Elasticsearch

ES_URL = "http://localhost:9200"
LOG_INDEX_PATTERN = "security-logs-*"
ALERT_INDEX = "security-alerts"

BRUTE_FORCE_THRESHOLD = 5      # échecs SSH depuis la même IP
SCAN_THRESHOLD = 8             # 404 depuis la même IP
INJECTION_PATTERNS = [
    r"union\s+select", r"or\s+'1'\s*=\s*'1", r"drop\s+table",
    r"\.\./", r"<script", r"etc/passwd",
]

FAILED_SSH_RE = re.compile(r"Failed password for(?:\s+invalid user)?\s+(\S+) from (\d+\.\d+\.\d+\.\d+)")
ACCEPTED_SSH_RE = re.compile(r"Accepted password for (\S+) from (\d+\.\d+\.\d+\.\d+)")


def get_client() -> Elasticsearch:
    return Elasticsearch(ES_URL)


def rule_ssh_brute_force(es: Elasticsearch) -> list[dict]:
    """T1110 - Brute Force : trop d'échecs d'authentification SSH depuis une même IP."""
    resp = es.search(
        index=LOG_INDEX_PATTERN,
        query={"bool": {"filter": [{"term": {"log_source": "ssh"}}]}},
        size=1000,
        sort=[{"@timestamp": "asc"}],
    )
    failures_by_ip = defaultdict(list)
    successes_by_ip = defaultdict(list)
    for hit in resp["hits"]["hits"]:
        message = hit["_source"].get("message", "")
        m = FAILED_SSH_RE.search(message)
        if m:
            user, ip = m.groups()
            failures_by_ip[ip].append(user)
            continue
        m = ACCEPTED_SSH_RE.search(message)
        if m:
            user, ip = m.groups()
            successes_by_ip[ip].append(user)

    alerts = []
    for ip, attempts in failures_by_ip.items():
        if len(attempts) >= BRUTE_FORCE_THRESHOLD:
            compromised = ip in successes_by_ip
            alerts.append({
                "rule": "ssh_brute_force",
                "mitre_technique": "T1110 - Brute Force",
                "severity": "critical" if compromised else "high",
                "source_ip": ip,
                "details": (
                    f"{len(attempts)} échecs d'authentification SSH depuis {ip}"
                    + (f", PUIS connexion réussie : compte probablement compromis." if compromised else ".")
                ),
                "count": len(attempts),
                "account_compromised": compromised,
            })
    return alerts


def rule_web_scanning(es: Elasticsearch) -> list[dict]:
    """T1595 - Active Scanning : rafale de réponses 404 depuis une même IP."""
    resp = es.search(
        index=LOG_INDEX_PATTERN,
        query={"bool": {"filter": [
            {"term": {"log_source": "webapp"}},
            {"term": {"status": 404}},
        ]}},
        size=1000,
    )
    by_ip = defaultdict(list)
    for hit in resp["hits"]["hits"]:
        src = hit["_source"]
        by_ip[src.get("client_ip", "unknown")].append(src.get("path"))

    alerts = []
    for ip, paths in by_ip.items():
        if len(paths) >= SCAN_THRESHOLD:
            alerts.append({
                "rule": "web_path_scanning",
                "mitre_technique": "T1595 - Active Scanning",
                "severity": "medium",
                "source_ip": ip,
                "details": f"{len(paths)} requêtes vers des chemins inexistants (404) depuis {ip} : "
                           f"comportement typique d'un outil de reconnaissance (ex: gobuster/dirbuster).",
                "count": len(paths),
                "sample_paths": paths[:5],
            })
    return alerts


def rule_injection_attempts(es: Elasticsearch) -> list[dict]:
    """Tentative d'exploitation via l'entrée utilisateur (SQLi, traversée de répertoire, XSS)."""
    resp = es.search(
        index=LOG_INDEX_PATTERN,
        query={"bool": {"filter": [{"term": {"log_source": "webapp"}}]}},
        size=1000,
    )
    alerts = []
    for hit in resp["hits"]["hits"]:
        src = hit["_source"]
        # Les requêtes HTTP arrivent encodées dans les logs : les caractères
        # spéciaux en %XX (ex: %27 pour l'apostrophe) ET les espaces en "+".
        # unquote() seul décode les %XX mais laisse les "+" tels quels — un
        # payload comme "OR+'1'='1" ne matchait alors aucun pattern à cause
        # de ce "+" au lieu d'un espace. unquote_plus() gère les deux à la fois.
        query = unquote_plus(src.get("query") or "")
        for pattern in INJECTION_PATTERNS:
            if re.search(pattern, query, re.IGNORECASE):
                alerts.append({
                    "rule": "injection_attempt",
                    "mitre_technique": "T1190 - Exploit Public-Facing Application",
                    "severity": "critical",
                    "source_ip": src.get("client_ip", "unknown"),
                    "details": f"Payload suspect détecté dans une requête vers {src.get('path')} : {query[:120]}",
                    "matched_pattern": pattern,
                })
                break
    return alerts


def run_all_rules(es: Elasticsearch) -> list[dict]:
    alerts = []
    alerts += rule_ssh_brute_force(es)
    alerts += rule_web_scanning(es)
    alerts += rule_injection_attempts(es)
    now = datetime.now(timezone.utc).isoformat()
    for alert in alerts:
        alert["@timestamp"] = now
    return alerts


def index_alerts(es: Elasticsearch, alerts: list[dict]) -> None:
    for alert in alerts:
        es.index(index=ALERT_INDEX, document=alert)


def main():
    es = get_client()
    alerts = run_all_rules(es)
    if not alerts:
        print("Aucune alerte détectée.")
        return

    print(f"=== {len(alerts)} alerte(s) détectée(s) ===\n")
    for a in alerts:
        print(f"[{a['severity'].upper()}] {a['mitre_technique']}")
        print(f"   Règle      : {a['rule']}")
        print(f"   IP source  : {a['source_ip']}")
        print(f"   Détail     : {a['details']}")
        print()

    index_alerts(es, alerts)
    print(f"Alertes indexées dans Elasticsearch (index '{ALERT_INDEX}').")


if __name__ == "__main__":
    main()
