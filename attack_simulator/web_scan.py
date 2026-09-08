"""
Simule deux techniques MITRE ATT&CK contre la webapp de démonstration :
- T1595 (Active Scanning) : rafale de requêtes sur des chemins qui n'existent
  pas, comme le ferait un outil de reconnaissance (ex: dirbuster/gobuster)
  cherchant des pages cachées.
- T1190-like (tentative d'exploitation via l'entrée utilisateur) : injection
  de payloads classiques (SQLi, traversée de répertoire) dans le paramètre de
  recherche.
Un peu de trafic légitime est aussi généré, pour que la détection doive
vraiment distinguer le normal de l'anormal plutôt que de tout signaler.
"""
import random
import time

import requests

BASE_URL = "http://localhost:8000"

SCAN_PATHS = [
    "/admin", "/.env", "/wp-login.php", "/backup.zip", "/config.php",
    "/.git/config", "/phpmyadmin", "/server-status", "/debug", "/console",
    "/api/v1/users", "/.aws/credentials", "/shell.php", "/test", "/old",
    "/backup", "/db.sql", "/.htaccess", "/private", "/secret", "/hidden",
    "/uploads", "/tmp", "/logs", "/api/internal", "/actuator/health",
]

INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "' UNION SELECT username, password FROM users--",
    "1; DROP TABLE users;--",
    "../../../../etc/passwd",
    "<script>alert(document.cookie)</script>",
]


def normal_traffic(n=10):
    print(f"=== Génération de {n} requêtes normales (bruit de fond légitime) ===")
    for _ in range(n):
        pid = random.choice([1, 2, 3])
        requests.get(f"{BASE_URL}/products/{pid}", timeout=5)
        requests.get(f"{BASE_URL}/search", params={"q": "clavier"}, timeout=5)
        time.sleep(0.3)


def scanning_attack():
    attacker_ip = "203.0.113.66"  # IP de démonstration (plage documentaire RFC 5737)
    print(f"=== Simulation de scan de chemins depuis {attacker_ip} (T1595) ===")
    for path in SCAN_PATHS:
        try:
            requests.get(f"{BASE_URL}{path}", headers={"X-Forwarded-For": attacker_ip}, timeout=5)
        except requests.RequestException:
            pass
        time.sleep(0.1)  # rafale rapide : c'est justement ce qui la rend détectable


def injection_attack():
    attacker_ip = "203.0.113.77"
    print(f"=== Simulation de tentatives d'injection depuis {attacker_ip} ===")
    for payload in INJECTION_PAYLOADS:
        try:
            requests.get(
                f"{BASE_URL}/search", params={"q": payload},
                headers={"X-Forwarded-For": attacker_ip}, timeout=5,
            )
        except requests.RequestException:
            pass
        time.sleep(0.2)


if __name__ == "__main__":
    normal_traffic()
    scanning_attack()
    injection_attack()
    print("\nTerminé.")
