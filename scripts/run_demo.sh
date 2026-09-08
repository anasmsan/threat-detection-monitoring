#!/usr/bin/env bash
# Rejoue l'intégralité de la démonstration : lance les attaques simulées puis
# le moteur de détection, et affiche les alertes obtenues.
set -euo pipefail
cd "$(dirname "$0")/.."
source .venv/bin/activate

echo "=== 1/3 — Simulation d'une attaque par force brute SSH (T1110) ==="
python attack_simulator/ssh_bruteforce.py

echo ""
echo "=== 2/3 — Simulation d'un scan de reconnaissance + tentatives d'injection ==="
python attack_simulator/web_scan.py

echo ""
echo "=== Pause pour laisser Filebeat acheminer les logs vers Elasticsearch ==="
sleep 10

echo ""
echo "=== 3/3 — Exécution du moteur de détection ==="
python detection_engine/rules.py

echo ""
echo "Tableau de bord Grafana : http://localhost:3000 (admin/admin)"
echo "Kibana                  : http://localhost:5601"
