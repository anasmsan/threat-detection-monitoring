"""
Application cible volontairement simple : son seul rôle dans ce projet est de
générer un flux de logs d'accès réalistes (JSON structuré), que les scripts
de l'attack_simulator vont ensuite bombarder de trafic normal et malveillant,
pour donner de la vraie matière au moteur de détection.
"""
import json
import logging
import time
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from prometheus_fastapi_instrumentator import Instrumentator

LOG_PATH = Path("/var/log/webapp/access.log")
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

access_logger = logging.getLogger("access")
access_logger.setLevel(logging.INFO)
handler = logging.FileHandler(LOG_PATH)
handler.setFormatter(logging.Formatter("%(message)s"))
access_logger.addHandler(handler)

app = FastAPI(title="Webapp cible (démo)")

# Expose /metrics au format Prometheus (requêtes par endpoint, latences, codes
# de statut) : Prometheus vient "scraper" (récupérer périodiquement) cette
# route toutes les quelques secondes.
Instrumentator().instrument(app).expose(app)

FAKE_USERS = {"alice": "hunter2", "bob": "correcthorse"}
FAKE_PRODUCTS = {1: "Clavier mécanique", 2: "Souris sans fil", 3: "Écran 27 pouces"}


@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.time()
    response = await call_next(request)
    entry = {
        "@timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + "Z",
        "client_ip": request.headers.get("x-forwarded-for", request.client.host),
        "method": request.method,
        "path": str(request.url.path),
        "query": str(request.url.query),
        "status": response.status_code,
        "duration_ms": round((time.time() - start) * 1000, 2),
    }
    access_logger.info(json.dumps(entry))
    return response


@app.get("/")
def home():
    return {"message": "Boutique de démo"}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/products/{product_id}")
def get_product(product_id: int):
    name = FAKE_PRODUCTS.get(product_id)
    if name is None:
        return JSONResponse(status_code=404, content={"detail": "Produit introuvable"})
    return {"id": product_id, "name": name}


@app.post("/login")
def login(username: str, password: str):
    # Volontairement une comparaison simple : ce n'est PAS l'application à
    # sécuriser (voir le projet "API de paiement sécurisée" pour ça), c'est
    # juste une cible réaliste pour générer du trafic à surveiller.
    if FAKE_USERS.get(username) == password:
        return {"status": "ok"}
    return JSONResponse(status_code=401, content={"detail": "Identifiants invalides"})


@app.get("/search")
def search(q: str = ""):
    return {"query": q, "results": []}
