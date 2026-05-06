"""
OAuth2 Cloud Run app para MercadoLibre y MercadoPago.

Flujo:
  1. Backoffice redirige a GET /auth/{service}/login?user_id=X&agent_id=Y
  2. Esta app redirige al usuario a ML/MP authorization
  3. ML/MP redirige a GET /auth/{service}/callback?code=Z&state=S
  4. Intercambia code por tokens, guarda temporalmente con short_code
  5. Envía WA al número del bot: "CAPITAN_OAUTH:{service}:{short_code}"
  6. Core del backend llama GET /tokens/{short_code} para retirar el token
  7. Core persiste el token para el user_id correspondiente
"""
from __future__ import annotations
import json
import logging
import os
import secrets
import threading
import time
import urllib.parse
import urllib.request
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, RedirectResponse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Capitan OAuth App", version="1.0.0")

# ── Config ─────────────────────────────────────────────────────────────────────

_STATE_TTL = int(os.environ.get("STATE_TTL", "600"))
_TOKEN_TTL  = int(os.environ.get("TOKEN_TTL", "300"))

_SERVICES: dict[str, dict[str, str]] = {
    "ml": {
        "auth_url":     "https://auth.mercadolibre.com.uy/authorization",
        "token_url":    "https://api.mercadolibre.com/oauth/token",
        "me_url":       "https://api.mercadolibre.com/users/me",
        "client_id":    os.environ.get("ML_CLIENT_ID", ""),
        "client_secret": os.environ.get("ML_CLIENT_SECRET", ""),
        "redirect_uri": os.environ.get("ML_REDIRECT_URI", ""),
        "label":        "MercadoLibre",
    },
    "mp": {
        "auth_url":     "https://auth.mercadopago.com.uy/authorization",
        "token_url":    "https://api.mercadopago.com/oauth/token",
        "me_url":       "https://api.mercadopago.com/users/me",
        "client_id":    os.environ.get("MP_CLIENT_ID", ""),
        "client_secret": os.environ.get("MP_CLIENT_SECRET", ""),
        "redirect_uri": os.environ.get("MP_REDIRECT_URI", ""),
        "label":        "MercadoPago",
    },
}

_WA_ACCESS_TOKEN    = os.environ.get("WA_ACCESS_TOKEN", "")
_WA_PHONE_NUMBER_ID = os.environ.get("WA_PHONE_NUMBER_ID", "")
_BOT_WA_PHONE       = os.environ.get("BOT_WA_PHONE", "").replace("+", "").replace(" ", "")

# ── In-memory stores (TTL enforced on read) ────────────────────────────────────

_lock           = threading.Lock()
_pending_states: dict[str, dict[str, Any]] = {}
_pending_tokens: dict[str, dict[str, Any]] = {}


def _prune(store: dict, now: float) -> None:
    expired = [k for k, v in store.items() if v.get("expires_at", 0) < now]
    for k in expired:
        del store[k]


def _get_service(service: str) -> dict[str, str]:
    svc = _SERVICES.get(service)
    if not svc:
        raise HTTPException(status_code=404, detail=f"Servicio '{service}' desconocido")
    if not svc["client_id"] or not svc["client_secret"]:
        raise HTTPException(status_code=503, detail=f"Credenciales de {service.upper()} no configuradas")
    if not svc["redirect_uri"]:
        raise HTTPException(status_code=503, detail=f"{service.upper()}_REDIRECT_URI no configurado")
    return svc


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/auth/{service}/login")
def login(
    service:  str,
    user_id:  str = Query(...),
    agent_id: str = Query(default=""),
) -> RedirectResponse:
    """Genera state y redirige al usuario a la página de autorización de ML/MP."""
    svc = _get_service(service)
    state = secrets.token_urlsafe(24)
    now   = time.time()

    with _lock:
        _prune(_pending_states, now)
        _pending_states[state] = {
            "user_id":    user_id,
            "agent_id":   agent_id,
            "service":    service,
            "expires_at": now + _STATE_TTL,
        }

    params = {
        "response_type": "code",
        "client_id":     svc["client_id"],
        "redirect_uri":  svc["redirect_uri"],
        "state":         state,
    }
    url = f"{svc['auth_url']}?{urllib.parse.urlencode(params)}"
    logger.info("[%s] login redirect para user=%s state=%s", service, user_id, state)
    return RedirectResponse(url, status_code=302)


@app.get("/ml/oauth2")
def callback_ml(
    code:  str = Query(default=""),
    state: str = Query(default=""),
    error: str = Query(default=""),
) -> HTMLResponse:
    return callback("ml", code, state, error)


@app.get("/mp/oauth2")
def callback_mp(
    code:  str = Query(default=""),
    state: str = Query(default=""),
    error: str = Query(default=""),
) -> HTMLResponse:
    return callback("mp", code, state, error)


@app.get("/auth/{service}/callback")
def callback(
    service: str,
    code:    str = Query(default=""),
    state:   str = Query(default=""),
    error:   str = Query(default=""),
) -> HTMLResponse:
    """Recibe el callback de ML/MP, intercambia code por tokens, notifica al bot."""
    if error or not code or not state:
        return _html_error(f"Error en la autorización: {error or 'sin código'}")

    svc = _get_service(service)
    now = time.time()

    with _lock:
        entry = _pending_states.pop(state, None)
    if not entry or entry["expires_at"] < now:
        return _html_error("Estado OAuth inválido o expirado. Iniciá el proceso nuevamente.")

    user_id  = entry["user_id"]
    agent_id = entry["agent_id"]
    label    = svc["label"]

    token_data = _exchange_code(svc, code)
    if not token_data:
        return _html_error("No se pudo intercambiar el código de autorización.")

    # Resolver el user_id remoto (ML/MP user ID)
    api_user_id = _fetch_me_user_id(svc, token_data.get("access_token", ""))

    short_code = secrets.token_urlsafe(24)
    with _lock:
        _prune(_pending_tokens, now)
        _pending_tokens[short_code] = {
            "user_id":       user_id,
            "agent_id":      agent_id,
            "service":       service,
            "access_token":  token_data.get("access_token", ""),
            "refresh_token": token_data.get("refresh_token", ""),
            "expires_in":    token_data.get("expires_in", 21600),
            "api_user_id":   api_user_id,
            "expires_at":    now + _TOKEN_TTL,
        }

    logger.info("[%s] token listo para user=%s short_code=%s", service, user_id, short_code)

    wa_ok = _send_wa(service, short_code)
    if not wa_ok:
        logger.warning("[%s] no se pudo enviar WA, token disponible por GET /tokens/%s", service, short_code)

    return _html_success(label, user_id, agent_id, wa_ok)


@app.get("/tokens/{short_code}")
def get_token(short_code: str) -> dict:
    """Retira el token por short_code (one-shot). Core lo llama al recibir el WA."""
    now = time.time()
    with _lock:
        entry = _pending_tokens.pop(short_code, None)
    if not entry or entry["expires_at"] < now:
        raise HTTPException(status_code=404, detail="Token no encontrado o expirado")
    logger.info("[%s] token retirado para user=%s", entry["service"], entry["user_id"])
    return {k: v for k, v in entry.items() if k != "expires_at"}


# ── Helpers ────────────────────────────────────────────────────────────────────

def _exchange_code(svc: dict[str, str], code: str) -> dict | None:
    try:
        data = urllib.parse.urlencode({
            "grant_type":    "authorization_code",
            "client_id":     svc["client_id"],
            "client_secret": svc["client_secret"],
            "code":          code,
            "redirect_uri":  svc["redirect_uri"],
        }).encode()
        req = urllib.request.Request(svc["token_url"], data=data, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except Exception as exc:
        logger.error("[oauth] exchange_code failed: %s", exc)
        return None


def _fetch_me_user_id(svc: dict[str, str], access_token: str) -> str:
    if not access_token:
        return ""
    try:
        req = urllib.request.Request(svc["me_url"])
        req.add_header("Authorization", f"Bearer {access_token}")
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        return str(data.get("id", ""))
    except Exception:
        return ""


def _send_wa(service: str, short_code: str) -> bool:
    """Envía mensaje al bot via Meta WA Cloud API."""
    if not _WA_ACCESS_TOKEN or not _WA_PHONE_NUMBER_ID or not _BOT_WA_PHONE:
        logger.warning("[wa] credenciales WA no configuradas — skipping")
        return False
    payload = {
        "messaging_product": "whatsapp",
        "to":   _BOT_WA_PHONE,
        "type": "text",
        "text": {"body": f"CAPITAN_OAUTH:{service}:{short_code}"},
    }
    try:
        resp = httpx.post(
            f"https://graph.facebook.com/v18.0/{_WA_PHONE_NUMBER_ID}/messages",
            json=payload,
            headers={"Authorization": f"Bearer {_WA_ACCESS_TOKEN}"},
            timeout=10,
        )
        if resp.status_code == 200:
            logger.info("[wa] mensaje enviado al bot para %s", service)
            return True
        logger.error("[wa] error %s: %s", resp.status_code, resp.text[:200])
        return False
    except Exception as exc:
        logger.error("[wa] exception: %s", exc)
        return False


def _html_success(label: str, user_id: str, agent_id: str, wa_ok: bool) -> HTMLResponse:
    wa_msg = (
        "El bot recibirá el token automáticamente en unos segundos."
        if wa_ok else
        "No se pudo notificar al bot automáticamente. Revisá los logs de Cloud Run."
    )
    body = f"""<!doctype html>
<html lang="es">
<head><meta charset="utf-8"><title>Conectado — {label}</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  body{{font-family:system-ui,sans-serif;background:#0a0a0a;color:#e5e7eb;
       display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}}
  .card{{background:#111;border:1px solid #222;border-radius:1rem;padding:2rem;max-width:400px;text-align:center}}
  h1{{color:#34d399;font-size:1.5rem;margin-bottom:.5rem}}
  p{{color:#9ca3af;font-size:.9rem;line-height:1.5}}
  .chip{{display:inline-block;background:#1a2a1a;color:#6ee7b7;font-size:.75rem;
         padding:.2rem .6rem;border-radius:.25rem;margin-top.5rem}}
</style></head>
<body><div class="card">
  <h1>✓ {label} conectado</h1>
  <p>Usuario: <span class="chip">{user_id}</span></p>
  <p style="margin-top:1rem">{wa_msg}</p>
  <p style="margin-top:1.5rem;color:#6b7280;font-size:.8rem">Podés cerrar esta pestaña.</p>
</div></body></html>"""
    return HTMLResponse(body)


def _html_error(msg: str) -> HTMLResponse:
    body = f"""<!doctype html>
<html lang="es">
<head><meta charset="utf-8"><title>Error OAuth</title>
<style>
  body{{font-family:system-ui,sans-serif;background:#0a0a0a;color:#e5e7eb;
       display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}}
  .card{{background:#111;border:1px solid #3f1515;border-radius:1rem;padding:2rem;max-width:400px;text-align:center}}
  h1{{color:#f87171;font-size:1.3rem}}
  p{{color:#9ca3af;font-size:.9rem}}
</style></head>
<body><div class="card">
  <h1>Error de autorización</h1>
  <p>{msg}</p>
  <p style="margin-top:1.5rem;color:#6b7280;font-size:.8rem">Podés cerrar esta pestaña e intentarlo nuevamente.</p>
</div></body></html>"""
    return HTMLResponse(body, status_code=400)
