"""Client WebSocket pour la box Tydom de Delta Dore.

Protocole local (Tydom 1.0) :
1. Handshake HTTPS vers la box dans un thread executor (opération bloquante)
   → récupère le challenge WWW-Authenticate: Digest
2. Calcul de la réponse Digest RFC 2617 (MD5) — implémentation directe
3. Ouverture du WebSocket asyncio avec l'en-tête Authorization calculé
4. Envoi de requêtes HTTP/1.1 encapsulées dans le WebSocket
5. Réception et parsing des réponses HTTP/1.1 chunked encapsulées

Mode cloud (optionnel) :
- Récupération du mot de passe Tydom depuis l'API Delta Dore avec les identifiants
  du compte Delta Dore (email + mot de passe de l'app)
- Utile si le PIN de l'étiquette a été changé via l'application Delta Dore
"""
from __future__ import annotations

import asyncio
import base64
import http.client
import json
import logging
import os
import ssl
from typing import Any, Callable

import websockets

_LOGGER = logging.getLogger(__name__)

TYDOM_PORT = 443
MEDIATION_URI = "/mediation/client?mac={mac}&appli=1"
TYDOM_REMOTE_HOST = "mediation.tydom.com"

# API Delta Dore pour récupérer le mot de passe Tydom
DELTADORE_AUTH_URL = "https://homepilot-api.somfy.com/auth/sign_in"
DELTADORE_ACCOUNT_URL = "https://homepilot-api.somfy.com/account"


# ---------------------------------------------------------------------------
# Helpers de parsing des réponses HTTP/1.1 encapsulées dans le WebSocket
# ---------------------------------------------------------------------------

def _parse_chunked_body(raw: str) -> str:
    """Décode un body HTTP/1.1 Transfer-Encoding: chunked."""
    output = []
    lines = raw.split("\r\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        try:
            chunk_size = int(line, 16)
        except ValueError:
            i += 1
            continue
        if chunk_size == 0:
            break
        if i + 1 < len(lines):
            output.append(lines[i + 1])
        i += 2
    return "".join(output)


def _extract_json_from_response(raw_bytes: bytes, cmd_prefix: str = "") -> dict | list | None:
    """Extrait et parse le JSON d'une réponse HTTP Tydom encapsulée."""
    try:
        raw = raw_bytes[len(cmd_prefix):].decode("utf-8", errors="replace")

        if "\r\n\r\n" not in raw:
            return None

        headers_part, body_part = raw.split("\r\n\r\n", 1)

        first_line = headers_part.split("\r\n")[0]
        if not first_line.startswith("HTTP/"):
            return None

        if "transfer-encoding: chunked" in headers_part.lower():
            body_part = _parse_chunked_body(body_part)

        body_part = body_part.strip()
        if not body_part:
            return None

        return json.loads(body_part)

    except Exception as exc:
        _LOGGER.debug("Parsing réponse Tydom échoué : %s", exc)
        return None


def _get_uri_origin(raw_bytes: bytes, cmd_prefix: str = "") -> str | None:
    """Extrait le header Uri-Origin d'une réponse HTTP Tydom."""
    try:
        raw = raw_bytes[len(cmd_prefix):].decode("utf-8", errors="replace")
        for line in raw.split("\r\n"):
            if line.lower().startswith("uri-origin:"):
                return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Récupération du mot de passe via le cloud Delta Dore (synchrone → executor)
# ---------------------------------------------------------------------------

def _fetch_tydom_password_from_cloud_sync(
    email: str, dd_password: str, mac: str
) -> str | None:
    """Récupère le mot de passe Tydom depuis l'API Delta Dore.

    Synchrone — doit être appelé via loop.run_in_executor().
    """
    import urllib.request
    import urllib.error

    # Étape 1 : authentification
    auth_payload = json.dumps({"email": email, "password": dd_password}).encode()
    req = urllib.request.Request(
        DELTADORE_AUTH_URL,
        data=auth_payload,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            auth_data = json.loads(resp.read().decode())
    except Exception as exc:
        _LOGGER.error("Authentification Delta Dore échouée : %s", exc)
        return None

    token = (
        auth_data.get("token")
        or (auth_data.get("data") or {}).get("token")
    )
    if not token:
        _LOGGER.error("Token Delta Dore non trouvé dans : %s", list(auth_data.keys()))
        return None

    # Étape 2 : récupération du compte
    account_req = urllib.request.Request(
        DELTADORE_ACCOUNT_URL,
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(account_req, timeout=10) as resp:
            account_data = json.loads(resp.read().decode())
    except Exception as exc:
        _LOGGER.error("Récupération compte Delta Dore échouée : %s", exc)
        return None

    for key in ("tydom_password", "tydomPassword", "password"):
        pwd = account_data.get(key)
        if pwd:
            return str(pwd)

    for gateway in account_data.get("gateways", []):
        if mac.upper() in str(gateway.get("mac", "")).upper():
            for key in ("password", "tydom_password"):
                pwd = gateway.get(key)
                if pwd:
                    return str(pwd)

    _LOGGER.warning("Mot de passe Tydom non trouvé via le cloud Delta Dore.")
    return None


# ---------------------------------------------------------------------------
# Handshake HTTP (bloquant) — exécuté dans un thread executor
# ---------------------------------------------------------------------------

def _do_http_handshake_sync(
    host: str, port: int, mac: str, ssl_context: ssl.SSLContext
) -> str | None:
    """Effectue le handshake HTTPS, renvoie le header WWW-Authenticate.

    Synchrone/bloquante — doit être appelé via loop.run_in_executor().
    """
    uri_path = MEDIATION_URI.format(mac=mac)
    http_headers = {
        "Connection": "Upgrade",
        "Upgrade": "websocket",
        "Host": f"{host}:{port}",
        "Accept": "*/*",
        "Sec-WebSocket-Key": base64.b64encode(os.urandom(16)).decode("ascii"),
        "Sec-WebSocket-Version": "13",
    }
    conn = http.client.HTTPSConnection(host, port, context=ssl_context, timeout=10)
    conn.request("GET", uri_path, None, http_headers)
    res = conn.getresponse()
    www_auth = res.headers.get("WWW-Authenticate", "")
    res.read()
    conn.close()
    return www_auth or None


# ---------------------------------------------------------------------------
# Client principal
# ---------------------------------------------------------------------------

class TydomClient:
    """Client asynchrone pour la box Tydom (mode local, Tydom 1.0)."""

    def __init__(
        self,
        mac: str,
        password: str,
        host: str | None = None,
        *,
        message_callback: Callable[[str, Any], None] | None = None,
    ) -> None:
        self._mac = mac.upper().replace(":", "").replace("-", "")
        self._password = password
        self._host = host or f"{self._mac}-tydom.local"
        self._message_callback = message_callback

        self._remote = self._host == TYDOM_REMOTE_HOST
        self._cmd_prefix = "\x02" if self._remote else ""

        self._websocket: websockets.WebSocketClientProtocol | None = None
        self._listen_task: asyncio.Task | None = None
        self._connected = False
        self._transac_id = 0

        _LOGGER.debug(
            "TydomClient initialisé — host=%s, mac=%s, remote=%s",
            self._host, self._mac, self._remote,
        )

    # ------------------------------------------------------------------
    # Connexion
    # ------------------------------------------------------------------

    def _build_ssl_context(self) -> ssl.SSLContext:
        """Contexte SSL adapté à la Tydom 1.0.

        La box utilise un vieux firmware TLS qui requiert deux adaptations :
        - Désactivation de la vérification du certificat (auto-signé)
        - Autorisation du "legacy renegotiation" (SSL_OP_LEGACY_SERVER_CONNECT)
          nécessaire pour OpenSSL >= 3.0 qui le désactive par défaut
        """
        ctx = ssl._create_unverified_context()
        # OP_LEGACY_SERVER_CONNECT = 0x4 — autorise la renégociation non-sécurisée
        # Nécessaire pour les box Tydom avec ancien firmware TLS
        try:
            ctx.options |= 0x4  # ssl.OP_LEGACY_SERVER_CONNECT (Python 3.12+)
        except AttributeError:
            pass
        # Fallback explicite si la constante est disponible
        if hasattr(ssl, "OP_LEGACY_SERVER_CONNECT"):
            ctx.options |= ssl.OP_LEGACY_SERVER_CONNECT
        return ctx

    def _build_digest_header(self, www_auth: str) -> str:
        """Calcule l'Authorization Digest (RFC 2617) depuis le challenge WWW-Authenticate.

        Implémentation directe sans requests.HTTPDigestAuth pour garantir
        nc=00000001 et éviter tout problème d'état interne de la librairie.
        Identique à la logique utilisée par tydom2mqtt.
        """
        import hashlib

        parts = [p.strip() for p in www_auth.replace("Digest ", "").split(",")]
        chal: dict[str, str] = {}
        for part in parts:
            if "=" in part:
                k, v = part.split("=", 1)
                chal[k.strip()] = v.strip().strip('"')

        nonce = chal.get("nonce", "")
        realm = chal.get("realm", "protected area")
        uri   = MEDIATION_URI.format(mac=self._mac)

        # Calcul RFC 2617 — qop=auth
        ha1      = hashlib.md5(f"{self._mac}:{realm}:{self._password}".encode()).hexdigest()
        ha2      = hashlib.md5(f"GET:{uri}".encode()).hexdigest()
        nc       = "00000001"
        cnonce   = hashlib.md5(b"tydom_ha").hexdigest()[:8]
        response = hashlib.md5(
            f"{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}".encode()
        ).hexdigest()

        return (
            f'Digest username="{self._mac}", realm="{realm}", '
            f'nonce="{nonce}", uri="{uri}", '
            f'response="{response}", '
            f'qop=auth, nc={nc}, cnonce="{cnonce}"'
        )

    async def connect(self) -> bool:
        """Handshake + ouverture WebSocket, entièrement non-bloquant pour HA."""
        _LOGGER.info("Connexion à la box Tydom (%s)…", self._host)

        ssl_context = self._build_ssl_context()
        loop = asyncio.get_event_loop()

        # Étape 1 — handshake HTTPS dans un thread executor (non-bloquant)
        try:
            www_auth = await loop.run_in_executor(
                None,
                _do_http_handshake_sync,
                self._host,
                TYDOM_PORT,
                self._mac,
                ssl_context,
            )
        except Exception as exc:
            _LOGGER.error("Impossible de contacter la box Tydom : %s", exc)
            return False

        if not www_auth:
            _LOGGER.error("Pas de challenge Digest reçu (WWW-Authenticate vide)")
            return False

        _LOGGER.debug("Challenge Digest reçu : %s", www_auth)

        # Étape 2 — calcul Digest (CPU pur, non-bloquant)
        try:
            authorization = self._build_digest_header(www_auth)
        except Exception as exc:
            _LOGGER.error("Erreur calcul Digest : %s", exc)
            return False

        _LOGGER.debug("Authorization Digest calculée")

        # Étape 3 — WebSocket asyncio
        # additional_headers : websockets >= 12.0
        # extra_headers       : websockets 10.x / 11.x (ancien nom)
        uri_path = MEDIATION_URI.format(mac=self._mac)
        ws_uri = f"wss://{self._host}:{TYDOM_PORT}{uri_path}"

        ws_kwargs: dict = {
            "ssl": ssl_context,
            "ping_interval": 30,
            "ping_timeout": 10,
            "close_timeout": 5,
        }
        import inspect
        _ws_params = inspect.signature(websockets.connect).parameters
        if "additional_headers" in _ws_params:
            ws_kwargs["additional_headers"] = {"Authorization": authorization}
        else:
            ws_kwargs["extra_headers"] = {"Authorization": authorization}

        try:
            self._websocket = await websockets.connect(ws_uri, **ws_kwargs)
        except Exception as exc:
            _LOGGER.error("Impossible d'ouvrir le WebSocket Tydom : %s", exc)
            return False

        self._connected = True
        _LOGGER.info("WebSocket Tydom connecté avec succès (%s)", self._host)
        return True

    async def disconnect(self) -> None:
        """Ferme proprement la connexion."""
        self._connected = False
        if self._listen_task and not self._listen_task.done():
            self._listen_task.cancel()
            try:
                await self._listen_task
            except asyncio.CancelledError:
                pass
        if self._websocket:
            await self._websocket.close()
            self._websocket = None

    # ------------------------------------------------------------------
    # Envoi de requêtes
    # ------------------------------------------------------------------

    def _next_transac_id(self) -> int:
        self._transac_id = (self._transac_id + 1) % 10000
        return self._transac_id

    def _build_get_request(self, path: str) -> bytes:
        tid = self._next_transac_id()
        return (
            f"{self._cmd_prefix}GET {path} HTTP/1.1\r\n"
            f"Content-Length: 0\r\n"
            f"Content-Type: application/json; charset=UTF-8\r\n"
            f"Transac-Id: {tid}\r\n\r\n"
        ).encode("ascii")

    def _build_put_request(self, path: str, body: str) -> bytes:
        tid = self._next_transac_id()
        return (
            f"{self._cmd_prefix}PUT {path} HTTP/1.1\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Content-Type: application/json; charset=UTF-8\r\n"
            f"Transac-Id: {tid}\r\n\r\n"
            f"{body}\r\n\r\n"
        ).encode("ascii")

    async def _send(self, data: bytes) -> None:
        if not self._websocket or not self._connected:
            raise ConnectionError("WebSocket non connecté")
        await self._websocket.send(data)

    async def get(self, path: str) -> dict | list | None:
        await self._send(self._build_get_request(path))
        raw = await self._websocket.recv()
        return _extract_json_from_response(
            raw if isinstance(raw, bytes) else raw.encode(), self._cmd_prefix
        )

    async def put(self, path: str, body_dict: list | dict) -> None:
        body = json.dumps(body_dict)
        await self._send(self._build_put_request(path, body))

    # ------------------------------------------------------------------
    # Requêtes de haut niveau
    # ------------------------------------------------------------------

    async def get_info(self) -> dict | None:
        return await self.get("/info")

    async def get_devices_data(self) -> list | None:
        return await self.get("/devices/data")

    async def get_devices_meta(self) -> list | None:
        return await self.get("/devices/meta")

    async def get_configs_file(self) -> dict | None:
        return await self.get("/configs/file")

    async def put_device_data(
        self, device_id: int, endpoint_id: int, name: str, value: Any
    ) -> None:
        path = f"/devices/{device_id}/endpoints/{endpoint_id}/data"
        await self.put(path, [{"name": name, "value": value}])

    # ------------------------------------------------------------------
    # Écoute des messages push
    # ------------------------------------------------------------------

    async def listen(self) -> None:
        """Écoute en boucle les messages push de la box."""
        if not self._websocket or not self._connected:
            _LOGGER.error("listen() appelé sans connexion active")
            return

        _LOGGER.debug("Début écoute messages Tydom")
        try:
            async for message in self._websocket:
                raw = message if isinstance(message, bytes) else message.encode()
                await self._handle_raw_message(raw)
        except websockets.ConnectionClosed:
            _LOGGER.warning("Connexion Tydom fermée")
            self._connected = False
        except Exception as exc:
            _LOGGER.error("Erreur boucle écoute Tydom : %s", exc)
            self._connected = False

    async def _handle_raw_message(self, raw: bytes) -> None:
        uri_origin = _get_uri_origin(raw, self._cmd_prefix)
        data = _extract_json_from_response(raw, self._cmd_prefix)
        if data is None:
            return
        _LOGGER.debug("Message Tydom reçu [%s]", uri_origin)
        if self._message_callback and uri_origin:
            try:
                self._message_callback(uri_origin, data)
            except Exception as exc:
                _LOGGER.error("Erreur callback message Tydom : %s", exc)

    def start_listening(self) -> asyncio.Task:
        self._listen_task = asyncio.ensure_future(self.listen())
        return self._listen_task

    @property
    def is_connected(self) -> bool:
        return self._connected and self._websocket is not None