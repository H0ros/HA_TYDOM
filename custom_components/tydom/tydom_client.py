"""Client WebSocket pour la box Tydom de Delta Dore.

Protocole local (Tydom 1.0) :
1. Handshake HTTPS dans un thread executor → récupère WWW-Authenticate: Digest
2. Calcul de la réponse Digest RFC 2617 (MD5) — implémentation directe
3. Ouverture du WebSocket asyncio avec l'en-tête Authorization

Note sur le mot de passe Tydom 1 :
- Par défaut en sortie d'usine : les 6 derniers caractères de l'adresse MAC
  Exemple : MAC 00:1A:25:08:84:6E → mot de passe : 08846E
- Ce mot de passe peut avoir été changé via l'ancienne version de l'app Delta Dore (v3)
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
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


# ---------------------------------------------------------------------------
# Helpers de parsing
# ---------------------------------------------------------------------------

def _parse_chunked_body(raw: str) -> str:
    output = []
    lines = raw.split("\r\n")
    i = 0
    while i < len(lines):
        try:
            chunk_size = int(lines[i], 16)
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
    try:
        raw = raw_bytes[len(cmd_prefix):].decode("utf-8", errors="replace")
        if "\r\n\r\n" not in raw:
            return None
        headers_part, body_part = raw.split("\r\n\r\n", 1)
        if not headers_part.split("\r\n")[0].startswith("HTTP/"):
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
    try:
        raw = raw_bytes[len(cmd_prefix):].decode("utf-8", errors="replace")
        for line in raw.split("\r\n"):
            if line.lower().startswith("uri-origin:"):
                return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Handshake HTTP synchrone → executor
# ---------------------------------------------------------------------------

def _do_http_handshake_sync(host: str, port: int, mac: str, ssl_context: ssl.SSLContext) -> str | None:
    """Handshake HTTPS pour obtenir le challenge WWW-Authenticate.
    Synchrone — doit être appelé via loop.run_in_executor().
    """
    uri_path = MEDIATION_URI.format(mac=mac)
    headers = {
        "Connection": "Upgrade",
        "Upgrade": "websocket",
        "Host": f"{host}:{port}",
        "Accept": "*/*",
        "Sec-WebSocket-Key": base64.b64encode(os.urandom(16)).decode("ascii"),
        "Sec-WebSocket-Version": "13",
    }
    conn = http.client.HTTPSConnection(host, port, context=ssl_context, timeout=10)
    conn.request("GET", uri_path, None, headers)
    res = conn.getresponse()
    www_auth = res.headers.get("WWW-Authenticate", "")
    status = res.status
    res.read()
    conn.close()
    return www_auth or None, status


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

        self._websocket = None
        self._listen_task = None
        self._connected = False
        self._transac_id = 0

        _LOGGER.debug("TydomClient initialisé — host=%s, mac=%s", self._host, self._mac)

    def _build_ssl_context(self) -> ssl.SSLContext:
        ctx = ssl._create_unverified_context()
        # OP_LEGACY_SERVER_CONNECT requis pour les anciens firmwares TLS de la Tydom 1
        legacy_opt = getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4)
        ctx.options |= legacy_opt
        return ctx

    def _build_digest_header(self, www_auth: str) -> str:
        """Calcul Digest RFC 2617 — implémentation directe (qop=auth, nc=00000001)."""
        parts = [p.strip() for p in www_auth.replace("Digest ", "").split(",")]
        chal: dict[str, str] = {}
        for part in parts:
            if "=" in part:
                k, v = part.split("=", 1)
                chal[k.strip()] = v.strip().strip('"')

        nonce = chal.get("nonce", "")
        realm = chal.get("realm", "protected area")
        uri   = MEDIATION_URI.format(mac=self._mac)

        ha1      = hashlib.md5(f"{self._mac}:{realm}:{self._password}".encode()).hexdigest()
        ha2      = hashlib.md5(f"GET:{uri}".encode()).hexdigest()
        nc       = "00000001"
        cnonce   = hashlib.md5(b"tydom_ha").hexdigest()[:8]
        response = hashlib.md5(f"{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}".encode()).hexdigest()

        header = (
            f'Digest username="{self._mac}", realm="{realm}", '
            f'nonce="{nonce}", uri="{uri}", '
            f'response="{response}", '
            f'qop=auth, nc={nc}, cnonce="{cnonce}"'
        )
        _LOGGER.debug("Digest calculé — realm=%s, nonce=%s, response=%s", realm, nonce, response)
        return header

    async def connect(self) -> bool:
        """Handshake + ouverture WebSocket, non-bloquant pour HA."""
        _LOGGER.info("Connexion à la box Tydom (%s)…", self._host)

        ssl_context = self._build_ssl_context()
        loop = asyncio.get_event_loop()

        # Étape 1 — handshake HTTPS (executor)
        try:
            result = await loop.run_in_executor(
                None, _do_http_handshake_sync, self._host, TYDOM_PORT, self._mac, ssl_context
            )
            www_auth, http_status = result
        except Exception as exc:
            _LOGGER.error("Impossible de contacter la box Tydom : %s", exc)
            return False

        _LOGGER.debug("Handshake HTTP — status=%s, WWW-Authenticate=%s", http_status, www_auth)

        if not www_auth:
            _LOGGER.error(
                "Pas de challenge Digest (WWW-Authenticate vide, HTTP status=%s). "
                "Vérifiez l'adresse IP et l'adresse MAC.", http_status
            )
            return False

        # Étape 2 — calcul Digest
        try:
            authorization = self._build_digest_header(www_auth)
        except Exception as exc:
            _LOGGER.error("Erreur calcul Digest : %s", exc)
            return False

        _LOGGER.debug("Authorization: %s", authorization)

        # Étape 3 — WebSocket
        uri_path = MEDIATION_URI.format(mac=self._mac)
        ws_uri = f"wss://{self._host}:{TYDOM_PORT}{uri_path}"
        _LOGGER.debug("Ouverture WebSocket vers %s", ws_uri)

        import inspect
        ws_kwargs: dict = {"ssl": ssl_context, "ping_interval": 30, "ping_timeout": 10, "close_timeout": 5}
        if "additional_headers" in inspect.signature(websockets.connect).parameters:
            ws_kwargs["additional_headers"] = {"Authorization": authorization}
        else:
            ws_kwargs["extra_headers"] = {"Authorization": authorization}

        try:
            self._websocket = await websockets.connect(ws_uri, **ws_kwargs)
        except Exception as exc:
            _LOGGER.error(
                "Impossible d'ouvrir le WebSocket Tydom : %s — "
                "Si HTTP 401 : vérifiez le mot de passe (par défaut = 6 derniers "
                "caractères de la MAC, ex : MAC 00:1A:25:08:84:6E → 08846E)", exc
            )
            return False

        self._connected = True
        _LOGGER.info("WebSocket Tydom connecté (%s)", self._host)
        return True

    async def disconnect(self) -> None:
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
        await self._send(self._build_put_request(path, json.dumps(body_dict)))

    async def get_info(self)         -> dict | None: return await self.get("/info")
    async def get_devices_data(self) -> list | None: return await self.get("/devices/data")
    async def get_devices_meta(self) -> list | None: return await self.get("/devices/meta")
    async def get_configs_file(self) -> dict | None: return await self.get("/configs/file")

    async def put_device_data(self, device_id: int, endpoint_id: int, name: str, value: Any) -> None:
        await self.put(f"/devices/{device_id}/endpoints/{endpoint_id}/data", [{"name": name, "value": value}])

    async def listen(self) -> None:
        if not self._websocket or not self._connected:
            return
        _LOGGER.debug("Écoute messages Tydom démarrée")
        try:
            async for message in self._websocket:
                raw = message if isinstance(message, bytes) else message.encode()
                uri_origin = _get_uri_origin(raw, self._cmd_prefix)
                data = _extract_json_from_response(raw, self._cmd_prefix)
                if data is not None and self._message_callback and uri_origin:
                    try:
                        self._message_callback(uri_origin, data)
                    except Exception as exc:
                        _LOGGER.error("Erreur callback : %s", exc)
        except websockets.ConnectionClosed:
            _LOGGER.warning("Connexion Tydom fermée")
            self._connected = False
        except Exception as exc:
            _LOGGER.error("Erreur écoute Tydom : %s", exc)
            self._connected = False

    def start_listening(self) -> asyncio.Task:
        self._listen_task = asyncio.ensure_future(self.listen())
        return self._listen_task

    @property
    def is_connected(self) -> bool:
        return self._connected and self._websocket is not None