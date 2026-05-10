"""Client WebSocket pour la box Tydom de Delta Dore.

Flow de connexion :
  1. Requête HTTP avec headers WebSocket (Upgrade) → 401 + nonce
  2. Calcul Authorization Digest avec ce nonce
  3. websockets.connect() avec Authorization → 101 ✓

Le nonce doit être obtenu avec les headers WebSocket (Upgrade/Connection)
sinon la box génère un nonce différent pour les connexions WebSocket.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import http.client
import inspect
import json
import logging
import os
import re
import ssl
from typing import Any, Callable

import websockets

_LOGGER = logging.getLogger(__name__)

TYDOM_PORT = 443
MEDIATION_URI = "/mediation/client?mac={mac}&appli=1"
TYDOM_REMOTE_HOST = "mediation.tydom.com"


# ---------------------------------------------------------------------------
# Helpers parsing
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
# Digest RFC 2617
# ---------------------------------------------------------------------------

def _parse_www_auth(www_auth: str) -> dict[str, str]:
    chal: dict[str, str] = {}
    for m in re.finditer(r'(\w+)=(?:"([^"]*)"|([\w./+=-]+))', www_auth):
        chal[m.group(1)] = m.group(2) if m.group(2) is not None else m.group(3)
    return chal


def _calc_digest(mac: str, password: str, realm: str, nonce: str, uri: str, opaque: str = "") -> str:
    ha1      = hashlib.md5(f"{mac}:{realm}:{password}".encode()).hexdigest()
    ha2      = hashlib.md5(f"GET:{uri}".encode()).hexdigest()
    nc       = "00000001"
    cnonce   = hashlib.md5(b"tydom_ha").hexdigest()[:8]
    response = hashlib.md5(f"{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}".encode()).hexdigest()
    header = (
        f'Digest username="{mac}", realm="{realm}", '
        f'nonce="{nonce}", uri="{uri}", '
        f'response="{response}", '
        f'qop=auth, nc={nc}, cnonce="{cnonce}"'
    )
    if opaque:
        header += f', opaque="{opaque}"'
    return header


# ---------------------------------------------------------------------------
# Handshake (synchrone → executor)
# ---------------------------------------------------------------------------

def _get_challenge_with_ws_headers_sync(
    host: str, port: int, mac: str, ssl_context: ssl.SSLContext
) -> tuple[str, str]:
    """Obtient le nonce Digest en envoyant des headers WebSocket.

    La box génère un nonce lié au contexte WebSocket (headers Upgrade présents).
    Ce nonce est ensuite valide pour websockets.connect().
    Synchrone — appelé via loop.run_in_executor().
    """
    uri = MEDIATION_URI.format(mac=mac)
    headers = {
        "Host": host,
        "Connection": "Upgrade",
        "Upgrade": "websocket",
        "Accept": "*/*",
        "Sec-WebSocket-Version": "13",
        "Sec-WebSocket-Key": base64.b64encode(os.urandom(16)).decode("ascii"),
    }
    conn = http.client.HTTPSConnection(host, port, context=ssl_context, timeout=10)
    conn.request("GET", uri, None, headers)
    r = conn.getresponse()
    status   = r.status
    www_auth = r.headers.get("WWW-Authenticate") or r.headers.get("www-authenticate") or ""
    r.read()
    conn.close()

    _LOGGER.debug("[TYDOM] Challenge : status=%d  WWW-Auth=%s", status, www_auth)

    if not www_auth:
        raise ConnectionError(
            f"Pas de challenge Digest (status={status}). "
            "Vérifiez l'adresse IP et la MAC."
        )

    chal   = _parse_www_auth(www_auth)
    nonce  = chal.get("nonce", "")
    realm  = chal.get("realm", "Protected Area")
    opaque = chal.get("opaque", "")
    _LOGGER.debug("[TYDOM] realm=%r  nonce=%s  opaque=%s", realm, nonce, opaque)
    return realm, nonce, opaque


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
        _LOGGER.debug("TydomClient — host=%s, mac=%s", self._host, self._mac)

    def _build_ssl_context(self) -> ssl.SSLContext:
        ctx = ssl._create_unverified_context()
        ctx.options |= getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4)
        return ctx

    async def connect(self) -> bool:
        """Obtient le nonce puis ouvre le WebSocket avec Authorization."""
        _LOGGER.info("Connexion Tydom (%s)…", self._host)
        ssl_context = self._build_ssl_context()
        loop = asyncio.get_event_loop()

        # Étape 1 — nonce via requête avec headers WebSocket (executor)
        try:
            realm, nonce, opaque = await loop.run_in_executor(
                None, _get_challenge_with_ws_headers_sync,
                self._host, TYDOM_PORT, self._mac, ssl_context,
            )
        except Exception as exc:
            _LOGGER.error("Impossible d'obtenir le challenge Tydom : %s", exc)
            return False

        # Étape 2 — Authorization Digest + websockets.connect()
        uri           = MEDIATION_URI.format(mac=self._mac)
        authorization = _calc_digest(self._mac, self._password, realm, nonce, uri, opaque)
        _LOGGER.debug("[TYDOM] Authorization: %s", authorization)

        ws_uri = f"wss://{self._host}:{TYDOM_PORT}{uri}"
        ws_kwargs: dict = {
            "ssl": ssl_context,
            "ping_interval": 30,
            "ping_timeout": 10,
            "close_timeout": 5,
        }
        auth_header = {"Authorization": authorization}
        if "additional_headers" in inspect.signature(websockets.connect).parameters:
            ws_kwargs["additional_headers"] = auth_header
        else:
            ws_kwargs["extra_headers"] = auth_header

        try:
            self._websocket = await websockets.connect(ws_uri, **ws_kwargs)
        except Exception as exc:
            _LOGGER.error("Impossible d'ouvrir le WebSocket Tydom : %s", exc)
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

    async def put_device_data(
        self, device_id: int, endpoint_id: int, name: str, value: Any
    ) -> None:
        await self.put(
            f"/devices/{device_id}/endpoints/{endpoint_id}/data",
            [{"name": name, "value": value}]
        )

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