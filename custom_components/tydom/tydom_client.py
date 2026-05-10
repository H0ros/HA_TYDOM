"""Client WebSocket pour la box Tydom de Delta Dore.

Protocole de connexion (3 requêtes sur la même connexion TCP) :
  Req 1 : GET sans Authorization            → 401 + nonce_A
  Req 2 : GET + Digest(nonce_A)             → 401 + nonce_B  (la box invalide nonce_A)
  Req 3 : GET + Digest(nonce_B)             → 101 Switching Protocols ✓

La box Tydom invalide systématiquement le premier nonce et en génère un nouveau.
C'est pour ça que toute approche en 2 requêtes échoue avec HTTP 401.
Le realm exact est "Protected Area" (sensible à la casse).
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import http.client
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
# Helpers de parsing des réponses WebSocket encapsulées
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
# Calcul Digest RFC 2617
# ---------------------------------------------------------------------------

def _calc_digest(mac: str, password: str, realm: str, nonce: str, uri: str) -> str:
    """Calcule l'Authorization Digest RFC 2617 (qop=auth, nc=00000001)."""
    ha1      = hashlib.md5(f"{mac}:{realm}:{password}".encode()).hexdigest()
    ha2      = hashlib.md5(f"GET:{uri}".encode()).hexdigest()
    nc       = "00000001"
    cnonce   = hashlib.md5(b"tydom_ha").hexdigest()[:8]
    response = hashlib.md5(f"{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}".encode()).hexdigest()
    return (
        f'Digest username="{mac}", realm="{realm}", '
        f'nonce="{nonce}", uri="{uri}", '
        f'response="{response}", '
        f'qop=auth, nc={nc}, cnonce="{cnonce}"'
    )


def _parse_www_auth(www_auth: str) -> dict[str, str]:
    """Parse le header WWW-Authenticate: Digest ..."""
    chal: dict[str, str] = {}
    for m in re.finditer(r'(\w+)=(?:"([^"]*)"|([\w./+=-]+))', www_auth):
        chal[m.group(1)] = m.group(2) if m.group(2) is not None else m.group(3)
    return chal


# ---------------------------------------------------------------------------
# Handshake complet (3 requêtes) — synchrone → executor
# ---------------------------------------------------------------------------

def _do_full_handshake_sync(
    host: str, port: int, mac: str, password: str, ssl_context: ssl.SSLContext
):
    """Effectue les 3 échanges HTTP nécessaires sur la même connexion TCP.

    La box Tydom invalide le premier nonce et en émet un second.
    Il faut donc :
      1. GET sans auth           → 401 + nonce_A
      2. GET + Digest(nonce_A)   → 401 + nonce_B
      3. GET + Digest(nonce_B)   → 101 Switching Protocols

    Retourne le socket TLS prêt pour WebSocket, ou lève une exception.
    Synchrone — appelé via loop.run_in_executor().
    """
    uri = MEDIATION_URI.format(mac=mac)

    def make_ws_headers(authorization: str | None = None) -> dict:
        h = {
            "Connection": "Upgrade",
            "Upgrade": "websocket",
            "Host": f"{host}:{port}",
            "Accept": "*/*",
            "Sec-WebSocket-Version": "13",
            "Sec-WebSocket-Key": base64.b64encode(os.urandom(16)).decode("ascii"),
        }
        if authorization:
            h["Authorization"] = authorization
        return h

    conn = http.client.HTTPSConnection(host, port, context=ssl_context, timeout=10)

    # ---- Requête 1 : sans Authorization → 401 + nonce_A ----
    _LOGGER.debug("[TYDOM] Req 1 (sans auth)…")
    conn.request("GET", uri, None, make_ws_headers())
    r1 = conn.getresponse()
    s1, h1 = r1.status, dict(r1.headers)
    r1.read()
    conn.close()
    _LOGGER.debug("[TYDOM] Réponse 1 : status=%d, Connection=%s", s1, h1.get("Connection", ""))

    www_auth_1 = h1.get("WWW-Authenticate") or h1.get("www-authenticate") or ""
    if s1 != 401 or not www_auth_1:
        raise ConnectionError(f"Réponse inattendue req1 : status={s1}, headers={h1}")

    chal_1 = _parse_www_auth(www_auth_1)
    nonce_a = chal_1.get("nonce", "")
    realm   = chal_1.get("realm", "Protected Area")
    _LOGGER.debug("[TYDOM] nonce_A=%s  realm=%r", nonce_a, realm)

    # ---- Requête 2 : nouvelle connexion + Digest(nonce_A) → 401 + nonce_B ----
    auth_a = _calc_digest(mac, password, realm, nonce_a, uri)
    _LOGGER.debug("[TYDOM] Req 2 Authorization: %s", auth_a)
    conn = http.client.HTTPSConnection(host, port, context=ssl_context, timeout=10)
    conn.request("GET", uri, None, make_ws_headers(auth_a))
    r2 = conn.getresponse()
    s2, h2 = r2.status, dict(r2.headers)
    _LOGGER.debug("[TYDOM] Réponse 2 : status=%d", s2)

    if s2 == 101:
        _LOGGER.debug("[TYDOM] Connexion acceptée dès req 2 (101)")
        raw_sock = conn.sock
        conn.sock = None
        return raw_sock

    r2.read()
    conn.close()

    if s2 != 401:
        raise ConnectionError(f"Réponse inattendue req2 : status={s2}, headers={h2}")

    www_auth_2 = h2.get("WWW-Authenticate") or h2.get("www-authenticate") or ""
    chal_2  = _parse_www_auth(www_auth_2)
    nonce_b = chal_2.get("nonce", "")
    realm   = chal_2.get("realm", realm)
    _LOGGER.debug("[TYDOM] nonce_B=%s  realm=%r", nonce_b, realm)

    # ---- Requête 3 : nouvelle connexion + Digest(nonce_B) → 101 ----
    auth_b = _calc_digest(mac, password, realm, nonce_b, uri)
    _LOGGER.debug("[TYDOM] Req 3 Authorization: %s", auth_b)
    conn = http.client.HTTPSConnection(host, port, context=ssl_context, timeout=10)
    conn.request("GET", uri, None, make_ws_headers(auth_b))
    r3 = conn.getresponse()
    s3, h3 = r3.status, dict(r3.headers)
    body3 = r3.read()
    www_auth_3 = h3.get("WWW-Authenticate") or h3.get("www-authenticate") or ""
    _LOGGER.debug("[TYDOM] Réponse 3 : status=%d, WWW-Auth=%s", s3, www_auth_3)
    _LOGGER.debug("[TYDOM] Réponse 3 headers complets : %s", h3)

    # Log de vérification du calcul Digest
    import hashlib as _hlib
    _ha1 = _hlib.md5(f"{mac}:{realm}:{password}".encode()).hexdigest()
    _ha2 = _hlib.md5(f"GET:{uri}".encode()).hexdigest()
    _LOGGER.debug("[TYDOM] Vérif calcul — mac=%r password=%r realm=%r", mac, password, realm)
    _LOGGER.debug("[TYDOM] ha1=%s  ha2=%s", _ha1, _ha2)

    if s3 != 101:
        conn.close()
        raise PermissionError(
            f"Échec après 3 tentatives (status={s3}). "
            f"WWW-Auth reçu: {www_auth_3!r}. "
            f"Calcul: mac={mac!r}, realm={realm!r}, password_len={len(password)}. "
            f"Body={body3[:200]!r}"
        )

    raw_sock = conn.sock
    conn.sock = None
    return raw_sock


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
        """Handshake 3 requêtes + WebSocket, non-bloquant pour HA."""
        _LOGGER.info("Connexion Tydom (%s)…", self._host)
        ssl_context = self._build_ssl_context()
        loop = asyncio.get_event_loop()

        try:
            raw_sock = await loop.run_in_executor(
                None, _do_full_handshake_sync,
                self._host, TYDOM_PORT, self._mac, self._password, ssl_context,
            )
        except PermissionError as exc:
            _LOGGER.error("%s", exc)
            return False
        except Exception as exc:
            _LOGGER.error("Impossible de contacter la box Tydom : %s", exc)
            return False

        ws_uri = f"wss://{self._host}:{TYDOM_PORT}{MEDIATION_URI.format(mac=self._mac)}"
        try:
            self._websocket = await websockets.connect(
                ws_uri,
                sock=raw_sock,
                ssl=None,
                ping_interval=30,
                ping_timeout=10,
                close_timeout=5,
            )
        except Exception as exc:
            _LOGGER.error("Impossible d'initialiser le WebSocket : %s", exc)
            try:
                raw_sock.close()
            except Exception:
                pass
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