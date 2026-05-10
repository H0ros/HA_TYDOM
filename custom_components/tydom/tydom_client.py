"""Client WebSocket pour la box Tydom de Delta Dore — version diagnostic."""
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


def _do_full_handshake_sync(
    host: str, port: int, mac: str, password: str, ssl_context: ssl.SSLContext
):
    """Handshake complet sur une seule connexion TCP — version avec logs détaillés."""
    uri = MEDIATION_URI.format(mac=mac)
    ws_key = base64.b64encode(os.urandom(16)).decode("ascii")

    base_headers = {
        "Connection": "Upgrade",
        "Upgrade": "websocket",
        "Host": f"{host}:{port}",
        "Accept": "*/*",
        "Sec-WebSocket-Version": "13",
        "Sec-WebSocket-Key": ws_key,
    }

    conn = http.client.HTTPSConnection(host, port, context=ssl_context, timeout=10)

    # ---- Requête 1 : sans Authorization ----
    _LOGGER.debug("[HANDSHAKE] Requête 1 → GET %s (sans auth)", uri)
    conn.request("GET", uri, None, base_headers)
    res1 = conn.getresponse()
    status1 = res1.status
    headers1 = dict(res1.headers)
    body1 = res1.read()

    _LOGGER.debug("[HANDSHAKE] Réponse 1 : status=%d", status1)
    _LOGGER.debug("[HANDSHAKE] Headers réponse 1 : %s", headers1)
    _LOGGER.debug("[HANDSHAKE] Body réponse 1 : %s", body1[:200])

    www_auth = headers1.get("WWW-Authenticate") or headers1.get("www-authenticate") or ""
    connection_hdr = headers1.get("Connection", "").lower()

    _LOGGER.debug("[HANDSHAKE] WWW-Authenticate brut : %r", www_auth)
    _LOGGER.debug("[HANDSHAKE] Connection header : %r", connection_hdr)

    if status1 not in (401, 407) or not www_auth:
        conn.close()
        raise ConnectionError(
            f"Réponse inattendue req1 : status={status1}, "
            f"WWW-Authenticate={www_auth!r}. Headers complets={headers1}"
        )

    # ---- Calcul Digest ----
    import re
    chal: dict[str, str] = {}
    for m in re.finditer(r'(\w+)=(?:"([^"]*)"|([\w./+=-]+))', www_auth):
        chal[m.group(1)] = m.group(2) if m.group(2) is not None else m.group(3)

    nonce = chal.get("nonce", "")
    realm = chal.get("realm", "")
    qop   = chal.get("qop", "auth")

    _LOGGER.debug("[DIGEST] realm=%r  nonce=%r  qop=%r", realm, nonce, qop)

    ha1 = hashlib.md5(f"{mac}:{realm}:{password}".encode()).hexdigest()
    ha2 = hashlib.md5(f"GET:{uri}".encode()).hexdigest()
    nc  = "00000001"
    cnonce = hashlib.md5(b"tydom_ha").hexdigest()[:8]
    response_dig = hashlib.md5(
        f"{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}".encode()
    ).hexdigest()

    authorization = (
        f'Digest username="{mac}", realm="{realm}", '
        f'nonce="{nonce}", uri="{uri}", '
        f'response="{response_dig}", '
        f'qop=auth, nc={nc}, cnonce="{cnonce}"'
    )

    _LOGGER.debug("[DIGEST] ha1=%s", ha1)
    _LOGGER.debug("[DIGEST] ha2=%s", ha2)
    _LOGGER.debug("[DIGEST] response=%s", response_dig)
    _LOGGER.debug("[DIGEST] Authorization envoyé : %s", authorization)

    # ---- Requête 2 : avec Authorization ----
    # Si la box a fermé la connexion, on en ouvre une nouvelle
    if "close" in connection_hdr:
        _LOGGER.debug("[HANDSHAKE] Box a fermé la connexion (Connection: close) — nouvelle connexion")
        conn.close()
        conn = http.client.HTTPSConnection(host, port, context=ssl_context, timeout=10)

    headers2 = dict(base_headers)
    headers2["Authorization"] = authorization
    headers2["Sec-WebSocket-Key"] = base64.b64encode(os.urandom(16)).decode("ascii")

    _LOGGER.debug("[HANDSHAKE] Requête 2 → GET %s (avec Authorization)", uri)
    conn.request("GET", uri, None, headers2)
    res2 = conn.getresponse()
    status2 = res2.status
    headers2_resp = dict(res2.headers)
    _LOGGER.debug("[HANDSHAKE] Réponse 2 : status=%d", status2)
    _LOGGER.debug("[HANDSHAKE] Headers réponse 2 : %s", headers2_resp)

    if status2 == 401:
        body2 = res2.read()
        www_auth2 = headers2_resp.get("WWW-Authenticate", "")
        conn.close()
        raise PermissionError(
            f"HTTP 401 persistant après Authorization Digest. "
            f"WWW-Authenticate 2ème réponse: {www_auth2!r}. "
            f"Body: {body2[:200]!r}"
        )

    if status2 != 101:
        body2 = res2.read()
        conn.close()
        raise ConnectionError(
            f"Upgrade WebSocket refusé (status={status2}). "
            f"Headers={headers2_resp}. Body={body2[:200]!r}"
        )

    raw_sock = conn.sock
    conn.sock = None
    return raw_sock


class TydomClient:
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
        _LOGGER.debug("TydomClient — host=%s, mac=%s, password_len=%d",
                      self._host, self._mac, len(self._password))

    def _build_ssl_context(self) -> ssl.SSLContext:
        ctx = ssl._create_unverified_context()
        ctx.options |= getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4)
        return ctx

    async def connect(self) -> bool:
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