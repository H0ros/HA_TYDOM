"""Client WebSocket pour la box Tydom de Delta Dore.

Protocole de connexion (validé empiriquement) :
  1. Connexion TLS 1  → GET avec headers WebSocket → 401 + nonce
  2. Connexion TLS 2  → GET avec Authorization Digest(nonce) → 101 Switching Protocols
  3. Framing WebSocket manuel sur le socket TLS 2 (pas de librairie websockets)

Points clés :
- Le mot de passe est récupéré depuis l'API Delta Dore (pas le PIN étiquette)
- Le realm doit être mis en minuscules pour le calcul Digest
- Le cnonce doit être en hexadécimal (pas base64)
- qop="auth" avec guillemets
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import re
import socket
import ssl
import struct
from typing import Any, Callable

_LOGGER = logging.getLogger(__name__)

TYDOM_PORT   = 443
MEDIATION_URI = "/mediation/client?mac={mac}&appli=1"


# ---------------------------------------------------------------------------
# WebSocket framing manuel (RFC 6455)
# ---------------------------------------------------------------------------

def _ws_encode(payload: bytes) -> bytes:
    """Encode une frame WebSocket client BINARY masquée."""
    mask   = os.urandom(4)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    length = len(payload)
    if length < 126:
        header = struct.pack("!BB", 0x82, 0x80 | length)
    elif length < 65536:
        header = struct.pack("!BBH", 0x82, 0xFE, length)
    else:
        header = struct.pack("!BBQ", 0x82, 0xFF, length)
    return header + mask + masked


def _ws_decode(data: bytes) -> bytes:
    """Décode le payload d'une frame WebSocket serveur (non masquée)."""
    if len(data) < 2:
        return b""
    payload_len = data[1] & 0x7F
    offset = 2
    if payload_len == 126:
        if len(data) < 4:
            return b""
        payload_len = struct.unpack("!H", data[2:4])[0]
        offset = 4
    elif payload_len == 127:
        if len(data) < 10:
            return b""
        payload_len = struct.unpack("!Q", data[2:10])[0]
        offset = 10
    return data[offset:offset + payload_len]


def _ws_ping_frame() -> bytes:
    """Frame PING WebSocket masquée."""
    mask = os.urandom(4)
    return struct.pack("!BB", 0x89, 0x80) + mask


def _ws_pong_frame(payload: bytes = b"") -> bytes:
    """Frame PONG WebSocket masquée."""
    mask   = os.urandom(4)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return struct.pack("!BB", 0x8A, 0x80 | len(payload)) + mask + masked


# ---------------------------------------------------------------------------
# Helpers de parsing des réponses HTTP encapsulées dans WebSocket
# ---------------------------------------------------------------------------

def _parse_chunked_body(raw: str) -> str:
    output = []
    lines  = raw.split("\r\n")
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


def _extract_json(raw_bytes: bytes) -> dict | list | None:
    try:
        raw = raw_bytes.decode("utf-8", errors="replace")
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


def _get_uri_origin(raw_bytes: bytes) -> str | None:
    try:
        raw = raw_bytes.decode("utf-8", errors="replace")
        for line in raw.split("\r\n"):
            if line.lower().startswith("uri-origin:"):
                return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Calcul Digest RFC 2617
# ---------------------------------------------------------------------------

def _parse_www_auth(www_auth: str) -> dict[str, str]:
    chal: dict[str, str] = {}
    for m in re.finditer(r'(\w+)=(?:"([^"]*)"|([\w./+=-]+))', www_auth):
        chal[m.group(1)] = m.group(2) if m.group(2) is not None else m.group(3)
    return chal


def _calc_digest(mac: str, password: str, nonce: str, realm: str,
                 opaque: str, uri: str) -> str:
    realm_lower = realm.lower()
    ha1      = hashlib.md5(f"{mac}:{realm_lower}:{password}".encode()).hexdigest()
    ha2      = hashlib.md5(f"GET:{uri}".encode()).hexdigest()
    nc, cnonce = "00000001", os.urandom(8).hex()
    response = hashlib.md5(f"{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}".encode()).hexdigest()
    auth = (
        f'Digest username="{mac}", realm="{realm_lower}", '
        f'nonce="{nonce}", uri="{uri}", '
        f'response="{response}", qop="auth", nc={nc}, cnonce="{cnonce}"'
    )
    if opaque:
        auth += f', opaque="{opaque}"'
    return auth


# ---------------------------------------------------------------------------
# Handshake (synchrone → executor)
# ---------------------------------------------------------------------------

def _build_ssl_context() -> ssl.SSLContext:
    ctx = ssl._create_unverified_context()
    # OP_LEGACY_SERVER_CONNECT requis pour les anciens firmwares TLS Tydom
    # Valeur 0x4 est la constante depuis Python 3.12 / OpenSSL 3.0
    legacy_opt = getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4)
    ctx.options |= legacy_opt
    # Double application via la constante numérique pour garantir la compatibilité
    ctx.options |= 0x4
    return ctx


def _open_tls(host: str, port: int, ctx: ssl.SSLContext) -> ssl.SSLSocket:
    raw = socket.create_connection((host, port), timeout=10)
    return ctx.wrap_socket(raw, server_hostname=host)


def _recv_headers(sock: ssl.SSLSocket) -> bytes:
    resp = b""
    while b"\r\n\r\n" not in resp:
        data = sock.recv(4096)
        if not data:
            break
        resp += data
    try:
        sock.settimeout(0.3)
        extra = sock.recv(4096)
        if extra:
            resp += extra
    except Exception:
        pass
    sock.settimeout(10)
    return resp


def _do_handshake_sync(
    host: str, port: int, mac: str, password: str
) -> ssl.SSLSocket:
    """Effectue le handshake Tydom en 2 connexions TLS.

    Retourne le socket TLS en état WebSocket connecté.
    Synchrone — appelé via loop.run_in_executor().
    """
    ctx = _build_ssl_context()
    uri = MEDIATION_URI.format(mac=mac)

    def ws_request(auth: str | None = None) -> bytes:
        key = base64.b64encode(os.urandom(16)).decode()
        lines = [
            f"GET {uri} HTTP/1.1",
            f"Host: {host}",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Key: {key}",
            "Sec-WebSocket-Version: 13",
            "Accept: */*",
        ]
        if auth:
            lines.append(f"Authorization: {auth}")
        return ("\r\n".join(lines) + "\r\n\r\n").encode()

    # ── Connexion 1 : obtenir le challenge ──
    sock1 = _open_tls(host, port, ctx)
    try:
        sock1.sendall(ws_request())
        resp1 = _recv_headers(sock1)
    finally:
        sock1.close()

    resp1_str = resp1.decode(errors="replace")
    _LOGGER.debug("[TYDOM] Réponse challenge : %s", resp1_str[:200])

    m = re.search(r'WWW-Authenticate: (.+)\r\n', resp1_str, re.IGNORECASE)
    if not m:
        raise ConnectionError(
            f"Pas de WWW-Authenticate (status={resp1_str.split(' ')[1] if ' ' in resp1_str else '?'})"
        )

    chal   = _parse_www_auth(m.group(1).strip())
    nonce  = chal.get("nonce", "")
    realm  = chal.get("realm", "Protected Area")
    opaque = chal.get("opaque", "")
    _LOGGER.debug("[TYDOM] realm=%r nonce=%s", realm, nonce[:16])

    auth = _calc_digest(mac, password, nonce, realm, opaque, uri)
    _LOGGER.debug("[TYDOM] Authorization: %s", auth)

    # ── Connexion 2 : WebSocket avec Authorization ──
    sock2 = _open_tls(host, port, ctx)
    sock2.sendall(ws_request(auth))
    resp2 = _recv_headers(sock2)

    resp2_str = resp2.decode(errors="replace")
    status2   = resp2_str.split(" ")[1].split("\r")[0].strip() if " " in resp2_str else "?"
    _LOGGER.debug("[TYDOM] Status WebSocket : %s", status2)

    if status2 != "101":
        sock2.close()
        raise PermissionError(
            f"Handshake WebSocket refusé (status={status2}). "
            f"Vérifiez le mot de passe Tydom."
        )

    return sock2


# ---------------------------------------------------------------------------
# Client principal
# ---------------------------------------------------------------------------

class TydomClient:
    """Client asynchrone pour la box Tydom (mode local)."""

    def __init__(
        self,
        mac: str,
        password: str,
        host: str,
        *,
        message_callback: Callable[[str, Any], None] | None = None,
    ) -> None:
        self._mac      = mac.upper().replace(":", "").replace("-", "")
        self._password = password
        self._host     = host
        self._message_callback = message_callback

        self._sock: ssl.SSLSocket | None = None
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._listen_task: asyncio.Task | None = None
        self._connected = False
        self._transac_id = 0

        _LOGGER.debug("TydomClient — host=%s, mac=%s", self._host, self._mac)

    # ------------------------------------------------------------------
    # Connexion
    # ------------------------------------------------------------------

    async def connect(self) -> bool:
        _LOGGER.info("Connexion Tydom (%s)…", self._host)
        loop = asyncio.get_event_loop()

        try:
            sock = await loop.run_in_executor(
                None, _do_handshake_sync,
                self._host, TYDOM_PORT, self._mac, self._password,
            )
        except PermissionError as exc:
            _LOGGER.error("%s", exc)
            return False
        except Exception as exc:
            _LOGGER.error("Impossible de contacter la box Tydom : %s", exc)
            return False

        # Wrapper le socket TLS déjà établi dans asyncio StreamReader/Writer
        # ssl=None important : le TLS est déjà actif sur le socket, pas de re-wrap
        try:
            self._reader, self._writer = await asyncio.open_connection(
                sock=sock, ssl=None
            )
        except Exception as exc:
            _LOGGER.error("Impossible d'initialiser les streams asyncio : %s", exc)
            sock.close()
            return False

        self._sock      = sock
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
        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass
        self._reader = self._writer = self._sock = None

    # ------------------------------------------------------------------
    # Envoi / réception
    # ------------------------------------------------------------------

    def _next_transac_id(self) -> int:
        self._transac_id = (self._transac_id + 1) % 10000
        return self._transac_id

    def _build_get(self, path: str) -> bytes:
        tid = self._next_transac_id()
        return _ws_encode(
            f"GET {path} HTTP/1.1\r\nContent-Length: 0\r\n"
            f"Content-Type: application/json; charset=UTF-8\r\n"
            f"Transac-Id: {tid}\r\n\r\n".encode("ascii")
        )

    def _build_put(self, path: str, body: str) -> bytes:
        tid = self._next_transac_id()
        return _ws_encode(
            f"PUT {path} HTTP/1.1\r\nContent-Length: {len(body)}\r\n"
            f"Content-Type: application/json; charset=UTF-8\r\n"
            f"Transac-Id: {tid}\r\n\r\n{body}\r\n\r\n".encode("ascii")
        )

    async def _send_frame(self, frame: bytes) -> None:
        if not self._writer or not self._connected:
            raise ConnectionError("Non connecté")
        self._writer.write(frame)
        await self._writer.drain()

    async def _recv_frame(self, timeout: float = 10.0) -> bytes:
        """Reçoit une frame WebSocket complète."""
        if not self._reader:
            raise ConnectionError("Non connecté")

        header = await asyncio.wait_for(self._reader.readexactly(2), timeout=timeout)
        opcode    = header[0] & 0x0F
        payload_len = header[1] & 0x7F

        if payload_len == 126:
            ext = await asyncio.wait_for(self._reader.readexactly(2), timeout=timeout)
            payload_len = struct.unpack("!H", ext)[0]
        elif payload_len == 127:
            ext = await asyncio.wait_for(self._reader.readexactly(8), timeout=timeout)
            payload_len = struct.unpack("!Q", ext)[0]

        payload = await asyncio.wait_for(self._reader.readexactly(payload_len), timeout=timeout)

        # PING → répondre PONG automatiquement
        if opcode == 0x9:
            await self._send_frame(_ws_pong_frame(payload))
            return await self._recv_frame(timeout)

        # CLOSE
        if opcode == 0x8:
            self._connected = False
            return b""

        return header[:1] + header[1:2] + payload

    async def _request(self, frame: bytes) -> dict | list | None:
        await self._send_frame(frame)
        raw = await self._recv_frame()
        return _extract_json(_ws_decode(raw))

    # ------------------------------------------------------------------
    # Requêtes de haut niveau
    # ------------------------------------------------------------------

    async def get(self, path: str) -> dict | list | None:
        return await self._request(self._build_get(path))

    async def put(self, path: str, body: list | dict) -> None:
        await self._send_frame(self._build_put(path, json.dumps(body)))

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

    # ------------------------------------------------------------------
    # Écoute des messages push
    # ------------------------------------------------------------------

    async def listen(self) -> None:
        _LOGGER.debug("Écoute Tydom démarrée")
        while self._connected:
            try:
                raw = await self._recv_frame(timeout=60)
                if not raw:
                    continue
                payload = _ws_decode(raw)
                if not payload:
                    continue
                uri_origin = _get_uri_origin(payload)
                data       = _extract_json(payload)
                if data is not None and self._message_callback and uri_origin:
                    try:
                        self._message_callback(uri_origin, data)
                    except Exception as exc:
                        _LOGGER.error("Erreur callback : %s", exc)
            except asyncio.TimeoutError:
                # Keepalive ping
                if self._connected:
                    try:
                        await self._send_frame(_ws_ping_frame())
                    except Exception:
                        self._connected = False
                        break
            except asyncio.CancelledError:
                break
            except Exception as exc:
                _LOGGER.error("Erreur écoute Tydom : %s", exc)
                self._connected = False
                break
        _LOGGER.debug("Écoute Tydom terminée")

    def start_listening(self) -> asyncio.Task:
        self._listen_task = asyncio.ensure_future(self.listen())
        return self._listen_task

    @property
    def is_connected(self) -> bool:
        return self._connected and self._writer is not None
