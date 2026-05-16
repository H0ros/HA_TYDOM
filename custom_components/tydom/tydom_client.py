"""Client WebSocket pour la box Tydom de Delta Dore.

Protocole de connexion (validé empiriquement) :
  1. Connexion TLS 1 → GET avec headers WebSocket → 401 + nonce
  2. Connexion TLS 2 → GET avec Authorization Digest(nonce) → 101 Switching Protocols
  3. Lecture/écriture directe sur le SSLSocket via run_in_executor (pas de asyncio streams)
  4. Framing WebSocket manuel (RFC 6455)

Points clés :
- Mot de passe récupéré depuis l'API Delta Dore (pas le PIN étiquette)
- realm en minuscules pour le calcul Digest
- cnonce en hexadécimal
- qop="auth" avec guillemets
- ssl.SSLContext(PROTOCOL_TLS_CLIENT) + SECLEVEL=1 pour OpenSSL 3.x
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

TYDOM_PORT    = 443
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


def _ws_ping_frame() -> bytes:
    mask = os.urandom(4)
    return struct.pack("!BB", 0x89, 0x80) + mask


def _ws_pong_frame(payload: bytes = b"") -> bytes:
    mask   = os.urandom(4)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return struct.pack("!BB", 0x8A, 0x80 | len(payload)) + mask + masked


# ---------------------------------------------------------------------------
# Lecture bloquante sur SSLSocket (pour executor)
# ---------------------------------------------------------------------------

def _sock_recv_exact(sock: ssl.SSLSocket, n: int) -> bytes:
    """Lit exactement n octets depuis le socket (bloquant)."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connexion fermée par la box Tydom")
        buf += chunk
    return buf


def _sock_recv_frame(sock: ssl.SSLSocket) -> tuple[int, bytes]:
    """Lit une frame WebSocket complète (bloquant). Retourne (opcode, payload)."""
    header = _sock_recv_exact(sock, 2)
    opcode      = header[0] & 0x0F
    payload_len = header[1] & 0x7F

    if payload_len == 126:
        ext         = _sock_recv_exact(sock, 2)
        payload_len = struct.unpack("!H", ext)[0]
    elif payload_len == 127:
        ext         = _sock_recv_exact(sock, 8)
        payload_len = struct.unpack("!Q", ext)[0]

    payload = _sock_recv_exact(sock, payload_len)
    return opcode, payload


def _sock_send_frame(sock: ssl.SSLSocket, frame: bytes) -> None:
    """Envoie une frame WebSocket (bloquant)."""
    sock.sendall(frame)


# ---------------------------------------------------------------------------
# Helpers de parsing des réponses HTTP encapsulées
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
# SSL context
# ---------------------------------------------------------------------------

def _build_ssl_context() -> ssl.SSLContext:
    """Contexte SSL compatible avec le firmware TLS de la Tydom 1.0.

    Python 3.14 / OpenSSL 3.x désactive le legacy renegotiation par défaut.
    On crée un fichier openssl.cnf temporaire qui le réactive.
    """
    import os
    import tempfile

    # Créer un fichier openssl.cnf temporaire qui autorise le legacy renegotiation
    openssl_conf = """
openssl_conf = openssl_init

[openssl_init]
ssl_conf = ssl_sect

[ssl_sect]
system_default = system_default_sect

[system_default_sect]
Options = UnsafeLegacyRenegotiation
MinProtocol = TLSv1
CipherString = DEFAULT:@SECLEVEL=1
"""
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".cnf", delete=False)
    tmp.write(openssl_conf)
    tmp.flush()
    tmp.close()

    # Pointer OpenSSL vers notre config temporaire
    old_conf = os.environ.get("OPENSSL_CONF")
    os.environ["OPENSSL_CONF"] = tmp.name

    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        ctx.options |= getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4)
        ctx.options |= 0x4
        try:
            ctx.set_ciphers("DEFAULT:@SECLEVEL=1")
        except ssl.SSLError:
            pass
    finally:
        # Restaurer la variable d'environnement
        if old_conf is None:
            os.environ.pop("OPENSSL_CONF", None)
        else:
            os.environ["OPENSSL_CONF"] = old_conf
        try:
            os.unlink(tmp.name)
        except Exception:
            pass

    return ctx


# ---------------------------------------------------------------------------
# Handshake (synchrone → executor)
# ---------------------------------------------------------------------------

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
    sock.settimeout(None)  # Remettre en mode bloquant
    return resp


def _do_handshake_sync(host: str, port: int, mac: str, password: str) -> ssl.SSLSocket:
    """Effectue le handshake Tydom en 2 connexions TLS.
    Synchrone — appelé via loop.run_in_executor().
    """
    ctx = _build_ssl_context()
    uri = MEDIATION_URI.format(mac=mac)

    def ws_request(auth: str | None = None) -> bytes:
        key   = base64.b64encode(os.urandom(16)).decode()
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

    # Connexion 1 : challenge
    sock1 = _open_tls(host, port, ctx)
    try:
        sock1.sendall(ws_request())
        resp1 = _recv_headers(sock1)
    finally:
        sock1.close()

    resp1_str = resp1.decode(errors="replace")
    _LOGGER.debug("[TYDOM] Challenge : %s", resp1_str[:300])

    m = re.search(r'WWW-Authenticate: (.+)\r\n', resp1_str, re.IGNORECASE)
    if not m:
        raise ConnectionError(
            f"Pas de WWW-Authenticate. Réponse : {resp1_str[:200]}"
        )

    chal   = _parse_www_auth(m.group(1).strip())
    nonce  = chal.get("nonce", "")
    realm  = chal.get("realm", "Protected Area")
    opaque = chal.get("opaque", "")
    _LOGGER.debug("[TYDOM] realm=%r nonce=%s", realm, nonce[:16])

    auth = _calc_digest(mac, password, nonce, realm, opaque, uri)

    # Connexion 2 : WebSocket
    sock2 = _open_tls(host, port, ctx)
    sock2.sendall(ws_request(auth))
    resp2     = _recv_headers(sock2)
    resp2_str = resp2.decode(errors="replace")
    status2   = resp2_str.split(" ")[1].split("\r")[0].strip() if " " in resp2_str else "?"
    _LOGGER.debug("[TYDOM] Status WebSocket : %s", status2)

    if status2 != "101":
        sock2.close()
        raise PermissionError(
            f"Handshake refusé (status={status2}). Vérifiez le mot de passe Tydom."
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
        self._listen_task: asyncio.Task | None = None
        self._connected = False
        self._transac_id = 0
        self._send_lock = asyncio.Lock()

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
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    # ------------------------------------------------------------------
    # Envoi / réception via executor
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

    async def _send(self, frame: bytes) -> None:
        if not self._sock or not self._connected:
            raise ConnectionError("Non connecté")
        loop = asyncio.get_event_loop()
        async with self._send_lock:
            await loop.run_in_executor(None, _sock_send_frame, self._sock, frame)

    async def _recv(self, timeout: float = 10.0) -> tuple[int, bytes]:
        if not self._sock:
            raise ConnectionError("Non connecté")
        loop = asyncio.get_event_loop()
        return await asyncio.wait_for(
            loop.run_in_executor(None, _sock_recv_frame, self._sock),
            timeout=timeout,
        )

    async def _request(self, frame: bytes) -> dict | list | None:
        await self._send(frame)
        accumulated = b""
        while True:
            opcode, payload = await self._recv(timeout=15.0)
            if opcode == 0x9:  # PING
                await self._send(_ws_pong_frame(payload))
                continue
            if opcode == 0x8:  # CLOSE
                self._connected = False
                return None

            accumulated += payload

            # Tenter de parser — si incomplet, continuer à accumuler
            result = _extract_json(accumulated)
            if result is not None:
                return result

            # Vérifier si la réponse HTTP est complète (fin du chunked encoding)
            raw = accumulated.decode("utf-8", errors="replace")
            if "0\r\n\r\n" in raw or (
                "\r\n\r\n" in raw
                and "transfer-encoding: chunked" not in raw.lower()
            ):
                # Réponse non-chunked ou chunked terminée mais JSON invalide
                _LOGGER.debug("Réponse incomplète ou non-JSON : %s", raw[:200])
                return None

    # ------------------------------------------------------------------
    # Requêtes de haut niveau
    # ------------------------------------------------------------------

    async def get(self, path: str) -> dict | list | None:
        return await self._request(self._build_get(path))

    async def put(self, path: str, body: list | dict) -> None:
        await self._send(self._build_put(path, json.dumps(body)))

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
        loop = asyncio.get_event_loop()
        while self._connected:
            try:
                opcode, payload = await asyncio.wait_for(
                    loop.run_in_executor(None, _sock_recv_frame, self._sock),
                    timeout=60,
                )
                if opcode == 0x9:  # PING
                    await self._send(_ws_pong_frame(payload))
                    continue
                if opcode == 0x8:  # CLOSE
                    self._connected = False
                    break
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
                if self._connected:
                    try:
                        await self._send(_ws_ping_frame())
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
        return self._connected and self._sock is not None
