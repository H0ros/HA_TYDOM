"""Client WebSocket pour la box Tydom de Delta Dore.

Protocole (une seule connexion TCP) :
1. Ouverture connexion TLS vers la box (http.client.HTTPSConnection)
2. GET /mediation/... → 401 + WWW-Authenticate: Digest  (challenge)
3. Calcul de la réponse Digest RFC 2617 (hashlib MD5)
4. GET /mediation/... avec Authorization: Digest → 101 Switching Protocols
5. Récupération du socket TLS sous-jacent (conn.sock)
6. Passage de ce socket à websockets.connect(sock=...) pour la suite

L'étape clé est que les étapes 2 à 6 se font sur la MÊME connexion TCP.
La box Tydom lie le nonce Digest à la session TCP — un nonce obtenu sur
une connexion fermée est rejeté avec HTTP 401 sur la nouvelle connexion WebSocket.
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
# Helpers de parsing des réponses HTTP/1.1 encapsulées dans le WebSocket
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

def _build_digest_header(mac: str, password: str, www_auth: str, uri: str) -> str:
    """Calcul Digest Auth RFC 2617, qop=auth, nc=00000001."""
    parts = [p.strip() for p in www_auth.replace("Digest ", "").split(",")]
    chal: dict[str, str] = {}
    for part in parts:
        if "=" in part:
            k, v = part.split("=", 1)
            chal[k.strip()] = v.strip().strip('"')

    nonce = chal.get("nonce", "")
    realm = chal.get("realm", "protected area")

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


# ---------------------------------------------------------------------------
# Handshake complet sur une seule connexion TCP (synchrone → executor)
# ---------------------------------------------------------------------------

def _do_full_handshake_sync(
    host: str, port: int, mac: str, password: str, ssl_context: ssl.SSLContext
):
    """Effectue les deux échanges HTTP sur la même connexion TCP.

    Retourne le socket TLS (conn.sock) prêt pour l'upgrade WebSocket,
    ou lève une exception en cas d'échec.

    Synchrone — doit être appelé via loop.run_in_executor().
    """
    uri = MEDIATION_URI.format(mac=mac)

    ws_headers = {
        "Connection": "Upgrade",
        "Upgrade": "websocket",
        "Host": f"{host}:{port}",
        "Accept": "*/*",
        "Sec-WebSocket-Key": base64.b64encode(os.urandom(16)).decode("ascii"),
        "Sec-WebSocket-Version": "13",
    }

    conn = http.client.HTTPSConnection(host, port, context=ssl_context, timeout=10)

    # --- Requête 1 : GET sans Authorization → la box répond 401 + challenge ---
    conn.request("GET", uri, None, ws_headers)
    res1 = conn.getresponse()
    www_auth = res1.headers.get("WWW-Authenticate", "")
    status1 = res1.status
    res1.read()

    _LOGGER.debug("Handshake req1 — status=%d, WWW-Authenticate=%s", status1, www_auth)

    if status1 != 401 or not www_auth:
        conn.close()
        raise ConnectionError(
            f"Réponse inattendue lors du handshake (status={status1}, "
            f"www_auth={www_auth!r}). Attendu: 401 + WWW-Authenticate."
        )

    # --- Calcul de l'Authorization Digest ---
    authorization = _build_digest_header(mac, password, www_auth, uri)
    _LOGGER.debug("Authorization Digest calculée: %s", authorization)

    # --- Requête 2 : GET avec Authorization → la box doit répondre 101 ---
    # IMPORTANT : on réutilise la même connexion TCP (même objet conn)
    ws_headers_with_auth = dict(ws_headers)
    ws_headers_with_auth["Authorization"] = authorization
    # Nouveau Sec-WebSocket-Key pour cette vraie requête WebSocket
    ws_headers_with_auth["Sec-WebSocket-Key"] = base64.b64encode(os.urandom(16)).decode("ascii")

    conn.request("GET", uri, None, ws_headers_with_auth)
    res2 = conn.getresponse()
    status2 = res2.status
    _LOGGER.debug("Handshake req2 — status=%d", status2)

    if status2 == 401:
        res2.read()
        conn.close()
        raise PermissionError(
            f"HTTP 401 après envoi de l'Authorization Digest. "
            f"Vérifiez le mot de passe (par défaut Tydom 1 = 6 derniers "
            f"caractères de la MAC en majuscules)."
        )

    if status2 != 101:
        body = res2.read()
        conn.close()
        raise ConnectionError(
            f"Upgrade WebSocket refusé (status={status2}). "
            f"Réponse: {body[:200]!r}"
        )

    # La connexion est maintenant en mode WebSocket
    # On récupère le socket TLS sous-jacent SANS fermer conn
    raw_sock = conn.sock
    # Détacher le socket de http.client pour éviter qu'il le ferme
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

        _LOGGER.debug("TydomClient initialisé — host=%s, mac=%s", self._host, self._mac)

    def _build_ssl_context(self) -> ssl.SSLContext:
        ctx = ssl._create_unverified_context()
        legacy_opt = getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4)
        ctx.options |= legacy_opt
        return ctx

    async def connect(self) -> bool:
        """Handshake complet + ouverture WebSocket sur la même connexion TCP."""
        _LOGGER.info("Connexion à la box Tydom (%s)…", self._host)

        ssl_context = self._build_ssl_context()
        loop = asyncio.get_event_loop()

        # Handshake complet dans un executor (opérations réseau bloquantes)
        try:
            raw_sock = await loop.run_in_executor(
                None,
                _do_full_handshake_sync,
                self._host,
                TYDOM_PORT,
                self._mac,
                self._password,
                ssl_context,
            )
        except PermissionError as exc:
            _LOGGER.error("%s", exc)
            return False
        except Exception as exc:
            _LOGGER.error("Impossible de contacter la box Tydom : %s", exc)
            return False

        # Le socket est maintenant en mode WebSocket (après 101 Switching Protocols)
        # On le passe à websockets pour gérer la couche WS
        ws_uri = f"wss://{self._host}:{TYDOM_PORT}{MEDIATION_URI.format(mac=self._mac)}"

        try:
            self._websocket = await websockets.connect(
                ws_uri,
                sock=raw_sock,
                ssl=None,          # TLS déjà établi sur raw_sock
                ping_interval=30,
                ping_timeout=10,
                close_timeout=5,
            )
        except Exception as exc:
            _LOGGER.error("Impossible d'initialiser le WebSocket sur le socket existant : %s", exc)
            try:
                raw_sock.close()
            except Exception:
                pass
            return False

        self._connected = True
        _LOGGER.info("WebSocket Tydom connecté avec succès (%s)", self._host)
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