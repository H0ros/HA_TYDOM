"""Client WebSocket pour la box Tydom de Delta Dore.

Protocole :
1. Connexion HTTPS vers la box pour récupérer le challenge Digest (WWW-Authenticate)
2. Calcul de la réponse Digest (requests.auth.HTTPDigestAuth)
3. Ouverture du WebSocket avec l'en-tête Authorization calculé
4. Envoi de requêtes HTTP/1.1 encapsulées dans le WebSocket
5. Réception et parsing des réponses HTTP/1.1 chunked encapsulées

Ce mécanisme est identique à celui utilisé par tydom2mqtt et tydom_python,
qui fonctionnent de manière éprouvée sur Tydom 1.0.
"""
from __future__ import annotations

import asyncio
import base64
import http.client
import json
import logging
import os
import ssl
import urllib3
from http.client import HTTPResponse
from http.server import BaseHTTPRequestHandler
from io import BytesIO
from typing import Any, Callable

import websockets
from requests.auth import HTTPDigestAuth

_LOGGER = logging.getLogger(__name__)

# Port de la box Tydom (local)
TYDOM_PORT = 443
# URI de médiation (locale et distante)
MEDIATION_URI = "/mediation/client?mac={mac}&appli=1"
TYDOM_REMOTE_HOST = "mediation.tydom.com"


# ---------------------------------------------------------------------------
# Helpers pour parser les réponses HTTP/1.1 encapsulées dans le WebSocket
# ---------------------------------------------------------------------------

class _BytesIOSocket:
    """Adaptateur socket pour http.client.HTTPResponse."""

    def __init__(self, content: bytes) -> None:
        self.handle = BytesIO(content)

    def makefile(self, mode: str):
        return self.handle


class _FakeHTTPResponse(BaseHTTPRequestHandler):
    """Parse une requête HTTP brute (utilisé pour les PUT responses)."""

    def __init__(self, request_text: bytes) -> None:
        self.raw_requestline = request_text
        self.error_code = self.error_message = None
        self.parse_request()

    def send_error(self, code, message=None, explain=None):
        self.error_code = code
        self.error_message = message


def _response_from_bytes(data: bytes) -> urllib3.HTTPResponse:
    """Convertit des bytes bruts en objet HTTPResponse."""
    sock = _BytesIOSocket(data)
    response = HTTPResponse(sock)
    response.begin()
    return urllib3.HTTPResponse.from_httplib(response)


def _parse_chunked_body(raw: str) -> str:
    """Décode un body HTTP/1.1 en Transfer-Encoding: chunked."""
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
        # La donnée suit sur la ligne d'après
        if i + 1 < len(lines):
            output.append(lines[i + 1])
        i += 2
    return "".join(output)


def _extract_json_from_response(raw_bytes: bytes, cmd_prefix: str = "") -> dict | list | None:
    """Extrait et parse le JSON d'une réponse HTTP Tydom encapsulée."""
    try:
        raw = raw_bytes[len(cmd_prefix):].decode("utf-8", errors="replace")

        # Sépare les headers du body
        if "\r\n\r\n" in raw:
            headers_part, body_part = raw.split("\r\n\r\n", 1)
        else:
            return None

        # Vérifie le statut HTTP
        first_line = headers_part.split("\r\n")[0]
        if not first_line.startswith("HTTP/"):
            return None

        # Décode chunked si nécessaire
        headers_lower = headers_part.lower()
        if "transfer-encoding: chunked" in headers_lower:
            body_part = _parse_chunked_body(body_part)

        body_part = body_part.strip()
        if not body_part:
            return None

        return json.loads(body_part)

    except Exception as exc:
        _LOGGER.debug("Impossible de parser la réponse Tydom : %s", exc)
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
# Client principal
# ---------------------------------------------------------------------------

class TydomClient:
    """Client asynchrone pour la box Tydom (Tydom 1.0 en mode local)."""

    def __init__(
        self,
        mac: str,
        password: str,
        host: str | None = None,
        *,
        message_callback: Callable[[str, Any], None] | None = None,
    ) -> None:
        self._mac = mac.upper().replace(":", "")
        self._password = password
        self._host = host or f"{self._mac}-tydom.local"
        self._message_callback = message_callback

        # Mode local si une IP ou hostname local est fourni, sinon remote
        self._remote = (self._host == TYDOM_REMOTE_HOST)
        self._cmd_prefix = "\x02" if self._remote else ""

        self._websocket: websockets.WebSocketClientProtocol | None = None
        self._listen_task: asyncio.Task | None = None
        self._connected = False
        self._transac_id = 0

        _LOGGER.debug(
            "TydomClient initialisé — host=%s, mac=%s, remote=%s",
            self._host,
            self._mac,
            self._remote,
        )

    # ------------------------------------------------------------------
    # Connexion
    # ------------------------------------------------------------------

    def _build_ssl_context(self) -> ssl.SSLContext:
        """Crée un contexte SSL sans vérification (certificat auto-signé Tydom)."""
        ctx = ssl._create_unverified_context()
        return ctx

    def _get_websocket_key(self) -> str:
        return base64.b64encode(os.urandom(16)).decode("ascii")

    def _build_digest_header(self, nonce_header: str) -> str:
        """Calcule l'en-tête Authorization Digest à partir du challenge WWW-Authenticate."""
        # Découpe le header : "Digest realm=..., qop=..., nonce=..."
        parts = [p.strip() for p in nonce_header.replace("Digest ", "").split(",")]
        chal: dict[str, str] = {}
        for part in parts:
            if "=" in part:
                k, v = part.split("=", 1)
                chal[k.strip()] = v.strip().strip('"')

        nonce = chal.get("nonce", "")
        realm = chal.get("realm", "protected area")

        digest_auth = HTTPDigestAuth(self._mac, self._password)
        digest_auth._thread_local.chal = {
            "nonce": nonce,
            "realm": realm,
            "qop": "auth",
        }
        digest_auth._thread_local.last_nonce = nonce
        digest_auth._thread_local.nonce_count = 1

        uri = f"https://{self._host}:{TYDOM_PORT}{MEDIATION_URI.format(mac=self._mac)}"
        return digest_auth.build_digest_header("GET", uri)

    async def connect(self) -> bool:
        """Effectue le handshake et ouvre le WebSocket."""
        _LOGGER.info("Connexion à la box Tydom (%s)…", self._host)

        ssl_context = self._build_ssl_context()
        http_headers = {
            "Connection": "Upgrade",
            "Upgrade": "websocket",
            "Host": f"{self._host}:{TYDOM_PORT}",
            "Accept": "*/*",
            "Sec-WebSocket-Key": self._get_websocket_key(),
            "Sec-WebSocket-Version": "13",
        }

        uri_path = MEDIATION_URI.format(mac=self._mac)

        # --- Étape 1 : handshake HTTP pour récupérer le challenge Digest ---
        try:
            conn = http.client.HTTPSConnection(
                self._host, TYDOM_PORT, context=ssl_context, timeout=10
            )
            conn.request("GET", uri_path, None, http_headers)
            res = conn.getresponse()
            www_auth = res.headers.get("WWW-Authenticate", "")
            res.read()
            conn.close()
        except Exception as exc:
            _LOGGER.error("Impossible de contacter la box Tydom : %s", exc)
            return False

        if not www_auth:
            _LOGGER.error("Pas de challenge Digest reçu (WWW-Authenticate vide)")
            return False

        _LOGGER.debug("Challenge Digest reçu : %s", www_auth)

        # --- Étape 2 : calcul de la réponse Digest ---
        try:
            authorization = self._build_digest_header(www_auth)
        except Exception as exc:
            _LOGGER.error("Erreur lors du calcul du header Digest : %s", exc)
            return False

        _LOGGER.debug("Authorization calculée : %s", authorization)

        # --- Étape 3 : ouverture du WebSocket avec Authorization ---
        ws_uri = f"wss://{self._host}:{TYDOM_PORT}{uri_path}"
        ws_headers = {"Authorization": authorization}

        try:
            self._websocket = await websockets.connect(
                ws_uri,
                extra_headers=ws_headers,
                ssl=ssl_context,
                ping_interval=30,
                ping_timeout=10,
                close_timeout=5,
            )
        except Exception as exc:
            _LOGGER.error("Impossible d'ouvrir le WebSocket Tydom : %s", exc)
            return False

        self._connected = True
        _LOGGER.info("WebSocket Tydom connecté avec succès")
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
        req = (
            f"{self._cmd_prefix}GET {path} HTTP/1.1\r\n"
            f"Content-Length: 0\r\n"
            f"Content-Type: application/json; charset=UTF-8\r\n"
            f"Transac-Id: {tid}\r\n\r\n"
        )
        return req.encode("ascii")

    def _build_put_request(self, path: str, body: str) -> bytes:
        tid = self._next_transac_id()
        req = (
            f"{self._cmd_prefix}PUT {path} HTTP/1.1\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Content-Type: application/json; charset=UTF-8\r\n"
            f"Transac-Id: {tid}\r\n\r\n"
            f"{body}\r\n\r\n"
        )
        return req.encode("ascii")

    async def _send(self, data: bytes) -> None:
        if not self._websocket or not self._connected:
            raise ConnectionError("WebSocket non connecté")
        await self._websocket.send(data)

    async def get(self, path: str) -> dict | list | None:
        """Envoie une requête GET et attend la réponse."""
        await self._send(self._build_get_request(path))
        raw = await self._websocket.recv()
        return _extract_json_from_response(raw if isinstance(raw, bytes) else raw.encode(), self._cmd_prefix)

    async def put(self, path: str, body_dict: list | dict) -> None:
        """Envoie une requête PUT (commande vers un device)."""
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
        """Envoie une commande vers un endpoint."""
        path = f"/devices/{device_id}/endpoints/{endpoint_id}/data"
        body = [{"name": name, "value": value}]
        await self.put(path, body)

    # ------------------------------------------------------------------
    # Écoute des messages push (loop)
    # ------------------------------------------------------------------

    async def listen(self) -> None:
        """Écoute en boucle les messages push de la box."""
        if not self._websocket or not self._connected:
            _LOGGER.error("listen() appelé sans connexion active")
            return

        _LOGGER.debug("Début de l'écoute des messages Tydom")
        try:
            async for message in self._websocket:
                raw = message if isinstance(message, bytes) else message.encode()
                await self._handle_raw_message(raw)
        except websockets.ConnectionClosed:
            _LOGGER.warning("Connexion Tydom fermée")
            self._connected = False
        except Exception as exc:
            _LOGGER.error("Erreur dans la boucle d'écoute Tydom : %s", exc)
            self._connected = False

    async def _handle_raw_message(self, raw: bytes) -> None:
        """Parse un message brut et appelle le callback si disponible."""
        uri_origin = _get_uri_origin(raw, self._cmd_prefix)
        data = _extract_json_from_response(raw, self._cmd_prefix)

        if data is None:
            return

        _LOGGER.debug("Message Tydom reçu [%s] : %s", uri_origin, data)

        if self._message_callback and uri_origin:
            try:
                self._message_callback(uri_origin, data)
            except Exception as exc:
                _LOGGER.error("Erreur dans le callback de message Tydom : %s", exc)

    def start_listening(self, loop: asyncio.AbstractEventLoop | None = None) -> asyncio.Task:
        """Lance la boucle d'écoute en tâche de fond."""
        self._listen_task = asyncio.ensure_future(self.listen())
        return self._listen_task

    @property
    def is_connected(self) -> bool:
        return self._connected and self._websocket is not None