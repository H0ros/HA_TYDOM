"""Client WebSocket pour la box Tydom Delta Dore."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import ssl
import time
from http.client import HTTPSConnection
from typing import Any, Callable

import websockets
from websockets.exceptions import ConnectionClosed

_LOGGER = logging.getLogger(__name__)

TYDOM_HOST = "{mac_address}-tydom.local"
TYDOM_URL = "wss://{host}/mediation/client?mac={mac}&appli=1"

# Commandes Tydom
CMD_GET_DEVICES = "/devices/data"
CMD_GET_CONFIGS = "/devices/cconfig"
CMD_GET_META = "/devices/meta"
CMD_GET_INFOS = "/infos"
CMD_POST_REFRESH = "/refresh/all"


class TydomClient:
    """Client pour communiquer avec la box Tydom via WebSocket."""

    def __init__(
        self,
        mac_address: str,
        password: str,
        host: str | None = None,
        callback: Callable | None = None,
    ) -> None:
        """Initialise le client Tydom."""
        self.mac = mac_address.upper().replace(":", "")
        self.password = password
        self.host = host or TYDOM_HOST.format(mac_address=self.mac.lower())
        self.callback = callback
        self._websocket = None
        self._running = False
        self._msg_id = 0
        self._ssl_context = self._create_ssl_context()

    def _create_ssl_context(self) -> ssl.SSLContext:
        """Crée un contexte SSL sans vérification de certificat."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context

    def _get_credentials(self) -> str:
        """Génère les credentials d'authentification Tydom."""
        # La box Tydom utilise le protocole HTTP Digest avec WebSocket
        # Username = adresse MAC, password = code Tydom
        credentials = f"{self.mac}:{self.password}"
        encoded = base64.b64encode(credentials.encode()).decode()
        return encoded

    def _next_msg_id(self) -> str:
        """Retourne le prochain ID de message."""
        self._msg_id += 1
        return str(self._msg_id)

    def _build_http_request(self, method: str, uri: str, body: str = "") -> str:
        """Construit une requête HTTP/1.1 formatée pour Tydom."""
        msg_id = self._next_msg_id()
        headers = [
            f"{method} {uri} HTTP/1.1",
            f"Host: {self.host}",
            f"Content-Length: {len(body)}",
            f"Content-Type: application/json; charset=UTF-8",
            f"Transac-Id: {msg_id}",
        ]
        if body:
            return "\r\n".join(headers) + "\r\n\r\n" + body
        return "\r\n".join(headers) + "\r\n\r\n"

    async def _authenticate(self, websocket) -> bool:
        """Authentifie le client auprès de la box Tydom."""
        # Étape 1 : Récupérer le challenge (nonce)
        await websocket.send(self._build_http_request("GET", "/mediation/client?mac={}&appli=1".format(self.mac)))
        
        try:
            response = await asyncio.wait_for(websocket.recv(), timeout=10)
            _LOGGER.debug("Challenge reçu: %s", response[:200])
        except asyncio.TimeoutError:
            _LOGGER.error("Timeout en attendant le challenge d'authentification")
            return False

        # Chercher le nonce dans la réponse 401
        nonce = None
        for line in response.split("\r\n"):
            if "Nonce=" in line or "nonce=" in line.lower():
                try:
                    nonce = line.split('"')[1]
                    break
                except (IndexError, ValueError):
                    pass

        if not nonce:
            # Peut-être déjà authentifié ou pas de challenge requis
            _LOGGER.debug("Pas de nonce trouvé, authentification directe")
            return True

        # Étape 2 : Calculer la réponse Digest
        ha1 = hashlib.md5(f"{self.mac}:MDCOM:{self.password}".encode()).hexdigest()
        ha2 = hashlib.md5(f"GET:/mediation/client?mac={self.mac}&appli=1".encode()).hexdigest()
        digest = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()

        auth_header = (
            f'Authorization: Digest username="{self.mac}", '
            f'realm="MDCOM", nonce="{nonce}", '
            f'uri="/mediation/client?mac={self.mac}&appli=1", '
            f'response="{digest}"'
        )

        auth_request = (
            f"GET /mediation/client?mac={self.mac}&appli=1 HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"{auth_header}\r\n\r\n"
        )

        await websocket.send(auth_request)

        try:
            auth_response = await asyncio.wait_for(websocket.recv(), timeout=10)
            _LOGGER.debug("Réponse auth: %s", auth_response[:200])
            if "200 OK" in auth_response or "101" in auth_response:
                _LOGGER.info("Authentification réussie")
                return True
            else:
                _LOGGER.error("Authentification échouée: %s", auth_response[:200])
                return False
        except asyncio.TimeoutError:
            _LOGGER.error("Timeout pendant l'authentification")
            return False

    async def connect(self) -> bool:
        """Établit la connexion WebSocket avec la box Tydom."""
        url = TYDOM_URL.format(host=self.host, mac=self.mac)
        
        extra_headers = {
            "Authorization": "Basic " + self._get_credentials(),
        }

        try:
            _LOGGER.info("Connexion à Tydom: %s", url)
            self._websocket = await asyncio.wait_for(
                websockets.connect(
                    url,
                    ssl=self._ssl_context,
                    additional_headers=extra_headers,
                    ping_interval=30,
                    ping_timeout=10,
                    close_timeout=5,
                ),
                timeout=15,
            )
            _LOGGER.info("Connexion WebSocket établie avec succès")
            return True
        except asyncio.TimeoutError:
            _LOGGER.error("Timeout de connexion à %s", url)
            return False
        except Exception as err:
            _LOGGER.error("Erreur de connexion: %s", err)
            return False

    async def disconnect(self) -> None:
        """Ferme la connexion WebSocket."""
        self._running = False
        if self._websocket:
            try:
                await self._websocket.close()
            except Exception:
                pass
            self._websocket = None

    async def send_message(self, method: str, uri: str, body: dict | None = None) -> None:
        """Envoie un message à la box Tydom."""
        if not self._websocket:
            raise ConnectionError("Non connecté à la box Tydom")
        
        body_str = json.dumps(body) if body else ""
        request = self._build_http_request(method, uri, body_str)
        
        try:
            await self._websocket.send(request)
            _LOGGER.debug("Message envoyé: %s %s", method, uri)
        except ConnectionClosed:
            _LOGGER.error("Connexion fermée lors de l'envoi")
            raise

    async def get_devices(self) -> None:
        """Demande les données de tous les équipements."""
        await self.send_message("GET", CMD_GET_DEVICES)

    async def get_configs(self) -> None:
        """Demande la configuration de tous les équipements."""
        await self.send_message("GET", CMD_GET_CONFIGS)

    async def get_info(self) -> None:
        """Demande les informations de la box."""
        await self.send_message("GET", CMD_GET_INFOS)

    async def refresh_all(self) -> None:
        """Demande un rafraîchissement de tous les équipements."""
        await self.send_message("POST", CMD_POST_REFRESH)

    async def set_device_data(self, device_id: str, endpoint_id: str, data: list) -> None:
        """Envoie une commande à un équipement."""
        uri = f"/devices/{device_id}/endpoints/{endpoint_id}/data"
        await self.send_message("PUT", uri, data)

    def _parse_response(self, raw: str) -> dict | list | None:
        """Parse une réponse HTTP Tydom."""
        try:
            # Chercher le body JSON après les headers HTTP
            parts = raw.split("\r\n\r\n", 1)
            if len(parts) < 2:
                return None
            
            body = parts[1].strip()
            if not body:
                return None

            # Gérer le chunked encoding
            if "\r\n" in body:
                lines = body.split("\r\n")
                body = "".join(
                    line for line in lines 
                    if not all(c in "0123456789abcdefABCDEF" for c in line.strip()) or not line.strip()
                )

            return json.loads(body)
        except (json.JSONDecodeError, ValueError) as err:
            _LOGGER.debug("Impossible de parser la réponse JSON: %s", err)
            return None

    async def listen(self) -> None:
        """Écoute les messages entrants de la box Tydom."""
        self._running = True
        
        while self._running:
            if not self._websocket:
                _LOGGER.warning("WebSocket non connecté, tentative de reconnexion...")
                success = await self.connect()
                if not success:
                    await asyncio.sleep(30)
                    continue
                # Demander les données initiales
                await self.get_devices()
                await self.get_configs()

            try:
                raw_message = await asyncio.wait_for(
                    self._websocket.recv(), timeout=60
                )
                
                _LOGGER.debug("Message brut reçu: %s", raw_message[:500])
                
                parsed = self._parse_response(raw_message)
                if parsed and self.callback:
                    # Extraire le type depuis les headers HTTP
                    msg_type = self._extract_msg_type(raw_message)
                    await self.callback(msg_type, parsed)

            except asyncio.TimeoutError:
                # Envoyer un ping pour maintenir la connexion
                try:
                    await self.send_message("GET", CMD_GET_INFOS)
                except Exception:
                    self._websocket = None
            except ConnectionClosed:
                _LOGGER.warning("Connexion WebSocket fermée, reconnexion...")
                self._websocket = None
                await asyncio.sleep(5)
            except Exception as err:
                _LOGGER.error("Erreur lors de la réception: %s", err)
                await asyncio.sleep(5)

    def _extract_msg_type(self, raw: str) -> str:
        """Extrait le type de message depuis l'URI HTTP."""
        try:
            first_line = raw.split("\r\n")[0]
            if CMD_GET_DEVICES in first_line or "/devices/" in first_line:
                return "devices_data"
            elif CMD_GET_CONFIGS in first_line:
                return "devices_config"
            elif CMD_GET_META in first_line:
                return "devices_meta"
            elif CMD_GET_INFOS in first_line:
                return "info"
            elif "PUT" in first_line:
                return "put_response"
        except Exception:
            pass
        return "unknown"

    async def ping(self) -> bool:
        """Teste la connexion avec la box Tydom."""
        try:
            await self.get_info()
            return True
        except Exception:
            return False
