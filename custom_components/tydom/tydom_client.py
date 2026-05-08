"""Client WebSocket pour la box Tydom Delta Dore.

Protocole réel Tydom :
  1. Connexion WSS sans credentials (la box accepte l'upgrade)
  2. La box envoie immédiatement un challenge HTTP 401 Digest dans le tunnel WS
  3. On répond avec Authorization: Digest calculé (realm=MDCOM)
  4. La box confirme avec HTTP 200 OK
  5. Toutes les commandes suivantes sont des requêtes HTTP/1.1 dans le tunnel WS
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import ssl
import uuid
from typing import Any, Callable

import websockets
from websockets.exceptions import ConnectionClosed

_LOGGER = logging.getLogger(__name__)

# mDNS local : <MAC_minuscules>-tydom.local
TYDOM_MDNS = "{mac_lower}-tydom.local"
# URL WebSocket — pas de credentials dans l'URL
TYDOM_WS_URL = "wss://{host}/mediation/client?mac={mac}&appli=1"

# Realm fixe de la box Tydom (compatible tydom2mqtt)
TYDOM_REALM = "protected area"

# Commandes internes Tydom (envoyées comme requêtes HTTP dans le tunnel WS)
CMD_GET_DEVICES = "/devices/data"
CMD_GET_CONFIGS = "/devices/cconfig"
CMD_GET_META    = "/devices/meta"
CMD_GET_INFOS   = "/infos"
CMD_POST_REFRESH = "/refresh/all"

# Délai de reconnexion
RECONNECT_DELAY = 30


class TydomClient:
    """Client Tydom : connexion WSS + authentification HTTP Digest dans le tunnel."""

    def __init__(
        self,
        mac_address: str,
        password: str,
        host: str | None = None,
        callback: Callable | None = None,
    ) -> None:
        # Normalisation MAC : "AA:BB:CC:DD:EE:FF" → "AABBCCDDEEFF"
        self.mac = mac_address.upper().replace(":", "").replace("-", "")
        self.password = password
        # Si pas d'IP fournie → découverte mDNS
        self.host = host if host else TYDOM_MDNS.format(mac_lower=self.mac.lower())
        self.callback = callback

        self._websocket = None
        self._running = False
        self._msg_id = 0
        self._ssl_context = self._make_ssl_context()
        self._nonce_count = 0  # Pour Digest auth avec qop

    # ──────────────────────────────────────────────────────────────────────
    # SSL
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def _make_ssl_context() -> ssl.SSLContext:
        """SSL sans vérification : la box utilise un certificat auto-signé.
        
        Active la renegotiation SSL non sécurisée pour compatibilité avec
        les anciennes versions du firmware Tydom qui utilisent une ancienne
        configuration SSL (UNSAFE_LEGACY_RENEGOTIATION_DISABLED).
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        # Essayer d'ajouter l'option pour la renegotiation non sécurisée
        try:
            # SSL_OP_LEGACY_SERVER_CONNECT = 0x4 (pour anciennes renegociations)
            if hasattr(ssl, 'OP_LEGACY_SERVER_CONNECT'):
                ctx.options |= ssl.OP_LEGACY_SERVER_CONNECT
                _LOGGER.debug("SSL_OP_LEGACY_SERVER_CONNECT activé")
            else:
                # Fallback pour Python < 3.10 ou versions sans cette option
                ctx.options |= 0x4
                _LOGGER.debug("SSL_OP_LEGACY_SERVER_CONNECT (0x4) ajouté via fallback")
        except Exception as e:
            _LOGGER.warning("Impossible d'ajouter SSL_OP_LEGACY_SERVER_CONNECT: %s", e)
        
        return ctx

    # ──────────────────────────────────────────────────────────────────────
    # Helpers HTTP-dans-WS
    # ──────────────────────────────────────────────────────────────────────

    def _next_id(self) -> str:
        self._msg_id += 1
        return str(self._msg_id)

    def _make_request(self, method: str, uri: str,
                      extra_headers: dict | None = None,
                      body: str = "") -> str:
        """Formate une requête HTTP/1.1 à envoyer dans le tunnel WebSocket."""
        lines = [
            f"{method} {uri} HTTP/1.1",
            f"Host: {self.host}",
            f"Transac-Id: {self._next_id()}",
            f"Content-Type: application/json; charset=UTF-8",
            f"Content-Length: {len(body.encode())}",
        ]
        if extra_headers:
            for k, v in extra_headers.items():
                lines.append(f"{k}: {v}")
        lines.append("")   # ligne vide séparatrice
        lines.append(body)
        return "\r\n".join(lines)

    @staticmethod
    def _parse_nonce(raw: str) -> str | None:
        """Extrait le nonce depuis un header WWW-Authenticate: Digest …"""
        # Cherche: nonce="<valeur>"
        m = re.search(r'[Nn]once="([^"]+)"', raw)
        return m.group(1) if m else None

    def _digest_response(self, nonce: str, uri: str | None = None) -> str:
        """
        Calcule la réponse HTTP Digest (RFC 2617 avec qop=auth).
        
        Compatible avec tydom2mqtt qui utilise :
        - qop="auth" (obligatoire pour nc et cnonce)
        - nc=nonce_count formaté en hexadécimal 8 caractères
        - cnonce=UUID générée
        - URI : par défaut URI complète https://{host}:443/mediation/client?mac={mac}&appli=1
               sinon l'URI passée en paramètre
        """
        self._nonce_count += 1
        nc = f"{self._nonce_count:08x}"  # Format hex 8 chars: "00000001"
        cnonce = str(uuid.uuid4())  # UUID comme cnonce
        qop = "auth"
        
        # URI pour le calcul du digest
        if uri is None:
            # Valeur par défaut : chemin de requête, selon RFC 2617.
            # La box Tydom attend /mediation/client?mac=...&appli=1, pas l'URL absolue.
            uri = f"/mediation/client?mac={self.mac}&appli=1"
        
        # RFC 2617 avec qop=auth :
        # HA1 = MD5(username:realm:password)
        # HA2 = MD5(method:uri)
        # response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
        ha1 = hashlib.md5(f"{self.mac}:{TYDOM_REALM}:{self.password}".encode()).hexdigest()
        ha2 = hashlib.md5(f"GET:{uri}".encode()).hexdigest()
        response = hashlib.md5(
            f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}".encode()
        ).hexdigest()
        
        _LOGGER.debug(
            "Digest calculation (qop=auth): MAC=%s, nonce=%s, nc=%s, "
            "cnonce=%s, uri=%s, ha1=%s, ha2=%s, response=%s",
            self.mac, nonce, nc, cnonce, uri, ha1, ha2, response
        )
        
        return (
            f'Digest username="{self.mac}", '
            f'realm="{TYDOM_REALM}", '
            f'nonce="{nonce}", '
            f'uri="{uri}", '
            f'qop={qop}, '
            f'nc={nc}, '
            f'cnonce="{cnonce}", '
            f'response="{response}"'
        )

    # ──────────────────────────────────────────────────────────────────────
    # Connexion + authentification
    # ──────────────────────────────────────────────────────────────────────

    async def connect(self) -> bool:
        """
        Ouvre le tunnel WSS puis exécute la poignée de main Digest.

        Comportement selon les versions de websockets et firmwares Tydom :
          - Tydom 1.0 / ancien firmware : la box accepte l'upgrade WS puis envoie
            le 401 Digest DANS le tunnel (messages WS).
          - Tydom 2.0 / nouveau firmware : la box renvoie HTTP 401 AVANT l'upgrade,
            ce qui fait lever InvalidStatusCode à websockets. On récupère le nonce
            depuis les headers de cette réponse 401, puis on se reconnecte avec
            l'Authorization: Digest dans les headers de l'upgrade WS.
        """
        url = TYDOM_WS_URL.format(host=self.host, mac=self.mac)
        _LOGGER.debug("Ouverture WSS vers %s", url)

        # ── Tentative 1 : connexion sans auth (firmware Tydom 1.0) ────────
        nonce_from_reject: str | None = None
        try:
            ws = await asyncio.wait_for(
                websockets.connect(
                    url,
                    ssl=self._ssl_context,
                    ping_interval=None,
                    close_timeout=5,
                    open_timeout=10,
                ),
                timeout=15,
            )
            # Connexion acceptée → attendre le challenge 401 dans le tunnel
            try:
                challenge = await asyncio.wait_for(ws.recv(), timeout=10)
                _LOGGER.debug("Challenge reçu dans tunnel : %s", challenge[:300])
            except asyncio.TimeoutError:
                _LOGGER.error("Pas de challenge reçu dans le tunnel (timeout 10 s)")
                await ws.close()
                return False

            if "200 OK" in challenge:
                # Déjà authentifié (reconnexion dans la même session TCP)
                self._websocket = ws
                _LOGGER.info("Tydom déjà authentifié (200 direct)")
                return True

            nonce = self._parse_nonce(challenge)
            if not nonce:
                _LOGGER.error("Challenge sans nonce reçu :\n%s", challenge)
                await ws.close()
                return False

            _LOGGER.debug("Nonce (tunnel) : %s", nonce)
            uri = f"/mediation/client?mac={self.mac}&appli=1"
            auth_req = self._make_request(
                "GET", uri,
                extra_headers={"Authorization": self._digest_response(nonce, uri)},
            )
            await ws.send(auth_req)

            try:
                auth_resp = await asyncio.wait_for(ws.recv(), timeout=10)
                _LOGGER.debug("Réponse auth (tunnel) : %s", auth_resp[:300])
            except asyncio.TimeoutError:
                _LOGGER.error("Timeout en attendant la confirmation 200 OK (tunnel)")
                await ws.close()
                return False

            if "200 OK" not in auth_resp:
                _LOGGER.error(
                    "Auth refusée dans le tunnel. Réponse :\n%s\n"
                    "→ Vérifiez MAC (%s) et mot de passe.",
                    auth_resp[:400], self.mac,
                )
                await ws.close()
                return False

            self._websocket = ws
            _LOGGER.info("Auth Tydom OK (tunnel, MAC=%s)", self.mac)
            return True

        except Exception as first_err:
            # Récupérer le nonce depuis les headers de la réponse 401 rejetée
            _LOGGER.debug(
                "Tentative 1 échouée. Type exception: %s, Message: %s",
                type(first_err).__name__, first_err
            )
            nonce_from_reject = self._extract_nonce_from_exception(first_err)
            if nonce_from_reject:
                _LOGGER.debug(
                    "401 reçu avant upgrade WS (firmware récent). "
                    "Nonce extrait : %s", nonce_from_reject
                )
            else:
                _LOGGER.error(
                    "Connexion WSS échouée (tentative sans auth) : %s\n"
                    "Exception type: %s\n"
                    "host=%s, MAC=%s", first_err, type(first_err).__name__, self.host, self.mac
                )
                return False

        # ── Tentative 2 : upgrade WS avec Authorization: Digest ──────────
        # (firmware Tydom 2.0 qui envoie 401 avant l'upgrade)
        digest_value = self._digest_response(nonce_from_reject)
        _LOGGER.debug(
            "Reconnexion avec Digest (qop=auth) dans les headers WS upgrade. "
            "Nonce=%s, Digest=%s",
            nonce_from_reject, digest_value
        )
        try:
            ws = await asyncio.wait_for(
                websockets.connect(
                    url,
                    ssl=self._ssl_context,
                    additional_headers={"Authorization": digest_value},
                    ping_interval=None,
                    close_timeout=5,
                    open_timeout=10,
                ),
                timeout=15,
            )
        except Exception as second_err:
            _LOGGER.error(
                "Connexion WSS avec Digest échouée : %s\n"
                "Nonce utilisé : %s\n"
                "Digest envoyé : %s\n"
                "→ Vérifiez MAC (%s) et mot de passe.",
                second_err, nonce_from_reject, digest_value, self.mac
            )
            return False

        # Attendre éventuellement un 200 dans le tunnel
        try:
            confirm = await asyncio.wait_for(ws.recv(), timeout=5)
            _LOGGER.debug("Confirmation après auth header : %s", confirm[:200])
        except asyncio.TimeoutError:
            pass  # Certains firmwares n'envoient rien de plus

        self._websocket = ws
        _LOGGER.info("Auth Tydom OK (header upgrade, MAC=%s)", self.mac)
        return True

    @staticmethod
    def _extract_nonce_from_exception(err: Exception) -> str | None:
        """
        Tente d'extraire le nonce depuis l'exception levée par websockets
        quand la box répond 401 avant l'upgrade.
        Compatible websockets >= 10 (InvalidStatusCode / RejectHandshake).
        """
        # websockets >= 10 : RejectHandshake ou InvalidStatusCode
        # Les headers de la réponse 401 sont dans err.headers ou err.response.headers
        headers_str = ""

        # Attribut 'headers' direct (websockets 10-11)
        if hasattr(err, "headers"):
            try:
                headers_str = str(err.headers)
                _LOGGER.debug("Nonce search: headers attribute found")
            except Exception as e:
                _LOGGER.debug("Nonce search: headers attribute error: %s", e)

        # Attribut 'response' (websockets 12+)
        if not headers_str and hasattr(err, "response"):
            try:
                headers_str = str(err.response.headers)
                _LOGGER.debug("Nonce search: response.headers attribute found")
            except Exception as e:
                _LOGGER.debug("Nonce search: response.headers attribute error: %s", e)

        # Dernier recours : représentation texte de l'exception
        if not headers_str:
            headers_str = str(err)
            _LOGGER.debug("Nonce search: using exception string representation")

        _LOGGER.debug("Nonce search: headers_str=%s", headers_str[:500])
        nonce = re.search(r'[Nn]once="([^"]+)"', headers_str)
        if nonce:
            result = nonce.group(1)
            _LOGGER.debug("Nonce found: %s", result)
            return result
        _LOGGER.warning("Nonce NOT found in: %s", headers_str)
        return None

    async def disconnect(self) -> None:
        self._running = False
        if self._websocket:
            try:
                await self._websocket.close()
            except Exception:
                pass
            self._websocket = None

    # ──────────────────────────────────────────────────────────────────────
    # Envoi de commandes
    # ──────────────────────────────────────────────────────────────────────

    async def send_message(self, method: str, uri: str,
                           body: dict | list | None = None) -> None:
        if not self._websocket:
            raise ConnectionError("Non connecté à la box Tydom")
        body_str = json.dumps(body) if body is not None else ""
        raw = self._make_request(method, uri, body=body_str)
        try:
            await self._websocket.send(raw)
            _LOGGER.debug("→ %s %s", method, uri)
        except ConnectionClosed:
            _LOGGER.warning("Connexion fermée pendant l'envoi")
            self._websocket = None
            raise

    async def get_devices(self) -> None:
        await self.send_message("GET", CMD_GET_DEVICES)

    async def get_configs(self) -> None:
        await self.send_message("GET", CMD_GET_CONFIGS)

    async def get_info(self) -> None:
        await self.send_message("GET", CMD_GET_INFOS)

    async def refresh_all(self) -> None:
        await self.send_message("POST", CMD_POST_REFRESH)

    async def set_device_data(self, device_id: str, endpoint_id: str,
                              data: list) -> None:
        uri = f"/devices/{device_id}/endpoints/{endpoint_id}/data"
        await self.send_message("PUT", uri, data)

    # ──────────────────────────────────────────────────────────────────────
    # Boucle d'écoute
    # ──────────────────────────────────────────────────────────────────────

    async def listen(self) -> None:
        """Reçoit les messages Tydom en continu et appelle le callback."""
        self._running = True

        while self._running:
            # Reconnexion si nécessaire
            if not self._websocket:
                _LOGGER.info("Reconnexion Tydom…")
                ok = await self.connect()
                if not ok:
                    await asyncio.sleep(RECONNECT_DELAY)
                    continue
                try:
                    await self.get_devices()
                    await self.get_configs()
                except Exception:
                    pass

            try:
                raw = await asyncio.wait_for(
                    self._websocket.recv(), timeout=70
                )
                _LOGGER.debug("← %s…", raw[:200])

                parsed = self._parse_response(raw)
                if parsed is not None and self.callback:
                    msg_type = self._msg_type(raw)
                    await self.callback(msg_type, parsed)

            except asyncio.TimeoutError:
                # keepalive
                try:
                    await self.send_message("GET", CMD_GET_INFOS)
                except Exception:
                    self._websocket = None

            except ConnectionClosed:
                _LOGGER.warning("Tunnel WS fermé, reconnexion dans %ds", RECONNECT_DELAY)
                self._websocket = None
                await asyncio.sleep(RECONNECT_DELAY)

            except Exception as err:
                _LOGGER.error("Erreur inattendue dans listen() : %s", err)
                await asyncio.sleep(5)

    # ──────────────────────────────────────────────────────────────────────
    # Helpers parsing
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def _parse_response(raw: str) -> dict | list | None:
        """Extrait le JSON du body d'une réponse HTTP-dans-WS."""
        try:
            _, _, body = raw.partition("\r\n\r\n")
            body = body.strip()
            if not body:
                return None
            # Dé-chunking basique : supprimer les lignes de taille hexa
            lines = body.splitlines()
            clean = []
            for line in lines:
                stripped = line.strip()
                if re.fullmatch(r"[0-9a-fA-F]+", stripped):
                    continue      # ligne de taille chunk
                if stripped == "0":
                    break         # fin de chunked
                clean.append(line)
            body = "\n".join(clean).strip()
            if not body:
                return None
            return json.loads(body)
        except (json.JSONDecodeError, ValueError):
            return None

    @staticmethod
    def _msg_type(raw: str) -> str:
        """Détermine le type de message depuis la première ligne HTTP."""
        first = raw.split("\r\n", 1)[0]
        if "/devices/data"    in first: return "devices_data"
        if "/devices/cconfig" in first: return "devices_config"
        if "/devices/meta"    in first: return "devices_meta"
        if "/infos"           in first: return "info"
        if "PUT"              in first: return "put_response"
        return "unknown"

    async def ping(self) -> bool:
        try:
            await self.send_message("GET", CMD_GET_INFOS)
            return True
        except Exception:
            return False
