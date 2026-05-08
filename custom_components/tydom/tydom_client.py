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

import aiohttp

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
    def _parse_www_authenticate(raw: str) -> dict[str, str]:
        """Extrait les paramètres d'un challenge WWW-Authenticate: Digest."""
        auth_match = re.search(r'WWW-Authenticate:\s*Digest\s*(.*)', raw, re.IGNORECASE)
        challenge = auth_match.group(1) if auth_match else raw
        params: dict[str, str] = {}
        for name, _, quoted, unquoted in re.findall(
            r'([a-zA-Z]+)=("([^"]*)"|([^,]*))(?:,\s*)?', challenge
        ):
            params[name.lower()] = quoted or unquoted.strip()
        return params
        """Extrait les paramètres d'un challenge WWW-Authenticate: Digest."""
        auth_match = re.search(r'WWW-Authenticate:\s*Digest\s*(.*)', raw, re.IGNORECASE)
        challenge = auth_match.group(1) if auth_match else raw
        params: dict[str, str] = {}
        for name, _, quoted, unquoted in re.findall(
            r'([a-zA-Z]+)=("([^"]*)"|([^,]*))(?:,\s*)?', challenge
        ):
            params[name.lower()] = quoted or unquoted.strip()
        return params

    def _digest_response(
        self,
        nonce: str,
        realm: str,
        qop: str | None = None,
    ) -> str:
        """
        Calcule la réponse HTTP Digest (RFC 2617) using requests.HTTPDigestAuth.

        Compatible tydom2mqtt qui utilise HTTPDigestAuth de requests.
        """
        # Créer une instance de HTTPDigestAuth avec username=MAC et password
        digest_auth = HTTPDigestAuth(self.mac, self.password)
        
        # Construire le challenge comme l'attend HTTPDigestAuth
        chal = {}
        chal["nonce"] = nonce
        chal["realm"] = realm.lower()  # tydom2mqtt utilise "protected area" en minuscules pour mode local
        if qop:
            chal["qop"] = qop
        
        # Initialiser les attributs thread_local attendus par HTTPDigestAuth
        digest_auth._thread_local.chal = chal
        digest_auth._thread_local.last_nonce = nonce
        digest_auth._thread_local.nonce_count = 1  # Comme tydom2mqtt
        digest_auth._thread_local.last_method = "GET"
        digest_auth._thread_local.num_401_calls = 0
        
        # Build digest header pour l'URI complète
        full_uri = f"https://{self.host}:443/mediation/client?mac={self.mac}&appli=1"
        auth_header = digest_auth.build_digest_header("GET", full_uri)
        
        _LOGGER.debug(
            "Digest response (via HTTPDigestAuth): nonce=%s, realm=%s, qop=%s, auth_header=%s",
            nonce, realm, qop, auth_header[:100],
        )
        
        _LOGGER.debug(
            "Digest response (via HTTPDigestAuth): nonce=%s, realm=%s, qop=%s, auth_header=%s",
            nonce, realm, qop, auth_header[:100],
        )
        
        # Debug: calcul manuel pour vérification
        import hashlib
        ha1 = hashlib.md5(f"{self.mac}:{realm}:{self.password}".encode()).hexdigest()
        ha2 = hashlib.md5(f"GET:{full_uri}".encode()).hexdigest()
        # Le cnonce sera dans le header, on peut l'extraire
        cnonce_match = re.search(r'cnonce="([^"]+)"', auth_header)
        actual_cnonce = cnonce_match.group(1) if cnonce_match else "unknown"
        manual_response = hashlib.md5(f"{ha1}:{nonce}:00000001:{actual_cnonce}:auth:{ha2}".encode()).hexdigest()
        _LOGGER.debug("Manual hash calc: HA1=%s, HA2=%s, cnonce=%s, response=%s", ha1, ha2, actual_cnonce, manual_response)
        
        return auth_header

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
        # D'abord faire une requête HTTP GET pour obtenir le challenge
        try:
            async with aiohttp.ClientSession() as session:
                headers = {
                    "Connection": "Upgrade",
                    "Upgrade": "websocket",
                    "Host": f"{self.host}:443",
                    "Accept": "*/*",
                    "Sec-WebSocket-Key": self._generate_websocket_key(),
                    "Sec-WebSocket-Version": "13",
                }
                async with session.get(
                    f"https://{self.host}:443/mediation/client?mac={self.mac}&appli=1",
                    headers=headers,
                    ssl=self._ssl_context
                ) as resp:
                    # Si 401, extraire le challenge et faire l'upgrade WS avec Digest
                    if resp.status == 401:
                        www_auth = resp.headers.get('WWW-Authenticate', '')
                        auth_params = self._parse_www_authenticate(www_auth)
                        nonce = auth_params.get("nonce")
                        realm = auth_params.get("realm")
                        if nonce and realm:
                            _LOGGER.info("Challenge HTTP GET - realm=%s, nonce=%s, qop=%s", 
                                         realm, nonce, auth_params.get("qop"))
                            
                            # Calculer Digest et faire l'upgrade WS
                            digest_value = self._digest_response(nonce, realm, qop=auth_params.get("qop"))
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
                            self._websocket = ws
                            _LOGGER.info("Auth Tydom OK (HTTP GET + WS upgrade, MAC=%s)", self.mac)
                            return True
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

            auth_params = self._parse_www_authenticate(challenge)
            nonce = auth_params.get("nonce")
            realm = auth_params.get("realm")
            if not nonce or not realm:
                _LOGGER.error("Challenge sans nonce/realm reçu :\n%s", challenge)
                await ws.close()
                return False

            _LOGGER.info("Challenge reçu - realm=%s, nonce=%s, qop=%s, opaque=%s, algorithm=%s", 
                         realm, nonce, auth_params.get("qop"), auth_params.get("opaque"), auth_params.get("algorithm"))
            
            # Debug: simuler l'extraction tydom2mqtt
            try:
                nonce_parts = challenge.split(",", 3)
                if len(nonce_parts) >= 3:
                    tydom2mqtt_nonce = nonce_parts[2].split("=", 1)[1].split('"')[1]
                    _LOGGER.info("tydom2mqtt nonce extraction: %s (vs notre: %s)", tydom2mqtt_nonce, nonce)
            except Exception as e:
                _LOGGER.debug("Erreur extraction nonce tydom2mqtt: %s", e)
            uri_path = f"/mediation/client?mac={self.mac}&appli=1"
            auth_req = self._make_request(
                "GET", uri_path,
                extra_headers={
                    "Authorization": self._digest_response(
                        nonce,
                        realm,
                        qop=auth_params.get("qop"),
                    )
                },
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
            auth_params = self._extract_www_authenticate_from_exception(first_err)
            nonce_from_reject = auth_params.get("nonce")
            if nonce_from_reject:
                _LOGGER.info("Tentative 2 - Challenge extrait: realm=%s, nonce=%s, qop=%s, opaque=%s, algorithm=%s", 
                             auth_params.get("realm"), nonce_from_reject, auth_params.get("qop"), auth_params.get("opaque"), auth_params.get("algorithm"))
                
                # Debug: simuler l'extraction tydom2mqtt pour tentative 2
                try:
                    headers_str = ""
                    if hasattr(first_err, "headers"):
                        headers_str = str(first_err.headers)
                    elif hasattr(first_err, "response"):
                        headers_str = str(first_err.response.headers)
                    else:
                        headers_str = str(first_err)
                    
                    _LOGGER.debug("Tentative 2 - Headers string: %s", headers_str[:300])
                    
                    # Essayer la méthode tydom2mqtt
                    www_auth_match = re.search(r'WWW-Authenticate:\s*Digest\s*(.*)', headers_str, re.IGNORECASE)
                    if www_auth_match:
                        digest_part = www_auth_match.group(1)
                        _LOGGER.debug("Tentative 2 - Digest part: %s", digest_part)
                        
                        # Méthode tydom2mqtt: split sur virgule et prendre le 3ème élément
                        parts = digest_part.split(",", 3)
                        if len(parts) >= 3:
                            nonce_part = parts[2].strip()
                            if "=" in nonce_part:
                                tydom2mqtt_nonce = nonce_part.split("=", 1)[1].strip().strip('"')
                                _LOGGER.info("Tentative 2 - tydom2mqtt nonce extraction: '%s' (vs notre: '%s')", tydom2mqtt_nonce, nonce_from_reject)
                except Exception as e:
                    _LOGGER.debug("Tentative 2 - Erreur extraction nonce tydom2mqtt: %s", e)
            else:
                _LOGGER.error(
                    "Connexion WSS échouée (tentative sans auth) : %s\n"
                    "Exception type: %s\n"
                    "host=%s, MAC=%s", first_err, type(first_err).__name__, self.host, self.mac
                )
                return False

        # ── Tentative 2 : upgrade WS avec Authorization: Digest ──────────
        # (firmware Tydom 2.0 qui envoie 401 avant l'upgrade)
        realm_reject = auth_params.get("realm") or TYDOM_REALM
        _LOGGER.info("Tentative 2 - realm=%s, nonce=%s, qop=%s, opaque=%s, algorithm=%s", 
                     realm_reject, nonce_from_reject, auth_params.get("qop"), auth_params.get("opaque"), auth_params.get("algorithm"))
        
        # Debug: simuler l'extraction tydom2mqtt pour tentative 2
        try:
            headers_str = ""
            if hasattr(first_err, "headers"):
                headers_str = str(first_err.headers)
            elif hasattr(first_err, "response"):
                headers_str = str(first_err.response.headers)
            else:
                headers_str = str(first_err)
            
            nonce_parts = headers_str.split(",", 3)
            if len(nonce_parts) >= 3:
                tydom2mqtt_nonce_2 = nonce_parts[2].split("=", 1)[1].split('"')[1]
                _LOGGER.info("Tentative 2 - tydom2mqtt nonce extraction: %s (vs notre: %s)", tydom2mqtt_nonce_2, nonce_from_reject)
        except Exception as e:
            _LOGGER.debug("Tentative 2 - Erreur extraction nonce tydom2mqtt: %s", e)
        
        digest_value = self._digest_response(
            nonce_from_reject,
            realm_reject,
            qop=auth_params.get("qop"),
        )
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
    def _extract_www_authenticate_from_exception(err: Exception) -> dict[str, str]:
        """
        Tente d'extraire les paramètres WWW-Authenticate depuis l'exception levée
        par websockets quand la box répond 401 avant l'upgrade.
        Compatible websockets >= 10 (InvalidStatusCode / RejectHandshake).
        """
        headers_str = ""

        if hasattr(err, "headers"):
            try:
                headers_str = str(err.headers)
                _LOGGER.debug("Digest auth search: headers attribute found")
            except Exception as e:
                _LOGGER.debug("Digest auth search: headers attribute error: %s", e)

        if not headers_str and hasattr(err, "response"):
            try:
                headers_str = str(err.response.headers)
                _LOGGER.debug("Digest auth search: response.headers attribute found")
            except Exception as e:
                _LOGGER.debug("Digest auth search: response.headers attribute error: %s", e)

        if not headers_str:
            headers_str = str(err)
            _LOGGER.debug("Digest auth search: using exception string representation")

        _LOGGER.debug("Digest auth search: headers_str=%s", headers_str[:500])
        auth_params = self._parse_www_authenticate(headers_str)
        if auth_params:
            _LOGGER.debug("Digest auth params found: %s", auth_params)
            return auth_params
        _LOGGER.warning("Digest auth params NOT found in: %s", headers_str)
        return {}

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
