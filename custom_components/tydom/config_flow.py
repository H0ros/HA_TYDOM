"""Config flow pour l'intégration Tydom."""
from __future__ import annotations

import logging
import re
import urllib.parse
import urllib.request
import urllib.error
import json
import ssl
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.data_entry_flow import FlowResult

from .const import CONF_HOST, CONF_MAC, CONF_PASSWORD, DOMAIN

_LOGGER = logging.getLogger(__name__)

_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:\-]?){5}[0-9A-Fa-f]{2}$")

# API Delta Dore (source : tydom2mqtt)
_DD_OPENID_URL  = "https://deltadoreadb2ciot.b2clogin.com/deltadoreadb2ciot.onmicrosoft.com/v2.0/.well-known/openid-configuration?p=B2C_1_AccountProviderROPC_SignIn"
_DD_CLIENT_ID   = "8782839f-3264-472a-ab87-4d4e23524da4"
_DD_SCOPE       = "openid profile offline_access https://deltadoreadb2ciot.onmicrosoft.com/iotapi/sites_management_gateway_credentials"
_DD_SITES_URL   = "https://prod.iotdeltadore.com/sitesmanagement/api/v1/sites?gateway_mac={mac}"


def _normalize_mac(mac: str) -> str:
    return mac.upper().replace(":", "").replace("-", "")

def _validate_mac(mac: str) -> bool:
    return bool(_MAC_RE.match(mac.strip()))


def _fetch_tydom_password_sync(email: str, dd_password: str, mac: str) -> str | None:
    """Récupère le mot de passe Tydom depuis l'API Delta Dore.
    Synchrone — appelé via loop.run_in_executor().
    """
    ctx = ssl.create_default_context()

    # Récupérer le token_endpoint
    try:
        req = urllib.request.Request(_DD_OPENID_URL, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, context=ctx, timeout=10) as r:
            token_endpoint = json.loads(r.read()).get("token_endpoint", "")
    except Exception as exc:
        _LOGGER.error("Impossible de récupérer le token_endpoint Delta Dore : %s", exc)
        return None

    # Authentification ROPC
    auth_data = urllib.parse.urlencode({
        "grant_type": "password",
        "username": email,
        "password": dd_password,
        "client_id": _DD_CLIENT_ID,
        "scope": _DD_SCOPE,
        "response_type": "token",
    }).encode()

    try:
        req = urllib.request.Request(
            token_endpoint, data=auth_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        with urllib.request.urlopen(req, context=ctx, timeout=15) as r:
            token = json.loads(r.read()).get("access_token")
    except Exception as exc:
        _LOGGER.error("Authentification Delta Dore échouée : %s", exc)
        return None

    if not token:
        return None

    # Récupérer le mot de passe depuis l'API sites
    try:
        sites_url = _DD_SITES_URL.format(mac=mac)
        req = urllib.request.Request(
            sites_url,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"}
        )
        with urllib.request.urlopen(req, context=ctx, timeout=15) as r:
            sites = json.loads(r.read())

        for site in sites.get("sites", []):
            gw = site.get("gateway", {})
            if gw.get("mac", "").upper().replace(":", "") == mac.upper():
                pwd = gw.get("password")
                if pwd:
                    _LOGGER.info("Mot de passe Tydom récupéré via API Delta Dore")
                    return pwd
    except Exception as exc:
        _LOGGER.error("Récupération mot de passe Tydom échouée : %s", exc)

    return None


class TydomConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Flux de configuration pour Tydom."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        errors: dict[str, str] = {}

        if user_input is not None:
            mac_raw    = user_input[CONF_MAC].strip()
            host       = user_input.get(CONF_HOST, "").strip() or None
            dd_email   = user_input.get("deltadore_email", "").strip()
            dd_pass    = user_input.get("deltadore_password", "").strip()
            manual_pwd = user_input.get(CONF_PASSWORD, "").strip()

            if not _validate_mac(mac_raw):
                errors[CONF_MAC] = "invalid_mac"
            elif not dd_email and not manual_pwd:
                errors["base"] = "missing_credentials"
            else:
                mac = _normalize_mac(mac_raw)
                password = manual_pwd

                # Récupérer le mot de passe via Delta Dore si email fourni
                if dd_email and dd_pass and not manual_pwd:
                    import asyncio
                    loop = asyncio.get_event_loop()
                    try:
                        password = await loop.run_in_executor(
                            None, _fetch_tydom_password_sync, dd_email, dd_pass, mac
                        )
                    except Exception:
                        password = None
                    if not password:
                        errors["base"] = "cannot_connect_cloud"

                if not errors and password:
                    # Test de connexion
                    from .tydom_client import TydomClient
                    if not host:
                        host = f"{mac}-tydom.local"
                    client = TydomClient(mac=mac, password=password, host=host)
                    try:
                        connected = await client.connect()
                        await client.disconnect()
                    except Exception:
                        connected = False

                    if not connected:
                        errors["base"] = "cannot_connect"
                    else:
                        await self.async_set_unique_id(mac)
                        self._abort_if_unique_id_configured()
                        return self.async_create_entry(
                            title=f"Tydom {mac_raw.upper()}",
                            data={
                                CONF_MAC: mac,
                                CONF_PASSWORD: password,
                                CONF_HOST: host or "",
                            },
                        )

        schema = vol.Schema({
            vol.Required(CONF_MAC): str,
            vol.Required(CONF_HOST): str,
            vol.Optional("deltadore_email", default=""): str,
            vol.Optional("deltadore_password", default=""): str,
            vol.Optional(CONF_PASSWORD, default=""): str,
        })

        return self.async_show_form(
            step_id="user",
            data_schema=schema,
            errors=errors,
        )
