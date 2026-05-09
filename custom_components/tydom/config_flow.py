"""Config flow pour l'intégration Tydom."""
from __future__ import annotations

import asyncio
import logging
import re
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.data_entry_flow import FlowResult

from .const import CONF_HOST, CONF_MAC, CONF_PASSWORD, CONF_DD_EMAIL, CONF_DD_PASSWORD, DOMAIN
from .tydom_client import TydomClient, _fetch_tydom_password_from_cloud_sync

_LOGGER = logging.getLogger(__name__)

_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:\-]?){5}[0-9A-Fa-f]{2}$")


def _normalize_mac(mac: str) -> str:
    return mac.upper().replace(":", "").replace("-", "")


def _validate_mac(mac: str) -> bool:
    return bool(_MAC_RE.match(mac.strip()))


class TydomConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Flux de configuration pour Tydom."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Étape 1 : saisie des infos de connexion."""
        errors: dict[str, str] = {}

        if user_input is not None:
            mac_raw = user_input[CONF_MAC].strip()
            host = user_input.get(CONF_HOST, "").strip() or None
            dd_email = user_input.get(CONF_DD_EMAIL, "").strip()
            dd_password = user_input.get(CONF_DD_PASSWORD, "").strip()
            pin = user_input.get(CONF_PASSWORD, "").strip()

            if not _validate_mac(mac_raw):
                errors[CONF_MAC] = "invalid_mac"
            elif not pin and not (dd_email and dd_password):
                errors["base"] = "missing_credentials"
            else:
                mac = _normalize_mac(mac_raw)
                password = pin

                # Si identifiants Delta Dore fournis, récupérer le mot de passe via le cloud
                if dd_email and dd_password and not pin:
                    try:
                        loop = asyncio.get_event_loop()
                        cloud_pwd = await loop.run_in_executor(
                            None,
                            _fetch_tydom_password_from_cloud_sync,
                            dd_email,
                            dd_password,
                            mac,
                        )
                        if cloud_pwd:
                            password = cloud_pwd
                            _LOGGER.info("Mot de passe Tydom récupéré via le cloud Delta Dore")
                        else:
                            errors["base"] = "cloud_password_not_found"
                    except Exception as exc:
                        _LOGGER.error("Erreur cloud Delta Dore : %s", exc)
                        errors["base"] = "cannot_connect_cloud"

                if not errors:
                    # Test de connexion à la box
                    client = TydomClient(mac=mac, password=password, host=host)
                    try:
                        connected = await client.connect()
                        await client.disconnect()
                    except Exception as exc:
                        _LOGGER.error("Test connexion échoué : %s", exc)
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

        schema = vol.Schema(
            {
                vol.Required(CONF_MAC): str,
                vol.Optional(CONF_HOST, default=""): str,
                vol.Optional(CONF_PASSWORD, default=""): str,
                vol.Optional(CONF_DD_EMAIL, default=""): str,
                vol.Optional(CONF_DD_PASSWORD, default=""): str,
            }
        )

        return self.async_show_form(
            step_id="user",
            data_schema=schema,
            errors=errors,
            description_placeholders={
                "pin_help": "Code PIN de l'étiquette sous la box (Tydom 1.0 : 6 chiffres)",
                "cloud_help": "OU identifiants du compte Delta Dore (app mobile)",
            },
        )