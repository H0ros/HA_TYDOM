"""Config flow pour l'intégration Tydom."""
from __future__ import annotations

import logging
import re
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.data_entry_flow import FlowResult

from .const import CONF_HOST, CONF_MAC, CONF_PASSWORD, DOMAIN
from .tydom_client import TydomClient

_LOGGER = logging.getLogger(__name__)

_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:\-]?){5}[0-9A-Fa-f]{2}$")


def _normalize_mac(mac: str) -> str:
    return mac.upper().replace(":", "").replace("-", "")


def _validate_mac(mac: str) -> bool:
    return bool(_MAC_RE.match(mac.strip()))


def _default_password(mac: str) -> str:
    """Mot de passe Tydom 1 par défaut = 6 derniers caractères de la MAC."""
    clean = _normalize_mac(mac)
    return clean[-6:] if len(clean) >= 6 else clean


class TydomConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Flux de configuration pour Tydom."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        errors: dict[str, str] = {}

        if user_input is not None:
            mac_raw = user_input[CONF_MAC].strip()
            password = user_input[CONF_PASSWORD].strip()
            host = user_input.get(CONF_HOST, "").strip() or None

            if not _validate_mac(mac_raw):
                errors[CONF_MAC] = "invalid_mac"
            elif not password:
                errors[CONF_PASSWORD] = "invalid_password"
            else:
                mac = _normalize_mac(mac_raw)

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

        # Pré-remplir le mot de passe par défaut si MAC déjà saisie
        mac_input = (user_input or {}).get(CONF_MAC, "")
        default_pwd = _default_password(mac_input) if _validate_mac(mac_input) else ""

        schema = vol.Schema({
            vol.Required(CONF_MAC): str,
            vol.Required(CONF_PASSWORD, default=default_pwd): str,
            vol.Optional(CONF_HOST, default=""): str,
        })

        return self.async_show_form(
            step_id="user",
            data_schema=schema,
            errors=errors,
        )