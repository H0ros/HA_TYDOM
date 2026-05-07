"""Config Flow pour l'intégration Tydom."""
from __future__ import annotations

import logging
import re
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResult

from .const import DOMAIN, CONF_MAC, CONF_PASSWORD, CONF_HOST
from .tydom_client import TydomClient

_LOGGER = logging.getLogger(__name__)

MAC_REGEX = re.compile(r"^([0-9A-Fa-f]{2}[:\-]?){5}([0-9A-Fa-f]{2})$")


def _normalize_mac(mac: str) -> str:
    """Normalise l'adresse MAC (supprime séparateurs, met en majuscules)."""
    return mac.upper().replace(":", "").replace("-", "")


async def _test_connection(hass: HomeAssistant, mac: str, password: str, host: str | None) -> str | None:
    """Teste la connexion à la box Tydom. Retourne None si OK, sinon un code d'erreur."""
    client = TydomClient(mac_address=mac, password=password, host=host or None)
    try:
        success = await client.connect()
        if not success:
            _LOGGER.error(
                "Connexion Tydom refusée (MAC=%s, host=%s). "
                "Activez les logs debug sur custom_components.tydom pour plus de détails.",
                mac, client.host,
            )
            return "cannot_connect"
        await client.disconnect()
        return None
    except Exception as err:
        _LOGGER.error(
            "Exception lors du test de connexion Tydom (MAC=%s, host=%s): %s",
            mac, host, err, exc_info=True,
        )
        return "cannot_connect"


class TydomConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Gère le flux de configuration de l'intégration Tydom."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Étape initiale : saisie des identifiants."""
        errors: dict[str, str] = {}

        if user_input is not None:
            mac_raw = user_input[CONF_MAC].strip()
            password = user_input[CONF_PASSWORD].strip()
            host = user_input.get(CONF_HOST, "").strip() or None

            # Validation du format MAC
            if not MAC_REGEX.match(mac_raw):
                errors[CONF_MAC] = "invalid_mac"
            else:
                mac = _normalize_mac(mac_raw)

                # Vérifier qu'on n'a pas déjà cette box configurée
                await self.async_set_unique_id(mac)
                self._abort_if_unique_id_configured()

                # Tester la connexion
                error = await _test_connection(self.hass, mac, password, host)
                if error:
                    errors["base"] = error
                else:
                    return self.async_create_entry(
                        title=f"Tydom {mac}",
                        data={
                            CONF_MAC: mac,
                            CONF_PASSWORD: password,
                            CONF_HOST: host,
                        },
                    )

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_MAC): str,
                    vol.Required(CONF_PASSWORD): str,
                    vol.Optional(CONF_HOST, default=""): str,
                }
            ),
            errors=errors,
            description_placeholders={
                "mac_example": "AA:BB:CC:DD:EE:FF",
                "host_example": "192.168.1.xxx (optionnel)",
            },
        )
