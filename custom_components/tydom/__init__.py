"""Intégration Home Assistant pour la box Tydom de Delta Dore."""
from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady

from .const import DOMAIN, PLATFORMS
from .coordinator import TydomCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Configure l'intégration à partir d'une entrée de configuration."""
    coordinator = TydomCoordinator(hass, entry)

    # Connexion initiale
    connected = await coordinator.async_connect()
    if not connected:
        raise ConfigEntryNotReady(
            "Impossible de se connecter à la box Tydom. "
            "Vérifiez l'adresse IP, l'adresse MAC et le code PIN."
        )

    # Première mise à jour des données
    await coordinator.async_config_entry_first_refresh()

    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][entry.entry_id] = coordinator

    # Chargement des plateformes
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Décharge l'intégration."""
    coordinator: TydomCoordinator = hass.data[DOMAIN].get(entry.entry_id)

    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)

    if unloaded and coordinator:
        await coordinator.async_disconnect()
        hass.data[DOMAIN].pop(entry.entry_id, None)

    return unloaded