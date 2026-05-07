"""Intégration Tydom Delta Dore pour Home Assistant."""
from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady

from .const import DOMAIN, CONF_MAC, CONF_PASSWORD, CONF_HOST, PLATFORMS
from .coordinator import TydomCoordinator
from .tydom_client import TydomClient

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Configure l'intégration depuis une entrée de configuration."""
    mac = entry.data[CONF_MAC]
    password = entry.data[CONF_PASSWORD]
    host = entry.data.get(CONF_HOST)

    client = TydomClient(mac_address=mac, password=password, host=host)
    coordinator = TydomCoordinator(hass, client)

    success = await coordinator.start()
    if not success:
        raise ConfigEntryNotReady(f"Impossible de se connecter à la box Tydom ({mac})")

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    # Listener pour les options mises à jour
    entry.async_on_unload(entry.add_update_listener(async_reload_entry))

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Décharge l'intégration."""
    coordinator: TydomCoordinator = hass.data[DOMAIN][entry.entry_id]
    await coordinator.stop()

    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id)

    return unload_ok


async def async_reload_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Recharge l'entrée de configuration."""
    await async_unload_entry(hass, entry)
    await async_setup_entry(hass, entry)
