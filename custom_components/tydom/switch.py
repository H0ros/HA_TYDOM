"""Plateforme switch pour Tydom."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import TydomCoordinator, TydomDevice

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: TydomCoordinator = hass.data[DOMAIN][entry.entry_id]
    entities = [
        TydomSwitch(coordinator, device)
        for device in coordinator.devices.values()
        if device.last_usage == "switch"
    ]
    _LOGGER.debug("Ajout de %d entités switch Tydom", len(entities))
    async_add_entities(entities)


class TydomSwitch(CoordinatorEntity[TydomCoordinator], SwitchEntity):
    """Interrupteur Tydom."""

    _attr_has_entity_name = True

    def __init__(self, coordinator: TydomCoordinator, device: TydomDevice) -> None:
        super().__init__(coordinator)
        self._device_uid = device.unique_id
        self._attr_unique_id = f"tydom_{device.unique_id}"
        self._attr_name = device.name

    @property
    def _device(self) -> TydomDevice | None:
        return self.coordinator.get_device(self._device_uid)

    @property
    def is_on(self) -> bool | None:
        d = self._device
        if d is None:
            return None
        return bool(d.attributes.get("on", False))

    async def async_turn_on(self, **kwargs: Any) -> None:
        d = self._device
        if d:
            await self.coordinator.client.put_device_data(
                d.device_id, d.endpoint_id, "on", True
            )

    async def async_turn_off(self, **kwargs: Any) -> None:
        d = self._device
        if d:
            await self.coordinator.client.put_device_data(
                d.device_id, d.endpoint_id, "on", False
            )

    @callback
    def _handle_coordinator_update(self) -> None:
        self.async_write_ha_state()