"""Plateforme light (lumières, variateurs) pour Tydom."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.light import (
    ATTR_BRIGHTNESS,
    ColorMode,
    LightEntity,
    LightEntityFeature,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import TydomCoordinator, TydomDevice

_LOGGER = logging.getLogger(__name__)

_LIGHT_USAGES = {"light", "dimmer"}


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: TydomCoordinator = hass.data[DOMAIN][entry.entry_id]
    entities = [
        TydomLight(coordinator, device)
        for device in coordinator.devices.values()
        if device.last_usage in _LIGHT_USAGES
    ]
    _LOGGER.debug("Ajout de %d entités light Tydom", len(entities))
    async_add_entities(entities)


class TydomLight(CoordinatorEntity[TydomCoordinator], LightEntity):
    """Lumière Tydom."""

    _attr_has_entity_name = True

    def __init__(self, coordinator: TydomCoordinator, device: TydomDevice) -> None:
        super().__init__(coordinator)
        self._device_uid = device.unique_id
        self._attr_unique_id = f"tydom_{device.unique_id}"
        self._attr_name = device.name

        is_dimmer = device.last_usage == "dimmer" or "level" in device.attributes
        if is_dimmer:
            self._attr_color_mode = ColorMode.BRIGHTNESS
            self._attr_supported_color_modes = {ColorMode.BRIGHTNESS}
        else:
            self._attr_color_mode = ColorMode.ONOFF
            self._attr_supported_color_modes = {ColorMode.ONOFF}

    @property
    def _device(self) -> TydomDevice | None:
        return self.coordinator.get_device(self._device_uid)

    @property
    def is_on(self) -> bool | None:
        d = self._device
        if d is None:
            return None
        # Tydom peut utiliser "level" (0-100) ou "on" (bool)
        level = d.attributes.get("level")
        if level is not None:
            return int(level) > 0
        on_val = d.attributes.get("on")
        if on_val is not None:
            return bool(on_val)
        return None

    @property
    def brightness(self) -> int | None:
        d = self._device
        if d is None:
            return None
        level = d.attributes.get("level")
        if level is not None:
            # Tydom : 0-100 → HA : 0-255
            return int(int(level) * 255 / 100)
        return None

    async def async_turn_on(self, **kwargs: Any) -> None:
        d = self._device
        if d is None:
            return
        brightness = kwargs.get(ATTR_BRIGHTNESS)
        if brightness is not None:
            level = int(brightness * 100 / 255)
            await self.coordinator.client.put_device_data(
                d.device_id, d.endpoint_id, "level", level
            )
        else:
            if "level" in (d.attributes or {}):
                await self.coordinator.client.put_device_data(
                    d.device_id, d.endpoint_id, "level", 100
                )
            else:
                await self.coordinator.client.put_device_data(
                    d.device_id, d.endpoint_id, "on", True
                )

    async def async_turn_off(self, **kwargs: Any) -> None:
        d = self._device
        if d is None:
            return
        if "level" in (d.attributes or {}):
            await self.coordinator.client.put_device_data(
                d.device_id, d.endpoint_id, "level", 0
            )
        else:
            await self.coordinator.client.put_device_data(
                d.device_id, d.endpoint_id, "on", False
            )

    @callback
    def _handle_coordinator_update(self) -> None:
        self.async_write_ha_state()