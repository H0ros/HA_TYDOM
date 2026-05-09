"""Plateforme cover (volets, portails, garages) pour Tydom."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.cover import (
    ATTR_POSITION,
    CoverDeviceClass,
    CoverEntity,
    CoverEntityFeature,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import TydomCoordinator, TydomDevice

_LOGGER = logging.getLogger(__name__)

_COVER_USAGES = {"shutter", "garage_door", "window", "gate"}

_USAGE_TO_CLASS = {
    "shutter": CoverDeviceClass.SHUTTER,
    "garage_door": CoverDeviceClass.GARAGE,
    "window": CoverDeviceClass.WINDOW,
    "gate": CoverDeviceClass.GATE,
}


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: TydomCoordinator = hass.data[DOMAIN][entry.entry_id]
    entities = [
        TydomCover(coordinator, device)
        for device in coordinator.devices.values()
        if device.last_usage in _COVER_USAGES
    ]
    _LOGGER.debug("Ajout de %d entités cover Tydom", len(entities))
    async_add_entities(entities)


class TydomCover(CoordinatorEntity[TydomCoordinator], CoverEntity):
    """Volet/portail Tydom."""

    _attr_has_entity_name = True

    def __init__(self, coordinator: TydomCoordinator, device: TydomDevice) -> None:
        super().__init__(coordinator)
        self._device_uid = device.unique_id
        self._attr_unique_id = f"tydom_{device.unique_id}"
        self._attr_name = device.name
        self._attr_device_class = _USAGE_TO_CLASS.get(device.last_usage, CoverDeviceClass.SHUTTER)

        # Fonctionnalités : position si l'attribut existe
        features = CoverEntityFeature.OPEN | CoverEntityFeature.CLOSE | CoverEntityFeature.STOP
        if "position" in device.attributes:
            features |= CoverEntityFeature.SET_POSITION
        self._attr_supported_features = features

    @property
    def _device(self) -> TydomDevice | None:
        return self.coordinator.get_device(self._device_uid)

    @property
    def is_closed(self) -> bool | None:
        d = self._device
        if d is None:
            return None
        pos = d.attributes.get("position")
        if pos is not None:
            return int(pos) == 0
        return None

    @property
    def current_cover_position(self) -> int | None:
        d = self._device
        if d is None:
            return None
        pos = d.attributes.get("position")
        if pos is not None:
            return int(pos)
        return None

    @property
    def is_opening(self) -> bool | None:
        d = self._device
        if d is None:
            return None
        return d.attributes.get("moving") == "UP"

    @property
    def is_closing(self) -> bool | None:
        d = self._device
        if d is None:
            return None
        return d.attributes.get("moving") == "DOWN"

    async def async_open_cover(self, **kwargs: Any) -> None:
        d = self._device
        if d:
            await self.coordinator.client.put_device_data(
                d.device_id, d.endpoint_id, "position", 100
            )

    async def async_close_cover(self, **kwargs: Any) -> None:
        d = self._device
        if d:
            await self.coordinator.client.put_device_data(
                d.device_id, d.endpoint_id, "position", 0
            )

    async def async_stop_cover(self, **kwargs: Any) -> None:
        d = self._device
        if d:
            await self.coordinator.client.put_device_data(
                d.device_id, d.endpoint_id, "stop", True
            )

    async def async_set_cover_position(self, **kwargs: Any) -> None:
        position = kwargs.get(ATTR_POSITION, 0)
        d = self._device
        if d:
            await self.coordinator.client.put_device_data(
                d.device_id, d.endpoint_id, "position", position
            )

    @callback
    def _handle_coordinator_update(self) -> None:
        self.async_write_ha_state()