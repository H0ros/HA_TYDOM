"""Plateforme binary_sensor (détecteurs) pour Tydom."""
from __future__ import annotations

import logging

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import TydomCoordinator, TydomDevice

_LOGGER = logging.getLogger(__name__)

_BINARY_USAGES = {"smoke_detector", "motion_detector", "opening_detector"}

_USAGE_TO_CLASS = {
    "smoke_detector": BinarySensorDeviceClass.SMOKE,
    "motion_detector": BinarySensorDeviceClass.MOTION,
    "opening_detector": BinarySensorDeviceClass.OPENING,
}

# Attributs Tydom à surveiller (premier trouvé)
_STATE_ATTRS = ["alarmMode", "alarmState", "onFault", "contactState", "intrusionDetect"]


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: TydomCoordinator = hass.data[DOMAIN][entry.entry_id]
    entities = [
        TydomBinarySensor(coordinator, device)
        for device in coordinator.devices.values()
        if device.last_usage in _BINARY_USAGES
    ]
    _LOGGER.debug("Ajout de %d entités binary_sensor Tydom", len(entities))
    async_add_entities(entities)


class TydomBinarySensor(CoordinatorEntity[TydomCoordinator], BinarySensorEntity):
    """Détecteur binaire Tydom."""

    _attr_has_entity_name = True

    def __init__(self, coordinator: TydomCoordinator, device: TydomDevice) -> None:
        super().__init__(coordinator)
        self._device_uid = device.unique_id
        self._attr_unique_id = f"tydom_{device.unique_id}"
        self._attr_name = device.name
        self._attr_device_class = _USAGE_TO_CLASS.get(device.last_usage)

    @property
    def _device(self) -> TydomDevice | None:
        return self.coordinator.get_device(self._device_uid)

    @property
    def is_on(self) -> bool | None:
        d = self._device
        if d is None:
            return None
        for attr in _STATE_ATTRS:
            val = d.attributes.get(attr)
            if val is not None:
                if isinstance(val, bool):
                    return val
                if isinstance(val, str):
                    return val.upper() not in ("OFF", "NONE", "NO_DEFECT", "CLOSED", "FALSE", "0")
                return bool(val)
        return None

    @callback
    def _handle_coordinator_update(self) -> None:
        self.async_write_ha_state()