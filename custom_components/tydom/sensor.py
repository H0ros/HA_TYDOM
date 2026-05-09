"""Plateforme sensor (capteurs numériques) pour Tydom."""
from __future__ import annotations

import logging

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    PERCENTAGE,
    UnitOfTemperature,
    CONCENTRATION_PARTS_PER_MILLION,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import TydomCoordinator, TydomDevice

_LOGGER = logging.getLogger(__name__)

_SENSOR_USAGES = {"temperature_sensor", "humidity_sensor", "co2_sensor", "battery"}

_USAGE_CONFIG: dict[str, dict] = {
    "temperature_sensor": {
        "attr": "temperature",
        "unit": UnitOfTemperature.CELSIUS,
        "device_class": SensorDeviceClass.TEMPERATURE,
        "state_class": SensorStateClass.MEASUREMENT,
    },
    "humidity_sensor": {
        "attr": "humidity",
        "unit": PERCENTAGE,
        "device_class": SensorDeviceClass.HUMIDITY,
        "state_class": SensorStateClass.MEASUREMENT,
    },
    "co2_sensor": {
        "attr": "co2Level",
        "unit": CONCENTRATION_PARTS_PER_MILLION,
        "device_class": SensorDeviceClass.CO2,
        "state_class": SensorStateClass.MEASUREMENT,
    },
    "battery": {
        "attr": "batteryLevel",
        "unit": PERCENTAGE,
        "device_class": SensorDeviceClass.BATTERY,
        "state_class": SensorStateClass.MEASUREMENT,
    },
}


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: TydomCoordinator = hass.data[DOMAIN][entry.entry_id]
    entities = [
        TydomSensor(coordinator, device)
        for device in coordinator.devices.values()
        if device.last_usage in _SENSOR_USAGES
    ]
    _LOGGER.debug("Ajout de %d entités sensor Tydom", len(entities))
    async_add_entities(entities)


class TydomSensor(CoordinatorEntity[TydomCoordinator], SensorEntity):
    """Capteur numérique Tydom."""

    _attr_has_entity_name = True

    def __init__(self, coordinator: TydomCoordinator, device: TydomDevice) -> None:
        super().__init__(coordinator)
        self._device_uid = device.unique_id
        self._attr_unique_id = f"tydom_{device.unique_id}"
        self._attr_name = device.name

        cfg = _USAGE_CONFIG.get(device.last_usage, {})
        self._value_attr: str = cfg.get("attr", "value")
        self._attr_native_unit_of_measurement = cfg.get("unit")
        self._attr_device_class = cfg.get("device_class")
        self._attr_state_class = cfg.get("state_class")

    @property
    def _device(self) -> TydomDevice | None:
        return self.coordinator.get_device(self._device_uid)

    @property
    def native_value(self):
        d = self._device
        if d is None:
            return None
        val = d.attributes.get(self._value_attr)
        if val is None:
            # Fallback : cherche le premier attribut numérique
            for v in d.attributes.values():
                if isinstance(v, (int, float)):
                    return v
        return val

    @callback
    def _handle_coordinator_update(self) -> None:
        self.async_write_ha_state()