"""Plateforme Sensor pour Tydom (températures, énergie…)."""
from __future__ import annotations

import logging

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.const import UnitOfTemperature, UnitOfEnergy, UnitOfPower
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN, SIGNAL_TYDOM_UPDATE
from .coordinator import TydomCoordinator

_LOGGER = logging.getLogger(__name__)

# Capteurs supplémentaires extraits de chaque équipement
EXTRA_SENSORS = {
    "temperature": (SensorDeviceClass.TEMPERATURE, UnitOfTemperature.CELSIUS, SensorStateClass.MEASUREMENT),
    "batteryLevel": (SensorDeviceClass.BATTERY, "%", SensorStateClass.MEASUREMENT),
    "energyIndex": (SensorDeviceClass.ENERGY, UnitOfEnergy.KILO_WATT_HOUR, SensorStateClass.TOTAL_INCREASING),
    "power": (SensorDeviceClass.POWER, UnitOfPower.WATT, SensorStateClass.MEASUREMENT),
}


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: TydomCoordinator = hass.data[DOMAIN][entry.entry_id]
    entities_added: set[str] = set()

    @callback
    def _check_new_sensors() -> None:
        new_entities = []
        for key, device_data in coordinator.devices.items():
            values = device_data.get("values", {})
            config = coordinator.device_configs.get(key, {})
            for value_name, (dev_class, unit, state_class) in EXTRA_SENSORS.items():
                sensor_key = f"{key}_{value_name}"
                if value_name in values and sensor_key not in entities_added:
                    entities_added.add(sensor_key)
                    new_entities.append(
                        TydomSensor(
                            coordinator=coordinator,
                            key=key,
                            sensor_key=sensor_key,
                            value_name=value_name,
                            name=f"{config.get('name', key)} {value_name}",
                            device_class=dev_class,
                            unit=unit,
                            state_class=state_class,
                        )
                    )
        if new_entities:
            async_add_entities(new_entities)

    entry.async_on_unload(
        async_dispatcher_connect(hass, f"{SIGNAL_TYDOM_UPDATE}_new", lambda _: _check_new_sensors())
    )
    _check_new_sensors()


class TydomSensor(SensorEntity):
    """Représente un capteur de valeur Tydom."""

    _attr_has_entity_name = True
    _attr_should_poll = False

    def __init__(self, coordinator, key, sensor_key, value_name, name, device_class, unit, state_class):
        self._coordinator = coordinator
        self._key = key
        self._value_name = value_name
        self._attr_unique_id = f"tydom_sensor_{sensor_key}"
        self._attr_name = name
        self._attr_device_class = device_class
        self._attr_native_unit_of_measurement = unit
        self._attr_state_class = state_class
        self._attr_native_value = None
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, key)},
            name=name,
            manufacturer="Delta Dore",
            model="Tydom",
        )

    async def async_added_to_hass(self) -> None:
        self.async_on_remove(
            async_dispatcher_connect(
                self.hass,
                f"{SIGNAL_TYDOM_UPDATE}_{self._key}",
                self._handle_update,
            )
        )
        self._update_from_coordinator()

    @callback
    def _handle_update(self, data: dict) -> None:
        self._update_from_coordinator()
        self.async_write_ha_state()

    def _update_from_coordinator(self) -> None:
        values = self._coordinator.devices.get(self._key, {}).get("values", {})
        raw = values.get(self._value_name)
        if raw is not None:
            try:
                self._attr_native_value = float(raw)
            except (ValueError, TypeError):
                self._attr_native_value = raw
