"""Plateforme Binary Sensor pour Tydom (détecteurs fumée, ouverture…)."""
from __future__ import annotations

import logging

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN, SIGNAL_TYDOM_UPDATE, DEVICE_TYPE_SMOKE
from .coordinator import TydomCoordinator

_LOGGER = logging.getLogger(__name__)


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
        for key in coordinator.get_all_devices_by_type(DEVICE_TYPE_SMOKE):
            if key not in entities_added:
                entities_added.add(key)
                config = coordinator.device_configs.get(key, {})
                new_entities.append(
                    TydomBinarySensor(
                        coordinator=coordinator,
                        key=key,
                        device_id=config.get("device_id", key.split("_")[0]),
                        endpoint_id=config.get("endpoint_id", key.split("_")[1] if "_" in key else "0"),
                        name=config.get("name", f"Capteur {key}"),
                        device_type=config.get("type", "SMOKE"),
                    )
                )
        if new_entities:
            async_add_entities(new_entities)

    entry.async_on_unload(
        async_dispatcher_connect(hass, f"{SIGNAL_TYDOM_UPDATE}_config", lambda _: _check_new_sensors())
    )
    _check_new_sensors()


class TydomBinarySensor(BinarySensorEntity):
    """Représente un capteur binaire Tydom."""

    _attr_has_entity_name = True
    _attr_should_poll = False

    def __init__(self, coordinator, key, device_id, endpoint_id, name, device_type="SMOKE"):
        self._coordinator = coordinator
        self._key = key
        self._device_id = device_id
        self._endpoint_id = endpoint_id
        self._attr_unique_id = f"tydom_binary_{key}"
        self._attr_name = name
        self._is_on: bool = False

        dtype = device_type.upper()
        if "SMOKE" in dtype:
            self._attr_device_class = BinarySensorDeviceClass.SMOKE
        elif "MOTION" in dtype:
            self._attr_device_class = BinarySensorDeviceClass.MOTION
        elif "DOOR" in dtype or "OPEN" in dtype:
            self._attr_device_class = BinarySensorDeviceClass.DOOR
        elif "WINDOW" in dtype:
            self._attr_device_class = BinarySensorDeviceClass.WINDOW
        else:
            self._attr_device_class = BinarySensorDeviceClass.SAFETY

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
        alarm = values.get("alarmState") or values.get("intrusionDetect") or values.get("smokeDetect")
        if alarm is not None:
            self._is_on = bool(alarm)

    @property
    def is_on(self) -> bool:
        return self._is_on
