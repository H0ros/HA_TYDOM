"""Plateforme climate (thermostats, chaudières) pour Tydom."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.climate import (
    ClimateEntity,
    ClimateEntityFeature,
    HVACMode,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import ATTR_TEMPERATURE, UnitOfTemperature
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import TydomCoordinator, TydomDevice

_LOGGER = logging.getLogger(__name__)

_CLIMATE_USAGES = {"boiler", "electric_heater", "hvac", "thermostat"}

_TYDOM_TO_HVAC: dict[str, HVACMode] = {
    "HEATING": HVACMode.HEAT,
    "COOLING": HVACMode.COOL,
    "AUTO": HVACMode.AUTO,
    "OFF": HVACMode.OFF,
    "STOP": HVACMode.OFF,
    "ANTI_FROST": HVACMode.AUTO,
}

_HVAC_TO_TYDOM: dict[HVACMode, str] = {
    HVACMode.HEAT: "HEATING",
    HVACMode.COOL: "COOLING",
    HVACMode.AUTO: "AUTO",
    HVACMode.OFF: "STOP",
}


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: TydomCoordinator = hass.data[DOMAIN][entry.entry_id]
    entities = [
        TydomClimate(coordinator, device)
        for device in coordinator.devices.values()
        if device.last_usage in _CLIMATE_USAGES
    ]
    _LOGGER.debug("Ajout de %d entités climate Tydom", len(entities))
    async_add_entities(entities)


class TydomClimate(CoordinatorEntity[TydomCoordinator], ClimateEntity):
    """Thermostat/chaudière Tydom."""

    _attr_has_entity_name = True
    _attr_temperature_unit = UnitOfTemperature.CELSIUS
    _attr_hvac_modes = [HVACMode.HEAT, HVACMode.AUTO, HVACMode.OFF]
    _attr_supported_features = (
        ClimateEntityFeature.TARGET_TEMPERATURE
    )

    def __init__(self, coordinator: TydomCoordinator, device: TydomDevice) -> None:
        super().__init__(coordinator)
        self._device_uid = device.unique_id
        self._attr_unique_id = f"tydom_{device.unique_id}"
        self._attr_name = device.name

    @property
    def _device(self) -> TydomDevice | None:
        return self.coordinator.get_device(self._device_uid)

    @property
    def current_temperature(self) -> float | None:
        d = self._device
        if d is None:
            return None
        t = d.attributes.get("temperature") or d.attributes.get("currentTemperature")
        return float(t) if t is not None else None

    @property
    def target_temperature(self) -> float | None:
        d = self._device
        if d is None:
            return None
        t = d.attributes.get("setpoint") or d.attributes.get("targetTemperature")
        return float(t) if t is not None else None

    @property
    def hvac_mode(self) -> HVACMode:
        d = self._device
        if d is None:
            return HVACMode.OFF
        mode = d.attributes.get("hvacMode") or d.attributes.get("authorization")
        if mode:
            return _TYDOM_TO_HVAC.get(str(mode).upper(), HVACMode.AUTO)
        return HVACMode.AUTO

    async def async_set_temperature(self, **kwargs: Any) -> None:
        temp = kwargs.get(ATTR_TEMPERATURE)
        d = self._device
        if d and temp is not None:
            await self.coordinator.client.put_device_data(
                d.device_id, d.endpoint_id, "setpoint", temp
            )

    async def async_set_hvac_mode(self, hvac_mode: HVACMode) -> None:
        d = self._device
        if d:
            tydom_mode = _HVAC_TO_TYDOM.get(hvac_mode, "AUTO")
            await self.coordinator.client.put_device_data(
                d.device_id, d.endpoint_id, "hvacMode", tydom_mode
            )

    @callback
    def _handle_coordinator_update(self) -> None:
        self.async_write_ha_state()