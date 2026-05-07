"""Plateforme Climate (thermostat) pour Tydom."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.climate import (
    ClimateEntity,
    ClimateEntityFeature,
    HVACMode,
)
from homeassistant.const import ATTR_TEMPERATURE, UnitOfTemperature
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN, SIGNAL_TYDOM_UPDATE, DEVICE_TYPE_THERMOSTAT
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
    def _check_new_thermostats() -> None:
        new_entities = []
        for key in coordinator.get_all_devices_by_type(DEVICE_TYPE_THERMOSTAT):
            if key not in entities_added:
                entities_added.add(key)
                config = coordinator.device_configs.get(key, {})
                new_entities.append(
                    TydomClimate(
                        coordinator=coordinator,
                        key=key,
                        device_id=config.get("device_id", key.split("_")[0]),
                        endpoint_id=config.get("endpoint_id", key.split("_")[1] if "_" in key else "0"),
                        name=config.get("name", f"Thermostat {key}"),
                    )
                )
        if new_entities:
            async_add_entities(new_entities)

    entry.async_on_unload(
        async_dispatcher_connect(hass, f"{SIGNAL_TYDOM_UPDATE}_config", lambda _: _check_new_thermostats())
    )
    _check_new_thermostats()


class TydomClimate(ClimateEntity):
    """Représente un thermostat Tydom."""

    _attr_has_entity_name = True
    _attr_should_poll = False
    _attr_temperature_unit = UnitOfTemperature.CELSIUS
    _attr_hvac_modes = [HVACMode.HEAT, HVACMode.OFF, HVACMode.AUTO]
    _attr_supported_features = ClimateEntityFeature.TARGET_TEMPERATURE
    _attr_min_temp = 5.0
    _attr_max_temp = 30.0
    _attr_target_temperature_step = 0.5

    def __init__(self, coordinator, key, device_id, endpoint_id, name):
        self._coordinator = coordinator
        self._key = key
        self._device_id = device_id
        self._endpoint_id = endpoint_id
        self._attr_unique_id = f"tydom_climate_{key}"
        self._attr_name = name
        self._current_temperature: float | None = None
        self._target_temperature: float | None = None
        self._hvac_mode: HVACMode = HVACMode.AUTO
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
        
        temp = values.get("temperature") or values.get("currentTemperature")
        if temp is not None:
            try:
                self._current_temperature = float(temp)
            except (ValueError, TypeError):
                pass

        setpoint = values.get("setpoint") or values.get("thermSetpoint")
        if setpoint is not None:
            try:
                self._target_temperature = float(setpoint)
            except (ValueError, TypeError):
                pass

        authorization = values.get("authorization", "HEATING")
        if authorization == "STOP":
            self._hvac_mode = HVACMode.OFF
        elif authorization == "HEATING":
            self._hvac_mode = HVACMode.HEAT
        else:
            self._hvac_mode = HVACMode.AUTO

    @property
    def current_temperature(self) -> float | None:
        return self._current_temperature

    @property
    def target_temperature(self) -> float | None:
        return self._target_temperature

    @property
    def hvac_mode(self) -> HVACMode:
        return self._hvac_mode

    async def async_set_temperature(self, **kwargs: Any) -> None:
        temp = kwargs.get(ATTR_TEMPERATURE)
        if temp is not None:
            self._target_temperature = temp
            self.async_write_ha_state()
            await self._coordinator.set_thermostat_setpoint(self._device_id, self._endpoint_id, temp)

    async def async_set_hvac_mode(self, hvac_mode: HVACMode) -> None:
        self._hvac_mode = hvac_mode
        self.async_write_ha_state()
        authorization_map = {
            HVACMode.OFF: "STOP",
            HVACMode.HEAT: "HEATING",
            HVACMode.AUTO: "AUTO",
        }
        value = authorization_map.get(hvac_mode, "AUTO")
        await self._coordinator.client.set_device_data(
            self._device_id,
            self._endpoint_id,
            [{"name": "authorization", "value": value}],
        )
