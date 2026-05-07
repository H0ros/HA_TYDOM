"""Plateforme Light pour Tydom."""
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
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN, SIGNAL_TYDOM_UPDATE, DEVICE_TYPE_LIGHT
from .coordinator import TydomCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Configure les entités Light."""
    coordinator: TydomCoordinator = hass.data[DOMAIN][entry.entry_id]
    entities_added: set[str] = set()

    @callback
    def _check_new_lights() -> None:
        new_entities = []
        for key in coordinator.get_all_devices_by_type(DEVICE_TYPE_LIGHT):
            if key not in entities_added:
                entities_added.add(key)
                config = coordinator.device_configs.get(key, {})
                new_entities.append(
                    TydomLight(
                        coordinator=coordinator,
                        key=key,
                        device_id=config.get("device_id", key.split("_")[0]),
                        endpoint_id=config.get("endpoint_id", key.split("_")[1] if "_" in key else "0"),
                        name=config.get("name", f"Lumière {key}"),
                        device_type=config.get("type", "LIGHT"),
                    )
                )
        if new_entities:
            async_add_entities(new_entities)

    entry.async_on_unload(
        async_dispatcher_connect(hass, f"{SIGNAL_TYDOM_UPDATE}_config", lambda _: _check_new_lights())
    )
    _check_new_lights()


class TydomLight(LightEntity):
    """Représente une lumière Tydom."""

    _attr_has_entity_name = True
    _attr_should_poll = False

    def __init__(self, coordinator, key, device_id, endpoint_id, name, device_type="LIGHT"):
        self._coordinator = coordinator
        self._key = key
        self._device_id = device_id
        self._endpoint_id = endpoint_id
        self._attr_unique_id = f"tydom_light_{key}"
        self._attr_name = name
        self._is_on: bool = False
        self._brightness: int | None = None
        self._is_dimmable = "DIMMER" in device_type.upper()

        if self._is_dimmable:
            self._attr_color_mode = ColorMode.BRIGHTNESS
            self._attr_supported_color_modes = {ColorMode.BRIGHTNESS}
        else:
            self._attr_color_mode = ColorMode.ONOFF
            self._attr_supported_color_modes = {ColorMode.ONOFF}

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
        on_fav = values.get("onFav")
        if on_fav is not None:
            self._is_on = bool(on_fav)
        level = values.get("level")
        if level is not None:
            # Tydom level 0-100 → HA brightness 0-255
            self._brightness = int(int(level) * 255 / 100)

    @property
    def is_on(self) -> bool:
        return self._is_on

    @property
    def brightness(self) -> int | None:
        return self._brightness

    async def async_turn_on(self, **kwargs: Any) -> None:
        self._is_on = True
        if ATTR_BRIGHTNESS in kwargs and self._is_dimmable:
            ha_brightness = kwargs[ATTR_BRIGHTNESS]
            level = int(ha_brightness * 100 / 255)
            self._brightness = ha_brightness
            self.async_write_ha_state()
            await self._coordinator.set_light_level(self._device_id, self._endpoint_id, level)
        else:
            self.async_write_ha_state()
            await self._coordinator.set_light_state(self._device_id, self._endpoint_id, True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        self._is_on = False
        self.async_write_ha_state()
        await self._coordinator.set_light_state(self._device_id, self._endpoint_id, False)
