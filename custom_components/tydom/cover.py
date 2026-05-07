"""Plateforme Cover (volets roulants, portails, etc.) pour Tydom."""
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
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN, SIGNAL_TYDOM_UPDATE, DEVICE_TYPE_SHUTTER
from .coordinator import TydomCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Configure les entités Cover depuis la config entry."""
    coordinator: TydomCoordinator = hass.data[DOMAIN][entry.entry_id]
    entities_added: set[str] = set()

    @callback
    def _check_new_covers() -> None:
        """Vérifie s'il y a de nouveaux volets à ajouter."""
        new_entities = []
        for key in coordinator.get_all_devices_by_type(DEVICE_TYPE_SHUTTER):
            if key not in entities_added:
                entities_added.add(key)
                config = coordinator.device_configs.get(key, {})
                new_entities.append(
                    TydomCover(
                        coordinator=coordinator,
                        key=key,
                        device_id=config.get("device_id", key.split("_")[0]),
                        endpoint_id=config.get("endpoint_id", key.split("_")[1] if "_" in key else "0"),
                        name=config.get("name", f"Volet {key}"),
                        device_type=config.get("type", "SHUTTER"),
                    )
                )
        if new_entities:
            async_add_entities(new_entities)

    # Écouter les mises à jour pour détecter de nouveaux équipements
    entry.async_on_unload(
        async_dispatcher_connect(hass, f"{SIGNAL_TYDOM_UPDATE}_config", lambda _: _check_new_covers())
    )

    # Vérification initiale
    _check_new_covers()


class TydomCover(CoverEntity):
    """Représente un volet roulant / portail Tydom."""

    _attr_has_entity_name = True
    _attr_should_poll = False

    def __init__(
        self,
        coordinator: TydomCoordinator,
        key: str,
        device_id: str,
        endpoint_id: str,
        name: str,
        device_type: str = "SHUTTER",
    ) -> None:
        """Initialise le volet."""
        self._coordinator = coordinator
        self._key = key
        self._device_id = device_id
        self._endpoint_id = endpoint_id
        self._attr_unique_id = f"tydom_cover_{key}"
        self._attr_name = name
        self._position: int | None = None
        self._is_closed: bool | None = None
        self._is_opening: bool = False
        self._is_closing: bool = False

        # Détecter le type de device pour la classe
        dtype = device_type.upper()
        if "GATE" in dtype:
            self._attr_device_class = CoverDeviceClass.GATE
        elif "GARAGE" in dtype:
            self._attr_device_class = CoverDeviceClass.GARAGE
        elif "WINDOW" in dtype:
            self._attr_device_class = CoverDeviceClass.WINDOW
        elif "CURTAIN" in dtype or "BLIND" in dtype:
            self._attr_device_class = CoverDeviceClass.BLIND
        else:
            self._attr_device_class = CoverDeviceClass.SHUTTER

        self._attr_supported_features = (
            CoverEntityFeature.OPEN
            | CoverEntityFeature.CLOSE
            | CoverEntityFeature.STOP
            | CoverEntityFeature.SET_POSITION
        )
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, key)},
            name=name,
            manufacturer="Delta Dore",
            model="Tydom",
        )

    async def async_added_to_hass(self) -> None:
        """S'abonne aux mises à jour dispatcher."""
        self.async_on_remove(
            async_dispatcher_connect(
                self.hass,
                f"{SIGNAL_TYDOM_UPDATE}_{self._key}",
                self._handle_update,
            )
        )
        # Charger l'état initial si disponible
        self._update_from_coordinator()

    @callback
    def _handle_update(self, data: dict) -> None:
        """Traite une mise à jour de données."""
        self._update_from_coordinator()
        self.async_write_ha_state()

    def _update_from_coordinator(self) -> None:
        """Met à jour l'état depuis le coordinateur."""
        device_data = self._coordinator.devices.get(self._key, {})
        values = device_data.get("values", {})

        # Position (0 = fermé, 100 = ouvert côté Tydom)
        raw_position = values.get("position")
        if raw_position is not None:
            try:
                self._position = int(raw_position)
                self._is_closed = self._position == 0
            except (ValueError, TypeError):
                pass

        # État mouvement
        therm_pos = values.get("thermPosition", "")
        if therm_pos == "UP":
            self._is_opening = True
            self._is_closing = False
        elif therm_pos == "DOWN":
            self._is_opening = False
            self._is_closing = True
        elif therm_pos == "STOP":
            self._is_opening = False
            self._is_closing = False

    @property
    def current_cover_position(self) -> int | None:
        """Retourne la position actuelle (0-100)."""
        return self._position

    @property
    def is_closed(self) -> bool | None:
        """Retourne True si le volet est fermé."""
        if self._position is not None:
            return self._position == 0
        return self._is_closed

    @property
    def is_opening(self) -> bool:
        """Retourne True si le volet est en train de s'ouvrir."""
        return self._is_opening

    @property
    def is_closing(self) -> bool:
        """Retourne True si le volet est en train de se fermer."""
        return self._is_closing

    async def async_open_cover(self, **kwargs: Any) -> None:
        """Ouvre le volet."""
        self._is_opening = True
        self._is_closing = False
        self.async_write_ha_state()
        await self._coordinator.set_cover_position(self._device_id, self._endpoint_id, 100)

    async def async_close_cover(self, **kwargs: Any) -> None:
        """Ferme le volet."""
        self._is_closing = True
        self._is_opening = False
        self.async_write_ha_state()
        await self._coordinator.set_cover_position(self._device_id, self._endpoint_id, 0)

    async def async_stop_cover(self, **kwargs: Any) -> None:
        """Arrête le volet."""
        self._is_opening = False
        self._is_closing = False
        self.async_write_ha_state()
        await self._coordinator.client.set_device_data(
            self._device_id,
            self._endpoint_id,
            [{"name": "thermPosition", "value": "STOP"}],
        )

    async def async_set_cover_position(self, **kwargs: Any) -> None:
        """Positionne le volet à un pourcentage précis."""
        position = kwargs[ATTR_POSITION]
        self._position = position
        self._is_closed = position == 0
        self.async_write_ha_state()
        await self._coordinator.set_cover_position(self._device_id, self._endpoint_id, position)
