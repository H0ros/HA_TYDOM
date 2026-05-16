"""Coordinateur de données pour l'intégration Tydom.

Gère :
- la connexion/reconnexion au client WebSocket Tydom
- la récupération initiale des devices (/configs/file + /devices/data + /devices/meta)
- la mise à jour périodique
- la distribution des mises à jour push vers les entités HA
"""
from __future__ import annotations

import asyncio
import logging
from datetime import timedelta
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import (
    CONF_HOST,
    CONF_MAC,
    CONF_PASSWORD,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
)
from .tydom_client import TydomClient

_LOGGER = logging.getLogger(__name__)


class TydomDevice:
    """Représentation d'un device Tydom."""

    def __init__(
        self,
        device_id: int,
        endpoint_id: int,
        name: str,
        last_usage: str,
        attributes: dict[str, Any],
    ) -> None:
        self.device_id = device_id
        self.endpoint_id = endpoint_id
        self.name = name
        self.last_usage = last_usage
        self.attributes = dict(attributes)

    @property
    def unique_id(self) -> str:
        return f"{self.device_id}_{self.endpoint_id}"

    def update_attributes(self, new_attrs: dict[str, Any]) -> None:
        self.attributes.update(new_attrs)

    def __repr__(self) -> str:
        return f"TydomDevice(id={self.device_id}, ep={self.endpoint_id}, name={self.name!r}, usage={self.last_usage})"


class TydomCoordinator(DataUpdateCoordinator[dict[str, TydomDevice]]):
    """Coordinateur central pour la box Tydom."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=DEFAULT_SCAN_INTERVAL),
        )
        self._entry = entry
        mac: str = entry.data[CONF_MAC]
        password: str = entry.data[CONF_PASSWORD]
        host: str = entry.data.get(CONF_HOST) or f"{mac}-tydom.local"

        self.client = TydomClient(
            mac=mac,
            password=password,
            host=host,
            message_callback=self._on_push_message,
        )
        # Dictionnaire device unique_id → TydomDevice
        self._devices: dict[str, TydomDevice] = {}
        self._connected = False

    # ------------------------------------------------------------------
    # Connexion / déconnexion
    # ------------------------------------------------------------------

    async def async_connect(self) -> bool:
        """Charge les devices initiaux.
        
        La box Tydom ferme la connexion TLS après chaque échange.
        On connecte, charge, déconnecte — puis le polling prend le relais.
        """
        if not await self.client.connect():
            return False

        try:
            await self._load_devices()
        except Exception as exc:
            _LOGGER.error("Erreur chargement initial des devices : %s", exc)
        finally:
            await self.client.disconnect()

        self._connected = True
        return True

    async def async_disconnect(self) -> None:
        """Ferme proprement la connexion."""
        await self.client.disconnect()
        self._connected = False

    # ------------------------------------------------------------------
    # Chargement initial des devices
    # ------------------------------------------------------------------

    async def _load_devices(self) -> None:
        """Charge la liste des devices depuis la box."""
        _LOGGER.debug("Chargement de /configs/file…")
        configs = await self.client.get_configs_file()
        if not configs:
            _LOGGER.warning("Réponse vide pour /configs/file")
            return

        # Extraction de la liste des endpoints depuis configs
        endpoints_config: list[dict] = []
        if isinstance(configs, dict):
            endpoints_config = configs.get("endpoints", [])
        elif isinstance(configs, list):
            # Certaines versions renvoient une liste directe
            endpoints_config = configs

        _LOGGER.debug("%d endpoints trouvés dans /configs/file", len(endpoints_config))

        # Construction d'un dict id_endpoint → config
        endpoint_cfg_map: dict[int, dict] = {}
        for ep in endpoints_config:
            ep_id = ep.get("id_endpoint") or ep.get("id")
            if ep_id is not None:
                endpoint_cfg_map[ep_id] = ep

        # Récupération des données courantes
        _LOGGER.debug("Chargement de /devices/data…")
        devices_data = await self.client.get_devices_data()
        if not devices_data:
            _LOGGER.warning("Réponse vide pour /devices/data")
            return

        for device_block in devices_data:
            if not isinstance(device_block, dict):
                continue
            device_id = device_block.get("id")
            if device_id is None:
                continue

            for ep in device_block.get("endpoints", []):
                if ep.get("error", 0) != 0:
                    continue
                ep_id = ep.get("id")
                if ep_id is None:
                    continue

                # Données courantes (liste de {name, value})
                attrs: dict[str, Any] = {}
                for item in ep.get("data", []):
                    attrs[item["name"]] = item["value"]

                # Infos de config
                cfg = endpoint_cfg_map.get(ep_id, {})
                name = cfg.get("name", f"Device {ep_id}")
                last_usage = cfg.get("last_usage", "unknown")

                unique_id = f"{device_id}_{ep_id}"
                if unique_id in self._devices:
                    self._devices[unique_id].update_attributes(attrs)
                else:
                    self._devices[unique_id] = TydomDevice(
                        device_id=device_id,
                        endpoint_id=ep_id,
                        name=name,
                        last_usage=last_usage,
                        attributes=attrs,
                    )

        _LOGGER.info("%d devices chargés depuis la box Tydom", len(self._devices))
        for d in self._devices.values():
            _LOGGER.debug("  → %s", d)

    # ------------------------------------------------------------------
    # Mise à jour périodique (DataUpdateCoordinator)
    # ------------------------------------------------------------------

    async def _async_update_data(self) -> dict[str, TydomDevice]:
        """Mise à jour périodique — reconnexion + polling de /devices/data.

        La box Tydom ferme la connexion TLS après chaque échange.
        On reconnecte à chaque mise à jour.
        """
        if self.client.is_connected:
            await self.client.disconnect()

        if not await self.client.connect():
            raise UpdateFailed("Impossible de se connecter à la box Tydom")

        try:
            devices_data = await self.client.get_devices_data()
        except Exception as exc:
            raise UpdateFailed(f"Erreur lors de /devices/data : {exc}") from exc
        finally:
            await self.client.disconnect()

        if devices_data:
            for device_block in devices_data:
                if not isinstance(device_block, dict):
                    continue
                device_id = device_block.get("id")
                for ep in device_block.get("endpoints", []):
                    if ep.get("error", 0) != 0:
                        continue
                    ep_id = ep.get("id")
                    if ep_id is None:
                        continue
                    unique_id = f"{device_id}_{ep_id}"
                    attrs = {item["name"]: item["value"] for item in ep.get("data", [])}
                    if unique_id in self._devices:
                        self._devices[unique_id].update_attributes(attrs)

        return dict(self._devices)

    # ------------------------------------------------------------------
    # Messages push
    # ------------------------------------------------------------------

    @callback
    def _on_push_message(self, uri_origin: str, data: Any) -> None:
        """Callback appelé par le client lors d'un message push Tydom."""
        _LOGGER.debug("Message push [%s] reçu", uri_origin)

        if not isinstance(data, list):
            return

        updated = False
        for device_block in data:
            if not isinstance(device_block, dict):
                continue
            device_id = device_block.get("id")
            for ep in device_block.get("endpoints", []):
                if ep.get("error", 0) != 0:
                    continue
                ep_id = ep.get("id")
                if ep_id is None:
                    continue
                unique_id = f"{device_id}_{ep_id}"
                attrs = {item["name"]: item["value"] for item in ep.get("data", [])}
                if unique_id in self._devices:
                    self._devices[unique_id].update_attributes(attrs)
                    updated = True

        if updated:
            # Notifie tous les abonnés (entités HA)
            self.async_set_updated_data(dict(self._devices))

    # ------------------------------------------------------------------
    # Accès aux devices
    # ------------------------------------------------------------------

    @property
    def devices(self) -> dict[str, TydomDevice]:
        return self._devices

    def get_device(self, unique_id: str) -> TydomDevice | None:
        return self._devices.get(unique_id)

    def devices_by_usage(self, usage: str) -> list[TydomDevice]:
        return [d for d in self._devices.values() if d.last_usage == usage]
