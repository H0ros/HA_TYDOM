"""Coordinateur central pour l'intégration Tydom."""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.dispatcher import async_dispatcher_send

from .const import (
    DOMAIN,
    SIGNAL_TYDOM_UPDATE,
    DEVICE_TYPE_SHUTTER,
    DEVICE_TYPE_LIGHT,
    DEVICE_TYPE_SWITCH,
    DEVICE_TYPE_THERMOSTAT,
    DEVICE_TYPE_SMOKE,
    DEVICE_TYPE_GATE,
    DEVICE_TYPE_GARAGE,
    DEVICE_TYPE_ALARM,
    DEVICE_CATEGORY_MAP,
)
from .tydom_client import TydomClient

_LOGGER = logging.getLogger(__name__)


class TydomCoordinator:
    """Coordinateur qui gère les données Tydom et dispatche les updates."""

    def __init__(self, hass: HomeAssistant, client: TydomClient) -> None:
        """Initialise le coordinateur."""
        self.hass = hass
        self.client = client
        self.devices: dict[str, dict] = {}
        self.device_configs: dict[str, dict] = {}
        self._listen_task = None
        client.callback = self._on_message

    async def start(self) -> bool:
        """Démarre la connexion et l'écoute."""
        success = await self.client.connect()
        if not success:
            return False
        
        # Demander les données initiales
        await self.client.get_devices()
        await self.client.get_configs()
        await self.client.get_info()
        
        # Lancer la tâche d'écoute en arrière-plan
        self._listen_task = asyncio.create_task(self.client.listen())
        return True

    async def stop(self) -> None:
        """Arrête la connexion."""
        if self._listen_task:
            self._listen_task.cancel()
            try:
                await self._listen_task
            except asyncio.CancelledError:
                pass
        await self.client.disconnect()

    async def _on_message(self, msg_type: str, data: Any) -> None:
        """Traite les messages entrants de la box Tydom."""
        _LOGGER.debug("Message reçu - type: %s, data: %s", msg_type, str(data)[:200])
        
        if msg_type == "devices_data":
            await self._process_devices_data(data)
        elif msg_type == "devices_config":
            await self._process_devices_config(data)
        elif msg_type == "put_response":
            # Confirmation d'une commande envoyée
            await self._process_devices_data(data if isinstance(data, list) else [])

    async def _process_devices_data(self, data: list) -> None:
        """Traite les données des équipements."""
        if not isinstance(data, list):
            return

        for device in data:
            device_id = str(device.get("id", ""))
            if not device_id:
                continue

            endpoints = device.get("endpoints", [])
            for endpoint in endpoints:
                endpoint_id = str(endpoint.get("id", ""))
                key = f"{device_id}_{endpoint_id}"
                
                # Construire un dictionnaire des valeurs
                values = {}
                for ep_data in endpoint.get("data", []):
                    name = ep_data.get("name")
                    value = ep_data.get("value")
                    if name:
                        values[name] = value

                if key not in self.devices:
                    self.devices[key] = {
                        "device_id": device_id,
                        "endpoint_id": endpoint_id,
                        "values": values,
                    }
                else:
                    self.devices[key]["values"].update(values)

                # Notifier les entités de la mise à jour
                signal = f"{SIGNAL_TYDOM_UPDATE}_{key}"
                async_dispatcher_send(self.hass, signal, self.devices[key])

    async def _process_devices_config(self, data: list) -> None:
        """Traite la configuration des équipements (nom, type...)."""
        if not isinstance(data, list):
            return

        for device in data:
            device_id = str(device.get("id", ""))
            if not device_id:
                continue

            endpoints = device.get("endpoints", [])
            for endpoint in endpoints:
                endpoint_id = str(endpoint.get("id", ""))
                key = f"{device_id}_{endpoint_id}"
                
                self.device_configs[key] = {
                    "device_id": device_id,
                    "endpoint_id": endpoint_id,
                    "name": endpoint.get("name", f"Tydom {key}"),
                    "type": endpoint.get("type", ""),
                    "last_usage": endpoint.get("last_usage", ""),
                    "categories": device.get("categories", []),
                }

                _LOGGER.debug(
                    "Config device %s: name=%s, type=%s",
                    key,
                    self.device_configs[key]["name"],
                    self.device_configs[key]["type"],
                )

    def get_device_type(self, key: str) -> str:
        """Détermine le type HA d'un équipement."""
        config = self.device_configs.get(key, {})
        ep_type = config.get("type", "").upper()
        last_usage = config.get("last_usage", "").upper()
        
        # Correspondance des types Tydom vers les catégories HA
        for tydom_type, ha_type in DEVICE_CATEGORY_MAP.items():
            if tydom_type in ep_type or tydom_type in last_usage:
                return ha_type
        
        # Déduction depuis les valeurs disponibles
        values = self.devices.get(key, {}).get("values", {})
        if "position" in values or "thermPosition" in values:
            return DEVICE_TYPE_SHUTTER
        if "onFav" in values or "level" in values:
            return DEVICE_TYPE_LIGHT
        if "onState" in values:
            return DEVICE_TYPE_SWITCH
        if "setpoint" in values or "thermSetpoint" in values:
            return DEVICE_TYPE_THERMOSTAT
        
        return "unknown"

    def get_all_devices_by_type(self, device_type: str) -> list[str]:
        """Retourne tous les devices d'un type donné."""
        result = []
        for key in set(list(self.devices.keys()) + list(self.device_configs.keys())):
            if self.get_device_type(key) == device_type:
                result.append(key)
        return result

    async def refresh(self) -> None:
        """Demande un rafraîchissement complet."""
        await self.client.refresh_all()
        await self.client.get_devices()

    async def set_cover_position(self, device_id: str, endpoint_id: str, position: int) -> None:
        """Commande la position d'un volet (0=fermé, 100=ouvert)."""
        # Tydom utilise une position inversée parfois selon les modèles
        await self.client.set_device_data(
            device_id,
            endpoint_id,
            [{"name": "position", "value": position}],
        )

    async def set_cover_command(self, device_id: str, endpoint_id: str, command: str) -> None:
        """Envoie une commande à un volet (UP, DOWN, STOP)."""
        await self.client.set_device_data(
            device_id,
            endpoint_id,
            [{"name": "thermPosition", "value": command}],
        )

    async def set_light_state(self, device_id: str, endpoint_id: str, state: bool) -> None:
        """Allume ou éteint une lumière."""
        await self.client.set_device_data(
            device_id,
            endpoint_id,
            [{"name": "onFav", "value": state}],
        )

    async def set_light_level(self, device_id: str, endpoint_id: str, level: int) -> None:
        """Règle le niveau d'une lumière dimmable (0-100)."""
        await self.client.set_device_data(
            device_id,
            endpoint_id,
            [{"name": "level", "value": level}],
        )

    async def set_switch_state(self, device_id: str, endpoint_id: str, state: bool) -> None:
        """Allume ou éteint un interrupteur."""
        await self.client.set_device_data(
            device_id,
            endpoint_id,
            [{"name": "onState", "value": state}],
        )

    async def set_thermostat_setpoint(self, device_id: str, endpoint_id: str, temperature: float) -> None:
        """Règle la consigne de température."""
        await self.client.set_device_data(
            device_id,
            endpoint_id,
            [{"name": "setpoint", "value": temperature}],
        )
