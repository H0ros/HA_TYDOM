"""Constantes pour l'intégration Tydom."""

DOMAIN = "tydom"

# Clés de configuration
CONF_MAC = "mac"
CONF_PASSWORD = "password"
CONF_HOST = "host"
CONF_DD_EMAIL = "deltadore_email"
CONF_DD_PASSWORD = "deltadore_password"

# Intervalle de polling (secondes)
DEFAULT_SCAN_INTERVAL = 60

# Correspondance last_usage Tydom → plateforme HA
USAGE_TO_PLATFORM: dict[str, str] = {
    "shutter": "cover",
    "garage_door": "cover",
    "window": "cover",
    "gate": "cover",
    "light": "light",
    "dimmer": "light",
    "switch": "switch",
    "boiler": "climate",
    "electric_heater": "climate",
    "hvac": "climate",
    "thermostat": "climate",
    "smoke_detector": "binary_sensor",
    "motion_detector": "binary_sensor",
    "opening_detector": "binary_sensor",
    "temperature_sensor": "sensor",
    "humidity_sensor": "sensor",
    "co2_sensor": "sensor",
    "battery": "sensor",
}

PLATFORMS = ["cover", "light", "switch", "climate", "binary_sensor", "sensor"]