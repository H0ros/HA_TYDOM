"""Constantes pour l'intégration Tydom."""

DOMAIN = "tydom"

# Signaux dispatcher
SIGNAL_TYDOM_UPDATE = "tydom_update"
SIGNAL_TYDOM_CONNECTED = "tydom_connected"

# Configuration
CONF_MAC = "mac_address"
CONF_PASSWORD = "password"
CONF_HOST = "host"

# Types d'équipements
DEVICE_TYPE_SHUTTER = "cover"
DEVICE_TYPE_LIGHT = "light"
DEVICE_TYPE_SWITCH = "switch"
DEVICE_TYPE_THERMOSTAT = "climate"
DEVICE_TYPE_SMOKE = "binary_sensor"
DEVICE_TYPE_GATE = "cover"
DEVICE_TYPE_GARAGE = "cover"
DEVICE_TYPE_ALARM = "alarm_control_panel"

# Mapping types Tydom -> types HA
DEVICE_CATEGORY_MAP = {
    "SHUTTER": "cover",
    "BLIND": "cover",
    "CURTAIN": "cover",
    "GATE": "cover",
    "GARAGE": "cover",
    "WINDOWOPENER": "cover",
    "LIGHT": "light",
    "DIMMER": "light",
    "OUTLET": "switch",
    "SWITCH": "switch",
    "HVAC": "climate",
    "THERMOSTAT": "climate",
    "BOILER": "climate",
    "SMOKE": "binary_sensor",
    "ALARM": "alarm_control_panel",
    "SENSOR": "sensor",
}

# Plateformes supportées
PLATFORMS = ["cover", "light", "switch", "climate", "binary_sensor", "sensor"]
