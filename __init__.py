"""Hisense TV integration for Home Assistant."""
import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import DOMAIN
from .tv_connector import HisenseTVConnector

_LOGGER = logging.getLogger(__name__)

PLATFORMS = ["media_player"]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Hisense TV from a config entry."""
    tv_ip = entry.data.get("tv_ip")
    _LOGGER.info("Setting up Hisense TV for %s", tv_ip)

    if DOMAIN not in hass.data:
        hass.data[DOMAIN] = {}

    # Create the TV connector with stored credentials
    connector = HisenseTVConnector(tv_ip, entry.data)

    hass.data[DOMAIN][entry.entry_id] = {
        "config": entry.data,
        "connector": connector,
    }

    has_token = bool(entry.data.get("accesstoken"))
    _LOGGER.info(
        "Credentials loaded: tv_ip=%s, mac=%s, has_token=%s",
        tv_ip,
        entry.data.get("mac_address"),
        has_token,
    )

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id, None)
    return unload_ok
