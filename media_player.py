"""Media player platform for Hisense TV integration."""
import asyncio
import logging
import socket
from typing import Any

from homeassistant.components.media_player import (
    MediaPlayerEntity,
    MediaPlayerEntityFeature,
    MediaPlayerState,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.event import async_track_time_interval

from datetime import datetime, timedelta

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

# How often to poll TV state (seconds)
SCAN_INTERVAL_SEC = 5

# Supported features
SUPPORTED_FEATURES = (
    MediaPlayerEntityFeature.TURN_ON
    | MediaPlayerEntityFeature.TURN_OFF
    | MediaPlayerEntityFeature.VOLUME_SET
    | MediaPlayerEntityFeature.VOLUME_STEP
    | MediaPlayerEntityFeature.VOLUME_MUTE
    | MediaPlayerEntityFeature.SELECT_SOURCE
)



async def async_setup_entry(hass, config_entry, async_add_entities):
    """Set up the Hisense TV media player."""
    _LOGGER.info("Setting up Hisense TV media player for entry: %s", config_entry.entry_id)

    data = hass.data[DOMAIN][config_entry.entry_id]
    connector = data["connector"]

    entity = HisenseTVEntity(config_entry, connector, hass)
    async_add_entities([entity], True)
    _LOGGER.info("Hisense TV media player entity added: %s", entity.name)


class HisenseTVEntity(MediaPlayerEntity):
    """Representation of a Hisense TV media player with real status polling."""

    def __init__(self, config_entry, connector, hass):
        """Initialize the Hisense TV entity."""
        super().__init__()
        self._config_entry = config_entry
        self._connector = connector
        self._hass = hass

        # Get configuration data
        self._tv_ip = config_entry.data.get("tv_ip")
        self._mac_address = config_entry.data.get("mac_address")

        self._tv_name = f"Hisense TV ({self._tv_ip})" if self._tv_ip else "Hisense TV"

        # Initialize state
        self._attr_state = MediaPlayerState.OFF
        self._attr_volume_level = 0.5
        self._attr_source = None
        self._attr_source_list = []
        self._attr_is_volume_muted = False
        self._attr_available = True
        self._attr_app_name = None

        # Full source/app data from TV
        self._sources_data: list[dict] = []
        self._apps_data: list[dict] = []

        # Polling unsub handle
        self._unsub_poll = None

        # Token refresh guard
        self._refreshing_tokens = False

        _LOGGER.info("Hisense TV entity initialized: %s", self._tv_name)

    @property
    def name(self):
        """Return the name of the entity."""
        return self._tv_name

    @property
    def unique_id(self):
        """Return a unique ID."""
        return f"{self._config_entry.entry_id}_tv"

    @property
    def supported_features(self):
        """Flag media player features that are supported."""
        return SUPPORTED_FEATURES

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return extra state attributes with connection info and token details."""
        attrs: dict[str, Any] = {
            "tv_ip": self._tv_ip,
            "mac_address": self._mac_address,
        }

        # Access token info
        access_token = self._connector._accesstoken
        if access_token:
            attrs["access_token"] = access_token[:12] + "…" if len(access_token) > 12 else access_token

        access_time = self._connector._accesstoken_time
        access_days = self._connector._accesstoken_duration_day
        if access_time and int(access_time) > 0:
            issued = datetime.fromtimestamp(int(access_time))
            expires = datetime.fromtimestamp(int(access_time) + int(access_days) * 86400)
            attrs["access_token_issued"] = issued.strftime("%Y-%m-%d %H:%M:%S")
            attrs["access_token_expires"] = expires.strftime("%Y-%m-%d %H:%M:%S")

        # Refresh token info
        refresh_token = self._connector._refreshtoken
        if refresh_token:
            attrs["refresh_token"] = refresh_token[:12] + "…" if len(refresh_token) > 12 else refresh_token

        refresh_time = self._connector._refreshtoken_time
        refresh_days = self._connector._refreshtoken_duration_day
        if refresh_time and int(refresh_time) > 0:
            issued = datetime.fromtimestamp(int(refresh_time))
            expires = datetime.fromtimestamp(int(refresh_time) + int(refresh_days) * 86400)
            attrs["refresh_token_issued"] = issued.strftime("%Y-%m-%d %H:%M:%S")
            attrs["refresh_token_expires"] = expires.strftime("%Y-%m-%d %H:%M:%S")

        return attrs

    @property
    def should_poll(self):
        """No default polling, we use our own timer."""
        return False

    async def async_added_to_hass(self):
        """Start polling when entity is added to HA."""
        await super().async_added_to_hass()

        # Do initial state check
        await self._async_update_state()

        # Set up periodic polling
        self._unsub_poll = async_track_time_interval(
            self._hass,
            self._async_poll_state,
            timedelta(seconds=SCAN_INTERVAL_SEC),
        )
        _LOGGER.info("Started polling TV state every %s seconds for %s", SCAN_INTERVAL_SEC, self._tv_name)

    async def async_will_remove_from_hass(self):
        """Stop polling when entity is removed."""
        if self._unsub_poll:
            self._unsub_poll()
            self._unsub_poll = None

    async def _async_poll_state(self, now=None):
        """Periodic callback to poll TV state."""
        await self._async_update_state()
        await self._async_refresh_tokens_if_needed()

    async def _async_update_state(self):
        """Query TV via MQTT and update state + volume."""
        try:
            tv_state = await self._hass.async_add_executor_job(
                self._connector.get_tv_state
            )

            old_state = self._attr_state

            if tv_state is None:
                # No MQTT connection → OFF
                self._attr_state = MediaPlayerState.OFF
                self._attr_available = True
            elif "fake_sleep" in tv_state.get("statetype", ""):
                # TV in sleep mode → STANDBY
                self._attr_state = MediaPlayerState.STANDBY
                self._attr_available = True
            else:
                # TV is on → ON, and query volume + sources
                self._attr_state = MediaPlayerState.ON
                self._attr_available = True
                await self._async_update_volume()
                await self._async_update_sources()

            if old_state != self._attr_state:
                _LOGGER.info(
                    "TV %s state changed: %s → %s",
                    self._tv_name, old_state, self._attr_state,
                )

            self.async_write_ha_state()

        except Exception as e:
            _LOGGER.error("Error polling TV state for %s: %s", self._tv_name, e)

    async def _async_update_volume(self):
        """Query TV volume and mute status via MQTT."""
        try:
            vol_data = await self._hass.async_add_executor_job(
                self._connector.get_volume
            )
            if vol_data is not None:
                volume_value = vol_data.get("volume_value", 0)
                volume_type = vol_data.get("volume_type", 0)

                self._attr_volume_level = volume_value / 100.0
                # volume_type 0 = normal, non-zero = muted
                self._attr_is_volume_muted = volume_type != 0

                _LOGGER.debug(
                    "TV %s volume: %d/100, muted=%s",
                    self._tv_name, volume_value, self._attr_is_volume_muted,
                )
        except Exception as e:
            _LOGGER.error("Error polling volume for %s: %s", self._tv_name, e)

    async def _async_update_sources(self):
        """Query TV source list + app list, combine into one source list."""
        try:
            # Get hardware sources
            sources = await self._hass.async_add_executor_job(
                self._connector.get_source_list
            )
            if sources and isinstance(sources, list):
                self._sources_data = sources

            # Get apps
            apps = await self._hass.async_add_executor_job(
                self._connector.get_app_list
            )
            if apps and isinstance(apps, list):
                self._apps_data = apps

            # Build combined list: sources with signal + all apps
            combined = []

            # Sources with signal first
            for s in self._sources_data:
                if s.get("has_signal") == "1":
                    combined.append(s.get("sourcename", s.get("sourceid", "Unknown")))

            # Then apps (prefixed with 📺 to distinguish)
            for app in self._apps_data:
                app_name = app.get("name", "")
                if app_name and app_name not in combined:
                    combined.append(app_name)

            if combined:
                self._attr_source_list = combined
                _LOGGER.debug("TV %s source list: %s", self._tv_name, combined)

        except Exception as e:
            _LOGGER.error("Error polling sources for %s: %s", self._tv_name, e)

    async def _async_refresh_tokens_if_needed(self):
        """Check if tokens expire within 1 hour and refresh them.

        Algorithm:
        1. If TV was off → turn on via WOL/MQTT, mute
        2. Refresh tokens
        3. If TV was originally off → turn it back off
        4. Save new tokens to config_entry.data
        """
        if self._refreshing_tokens:
            return

        try:
            expires_soon = await self._hass.async_add_executor_job(
                self._connector.token_expires_soon
            )
            if not expires_soon:
                return

            self._refreshing_tokens = True
            tv_was_off = self._attr_state in (MediaPlayerState.OFF, MediaPlayerState.STANDBY)

            _LOGGER.warning(
                "Token expires within 1 hour for %s! Starting refresh procedure (TV was %s)",
                self._tv_name, "OFF" if tv_was_off else "ON",
            )

            # Step 1: If TV is off, turn it on and mute
            if tv_was_off:
                _LOGGER.info("Waking up TV %s for token refresh...", self._tv_name)

                # Try MQTT power on first, then WOL
                success = await self._hass.async_add_executor_job(
                    self._connector.power_on
                )
                if not success and self._mac_address:
                    await self._hass.async_add_executor_job(
                        self._send_wol, self._mac_address
                    )

                # Wait for TV to boot up
                await asyncio.sleep(15)

                # Mute so it doesn't disturb
                _LOGGER.info("Muting TV %s during token refresh", self._tv_name)
                await self._hass.async_add_executor_job(
                    self._connector.send_key, "KEY_MUTE"
                )
                await asyncio.sleep(2)

            # Step 2: Refresh tokens
            _LOGGER.info("Refreshing tokens for %s...", self._tv_name)
            new_creds = await self._hass.async_add_executor_job(
                self._connector.refresh_tokens
            )

            if new_creds:
                # Save new tokens to config_entry.data
                updated_data = dict(self._config_entry.data)
                updated_data.update({
                    "accesstoken": new_creds.get("accesstoken"),
                    "accesstoken_time": new_creds.get("accesstoken_time"),
                    "accesstoken_duration_day": new_creds.get("accesstoken_duration_day"),
                    "refreshtoken": new_creds.get("refreshtoken"),
                    "refreshtoken_time": new_creds.get("refreshtoken_time"),
                    "refreshtoken_duration_day": new_creds.get("refreshtoken_duration_day"),
                })
                self._hass.config_entries.async_update_entry(
                    self._config_entry, data=updated_data
                )
                _LOGGER.info("New tokens saved to config_entry for %s", self._tv_name)
            else:
                _LOGGER.error("Token refresh FAILED for %s", self._tv_name)

            # Step 3: If TV was off, turn it back off
            if tv_was_off:
                _LOGGER.info("Turning TV %s back off after token refresh", self._tv_name)
                await asyncio.sleep(3)
                await self._hass.async_add_executor_job(
                    self._connector.power_off
                )
                self._attr_state = MediaPlayerState.OFF
                self.async_write_ha_state()

        except Exception as e:
            _LOGGER.error("Error during token refresh for %s: %s", self._tv_name, e)
        finally:
            self._refreshing_tokens = False

    async def async_turn_on(self):
        """Turn the media player on.

        Strategy based on current state:
        - STANDBY (fake_sleep): MQTT is reachable → send KEY_POWER via MQTT
        - OFF (MQTT unreachable): send Wake-on-LAN magic packet
        """
        current = self._attr_state

        if current == MediaPlayerState.STANDBY:
            # TV is in standby, MQTT is available → wake via MQTT
            _LOGGER.info("TV %s is in STANDBY, sending KEY_POWER via MQTT", self._tv_name)
            await self._hass.async_add_executor_job(
                self._connector.power_on
            )
        elif current == MediaPlayerState.OFF:
            # TV is fully off, MQTT unreachable → WOL
            if not self._mac_address:
                _LOGGER.warning("Cannot turn on %s: no MAC address for WOL", self._tv_name)
                return
            _LOGGER.info("TV %s is OFF, sending WOL to %s", self._tv_name, self._mac_address)
            await self._hass.async_add_executor_job(
                self._send_wol, self._mac_address
            )
        else:
            # Already ON or PLAYING — nothing to do
            _LOGGER.debug("TV %s is already in state %s, ignoring turn_on", self._tv_name, current)
            return

        # Optimistically set state, polling will confirm
        self._attr_state = MediaPlayerState.ON
        self.async_write_ha_state()

    async def async_turn_off(self):
        """Turn the media player off via MQTT KEY_POWER."""
        current = self._attr_state

        if current in (MediaPlayerState.OFF, MediaPlayerState.STANDBY):
            # Already off or in standby — nothing to do
            _LOGGER.debug("TV %s is already %s, ignoring turn_off", self._tv_name, current)
            return

        _LOGGER.info("Turning off %s via MQTT", self._tv_name)
        success = await self._hass.async_add_executor_job(
            self._connector.power_off
        )
        if success:
            self._attr_state = MediaPlayerState.OFF
            self.async_write_ha_state()
        else:
            _LOGGER.warning("Failed to send power off to %s", self._tv_name)

    @staticmethod
    def _send_wol(mac_address: str):
        """Send a Wake-on-LAN magic packet to the given MAC address."""
        mac_bytes = bytes.fromhex(mac_address.replace(":", "").replace("-", ""))
        magic_packet = b"\xff" * 6 + mac_bytes * 16

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.sendto(magic_packet, ("<broadcast>", 9))

    async def async_set_volume_level(self, volume: float):
        """Set volume level, range 0..1 → TV 0-100."""
        tv_volume = int(round(volume * 100))
        _LOGGER.info("Setting volume to %d for %s", tv_volume, self._tv_name)
        success = await self._hass.async_add_executor_job(
            self._connector.change_volume, tv_volume
        )
        if success:
            self._attr_volume_level = volume
            self._attr_is_volume_muted = False
            self.async_write_ha_state()

    async def async_volume_up(self):
        """Volume up via KEY_VOLUMEUP."""
        _LOGGER.info("Volume up for %s", self._tv_name)
        success = await self._hass.async_add_executor_job(
            self._connector.send_key, "KEY_VOLUMEUP"
        )
        if success:
            # Optimistic update, polling will correct
            self._attr_volume_level = min(self._attr_volume_level + 0.01, 1.0)
            self._attr_is_volume_muted = False
            self.async_write_ha_state()

    async def async_volume_down(self):
        """Volume down via KEY_VOLUMEDOWN."""
        _LOGGER.info("Volume down for %s", self._tv_name)
        success = await self._hass.async_add_executor_job(
            self._connector.send_key, "KEY_VOLUMEDOWN"
        )
        if success:
            self._attr_volume_level = max(self._attr_volume_level - 0.01, 0.0)
            self._attr_is_volume_muted = False
            self.async_write_ha_state()

    async def async_mute_volume(self, mute: bool):
        """Toggle mute via KEY_MUTE."""
        _LOGGER.info("%s mute for %s", "Muting" if mute else "Unmuting", self._tv_name)
        success = await self._hass.async_add_executor_job(
            self._connector.mute_toggle
        )
        if success:
            self._attr_is_volume_muted = mute
            self.async_write_ha_state()

    async def async_select_source(self, source: str):
        """Select input source or launch app via connector."""
        # Check if it's a hardware source
        source_id = None
        for s in self._sources_data:
            if s.get("sourcename") == source or s.get("sourceid") == source:
                source_id = s.get("sourceid")
                break

        if source_id:
            # It's a hardware source → change source
            _LOGGER.info("Selecting source %s (id=%s) for %s", source, source_id, self._tv_name)
            success = await self._hass.async_add_executor_job(
                self._connector.change_source, source_id
            )
            if success:
                self._attr_source = source
                self._attr_state = MediaPlayerState.ON
                self.async_write_ha_state()
            return

        # Check if it's an app
        for app in self._apps_data:
            if app.get("name") == source:
                _LOGGER.info("Launching app %s for %s", source, self._tv_name)
                success = await self._hass.async_add_executor_job(
                    self._connector.launch_app,
                    app["name"],
                    app["appId"],
                    app["url"],
                )
                if success:
                    self._attr_source = source
                    self._attr_app_name = source
                    self._attr_state = MediaPlayerState.PLAYING
                    self.async_write_ha_state()
                return

        _LOGGER.warning("Source %s not found for %s", source, self._tv_name)
