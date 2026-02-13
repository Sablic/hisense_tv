"""Config flow for Hisense TV integration.

Step 1: IP address of the TV.
Step 2: Connect to TV via MQTT, show PIN on screen, user enters PIN → get tokens.
All credentials are stored in config_entry.data (no files).
"""
import ipaddress
import logging

import voluptuous as vol

from homeassistant import config_entries

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)


def _get_mac_from_arp(ip: str) -> str | None:
    """Read MAC address from /proc/net/arp (works even when TV is off)."""
    try:
        with open("/proc/net/arp", "r") as f:
            for line in f:
                # Format: IP  HWtype  Flags  HWaddress  Mask  Device
                if not line.startswith(ip + " ") and f" {ip} " not in line:
                    continue
                parts = line.split()
                if len(parts) >= 4:
                    mac = parts[3]
                    if ":" in mac and len(mac) == 17 and mac != "00:00:00:00:00:00":
                        return mac.lower()
    except Exception as e:
        _LOGGER.warning("Could not read /proc/net/arp for %s: %s", ip, e)
    return None


def _start_auth_session(tv_ip: str, mac_address: str | None):
    """Create AuthSession and call start() — blocking, run in executor."""
    from .auth import AuthSession

    session = AuthSession(tv_ip, mac_address)
    session.start()          # blocks until PIN window appears on TV
    return session


def _send_pin(session, pin_code: str) -> dict:
    """Send PIN via active session — blocking, run in executor."""
    return session.send_pin(pin_code)


class HisenseTVConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Hisense TV."""

    VERSION = 1

    def __init__(self):
        """Initialize."""
        self._tv_ip: str | None = None
        self._mac_address: str | None = None
        self._auth_session = None  # AuthSession object (lives between steps)

    async def async_step_user(self, user_input=None):
        """Step 1: Ask for TV IP address."""
        errors = {}

        if user_input is not None:
            tv_ip = user_input["tv_ip"].strip()

            try:
                ipaddress.ip_address(tv_ip)
            except ValueError:
                errors["tv_ip"] = "invalid_ip"

            if not errors:
                await self.async_set_unique_id(tv_ip)
                self._abort_if_unique_id_configured()

                self._tv_ip = tv_ip

                # Get MAC from ARP (blocking)
                self._mac_address = await self.hass.async_add_executor_job(
                    _get_mac_from_arp, tv_ip
                )

                # Start MQTT auth session — triggers PIN on TV screen
                try:
                    self._auth_session = await self.hass.async_add_executor_job(
                        _start_auth_session, tv_ip, self._mac_address
                    )
                except Exception as exc:
                    _LOGGER.error("Failed to connect to TV: %s", exc)
                    errors["tv_ip"] = "cannot_connect"

            if not errors:
                return await self.async_step_pin()

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema({
                vol.Required("tv_ip", default="192.168.32.19"): str,
            }),
            errors=errors,
        )

    async def async_step_pin(self, user_input=None):
        """Step 2: User enters PIN shown on TV, we exchange it for tokens."""
        errors = {}
        mac_display = self._mac_address or "unknown"

        if user_input is not None:
            pin_code = user_input["pin_code"].strip()

            if not pin_code.isdigit() or len(pin_code) != 4:
                errors["pin_code"] = "invalid_pin"

            if not errors:
                try:
                    credentials = await self.hass.async_add_executor_job(
                        _send_pin, self._auth_session, pin_code
                    )
                except RuntimeError as exc:
                    # PIN rejected
                    _LOGGER.error("PIN rejected: %s", exc)
                    errors["pin_code"] = "wrong_pin"
                except Exception as exc:
                    _LOGGER.error("Auth error: %s", exc)
                    errors["pin_code"] = "auth_error"

            if not errors:
                self._auth_session = None  # cleanup

                return self.async_create_entry(
                    title=f"Hisense TV ({self._tv_ip})",
                    data={
                        "tv_ip": self._tv_ip,
                        "mac_address": self._mac_address or "unknown",
                        # Tokens from TV
                        "accesstoken": credentials["accesstoken"],
                        "accesstoken_time": credentials["accesstoken_time"],
                        "accesstoken_duration_day": credentials["accesstoken_duration_day"],
                        "refreshtoken": credentials["refreshtoken"],
                        "refreshtoken_time": credentials["refreshtoken_time"],
                        "refreshtoken_duration_day": credentials["refreshtoken_duration_day"],
                        # MQTT credentials
                        "client_id": credentials["client_id"],
                        "mqtt_username": credentials["username"],
                        "mqtt_password": credentials["password"],
                    },
                )

        return self.async_show_form(
            step_id="pin",
            data_schema=vol.Schema({
                vol.Optional("mac_address", default=mac_display): str,
                vol.Required("pin_code"): str,
            }),
            description_placeholders={
                "tv_ip": self._tv_ip,
                "mac_address": mac_display,
            },
            errors=errors,
        )

    async def async_on_unload(self):
        """Cleanup if flow is cancelled."""
        if self._auth_session:
            try:
                await self.hass.async_add_executor_job(self._auth_session.stop)
            except Exception:
                pass
            self._auth_session = None
