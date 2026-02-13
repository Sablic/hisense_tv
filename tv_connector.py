"""Hisense TV MQTT connector for status queries and commands.

Uses stored credentials (accesstoken) to connect to the TV's MQTT broker
and retrieve state information.
"""
import json
import logging
import os
import ssl
import time
from typing import Any

import paho.mqtt.client as mqtt

_LOGGER = logging.getLogger(__name__)

_DIR = os.path.dirname(os.path.abspath(__file__))
CERTFILE = os.path.join(_DIR, "rcm_certchain_pem.cer")
KEYFILE = os.path.join(_DIR, "rcm_pem_privkey.pkcs8")

MQTT_PORT = 36669
CONNECT_TIMEOUT = 10
QUERY_TIMEOUT = 15


class HisenseTVConnector:
    """Connects to Hisense TV via MQTT and queries its state."""

    def __init__(self, tv_ip: str, credentials: dict):
        """Initialize connector with TV IP and stored credentials."""
        self.tv_ip = tv_ip
        self._client_id = credentials.get("client_id", "")
        self._username = credentials.get("mqtt_username") or credentials.get("username", "")
        self._password = credentials.get("mqtt_password") or credentials.get("password", "")
        self._accesstoken = credentials.get("accesstoken", "")
        self._refreshtoken = credentials.get("refreshtoken", "")

        # Token expiration tracking
        self._accesstoken_time = credentials.get("accesstoken_time", "0")
        self._accesstoken_duration_day = credentials.get("accesstoken_duration_day", 0)
        self._refreshtoken_time = credentials.get("refreshtoken_time", "0")
        self._refreshtoken_duration_day = credentials.get("refreshtoken_duration_day", 0)

        # Topic paths (derived from client_id)
        cid = self._client_id
        self._topic_tv_ui = f"/remoteapp/tv/ui_service/{cid}/"
        self._topic_tv_ps = f"/remoteapp/tv/platform_service/{cid}/"
        self._topic_mobi = f"/remoteapp/mobile/{cid}/"
        self._topic_brcs = "/remoteapp/mobile/broadcast/"
        self._topic_remo = f"/remoteapp/tv/remote_service/{cid}/"

    # ── internal helpers ─────────────────────────────────────

    def _create_client(self, password: str | None = None) -> mqtt.Client:
        """Create an MQTT client with TLS and credentials.

        Args:
            password: MQTT password override (default: accesstoken).
        """
        client = mqtt.Client(
            client_id=self._client_id,
            clean_session=True,
            protocol=mqtt.MQTTv311,
            transport="tcp",
        )
        client.tls_set(
            ca_certs=None,
            certfile=CERTFILE,
            keyfile=KEYFILE,
            cert_reqs=ssl.CERT_NONE,
            tls_version=ssl.PROTOCOL_TLS,
        )
        client.tls_insecure_set(True)
        client.username_pw_set(
            username=self._username,
            password=password or self._accesstoken,
        )
        client.connected_flag = False  # type: ignore[attr-defined]
        client.cancel_loop = False  # type: ignore[attr-defined]
        return client

    @staticmethod
    def _wait(condition, timeout: int = QUERY_TIMEOUT) -> bool:
        """Block until condition() is False or timeout. Returns True on success."""
        start = time.time()
        while condition():
            if time.time() - start > timeout:
                return False
            time.sleep(0.2)
        return True

    def _query(self, subscribe_topic: str, publish_topic: str) -> dict | None:
        """Generic MQTT query: subscribe → publish → wait for response → return parsed JSON."""
        result: dict[str, Any] = {"data": None}

        def on_connect(client, userdata, flags, rc):
            if rc == 0:
                client.connected_flag = True
            else:
                _LOGGER.debug("MQTT connect failed rc=%s for %s", rc, self.tv_ip)
                client.cancel_loop = True

        def on_disconnect(client, userdata, rc):
            client.cancel_loop = True

        def on_response(mosq, obj, msg):
            try:
                result["data"] = msg.payload.decode("utf-8")
                _LOGGER.debug("MQTT response on %s: %s", msg.topic, result["data"])
            except Exception as e:
                _LOGGER.error("Error decoding MQTT response: %s", e)

        client = self._create_client()
        client.on_connect = on_connect
        client.on_disconnect = on_disconnect
        client.message_callback_add(subscribe_topic, on_response)

        try:
            client.connect_async(self.tv_ip, MQTT_PORT, 60)
            client.loop_start()

            if not self._wait(
                lambda: not client.connected_flag and not client.cancel_loop,
                timeout=CONNECT_TIMEOUT,
            ) or client.cancel_loop:
                _LOGGER.debug("Cannot connect to TV MQTT at %s", self.tv_ip)
                client.loop_stop()
                client.disconnect()
                return None

            client.subscribe(subscribe_topic, 0)
            client.publish(publish_topic, None)

            self._wait(
                lambda: result["data"] is None and not client.cancel_loop,
                timeout=QUERY_TIMEOUT,
            )

            client.loop_stop()
            client.disconnect()

            if result["data"]:
                return json.loads(result["data"])
            return None

        except Exception as e:
            _LOGGER.debug("Error in MQTT query: %s", e)
            try:
                client.loop_stop()
                client.disconnect()
            except Exception:
                pass
            return None

    def _send_command(self, publish_topic: str, payload: str | None = None) -> bool:
        """Generic MQTT command: connect → publish → disconnect."""
        def on_connect(client, userdata, flags, rc):
            if rc == 0:
                client.connected_flag = True
            else:
                client.cancel_loop = True

        def on_disconnect(client, userdata, rc):
            client.cancel_loop = True

        client = self._create_client()
        client.on_connect = on_connect
        client.on_disconnect = on_disconnect

        try:
            client.connect_async(self.tv_ip, MQTT_PORT, 60)
            client.loop_start()

            if not self._wait(
                lambda: not client.connected_flag and not client.cancel_loop,
                timeout=CONNECT_TIMEOUT,
            ) or client.cancel_loop:
                _LOGGER.debug("Cannot connect to TV MQTT at %s", self.tv_ip)
                client.loop_stop()
                client.disconnect()
                return False

            _LOGGER.debug("Publishing to %s: %s", publish_topic, payload)
            client.publish(publish_topic, payload)
            time.sleep(0.3)

            client.loop_stop()
            client.disconnect()
            return True

        except Exception as e:
            _LOGGER.error("Error sending MQTT command: %s", e)
            try:
                client.loop_stop()
                client.disconnect()
            except Exception:
                pass
            return False

    # ── state queries ────────────────────────────────────────

    def get_tv_state(self) -> dict | None:
        """Query TV state. Returns dict with 'statetype' etc, or None."""
        return self._query(
            subscribe_topic=self._topic_brcs + "ui_service/state",
            publish_topic=self._topic_tv_ui + "actions/gettvstate",
        )

    def get_source_list(self) -> list | None:
        """Query TV source list.

        Returns list of dicts like:
        [{"sourceid": "HDMI1", "sourcename": "HDMI1", "displayname": "HDMI1",
          "has_signal": "1", ...}, ...]
        or None on failure.
        """
        return self._query(
            subscribe_topic=self._topic_mobi + "ui_service/data/sourcelist",
            publish_topic=self._topic_tv_ui + "actions/sourcelist",
        )

    def get_app_list(self) -> list | None:
        """Query TV app list.

        Returns list of dicts like:
        [{"name": "Netflix", "appId": "6", "url": "...", ...}, ...]
        or None on failure.
        """
        return self._query(
            subscribe_topic=self._topic_mobi + "ui_service/data/applist",
            publish_topic=self._topic_tv_ui + "actions/applist",
        )

    def get_volume(self) -> dict | None:
        """Query TV volume.

        Returns dict like {"volume_type": 0, "volume_value": 18} or None.
        volume_type: 0 = not muted (normal), other values may indicate mute.
        volume_value: 0-100.
        """
        return self._query(
            subscribe_topic=self._topic_brcs + "platform_service/actions/volumechange",
            publish_topic=self._topic_tv_ps + "actions/getvolume",
        )

    def is_tv_on(self) -> bool:
        """Check if TV is on (MQTT reachable and not fake_sleep)."""
        state = self.get_tv_state()
        if state is None:
            _LOGGER.debug("TV %s: no MQTT response → OFF", self.tv_ip)
            return False
        statetype = state.get("statetype", "")
        if "fake_sleep" in statetype:
            _LOGGER.debug("TV %s: statetype=%s → OFF", self.tv_ip, statetype)
            return False
        _LOGGER.debug("TV %s: statetype=%s → ON", self.tv_ip, statetype)
        return True

    # ── commands ─────────────────────────────────────────────

    def send_key(self, key: str) -> bool:
        """Send a remote key to the TV."""
        return self._send_command(
            self._topic_remo + "actions/sendkey", key
        )

    def power_on(self) -> bool:
        """Send KEY_POWER to wake the TV (if MQTT reachable in standby)."""
        _LOGGER.info("Sending power on to %s via MQTT", self.tv_ip)
        return self.send_key("KEY_POWER")

    def power_off(self) -> bool:
        """Send KEY_POWER to turn off the TV."""
        _LOGGER.info("Sending power off to %s", self.tv_ip)
        return self.send_key("KEY_POWER")

    def change_volume(self, volume: int) -> bool:
        """Set TV volume (0-100)."""
        _LOGGER.info("Setting volume to %d on %s", volume, self.tv_ip)
        return self._send_command(
            self._topic_tv_ps + "actions/changevolume",
            str(volume),
        )

    def mute_toggle(self) -> bool:
        """Toggle mute on the TV."""
        _LOGGER.info("Toggling mute on %s", self.tv_ip)
        return self.send_key("KEY_MUTE")

    def change_source(self, source_id: str) -> bool:
        """Change TV input source by sourceid."""
        _LOGGER.info("Changing source to %s on %s", source_id, self.tv_ip)
        return self._send_command(
            self._topic_tv_ui + "actions/changesource",
            json.dumps({"sourceid": source_id}),
        )

    def launch_app(self, app_name: str, app_id: str, app_url: str) -> bool:
        """Launch an app on the TV."""
        _LOGGER.info("Launching app %s on %s", app_name, self.tv_ip)
        return self._send_command(
            self._topic_tv_ui + "actions/launchapp",
            json.dumps({"appId": app_id, "name": app_name, "url": app_url}),
        )

    # ── token management ─────────────────────────────────────

    def token_expires_soon(self, threshold_sec: int = 3600) -> bool:
        """Check if any token expires within threshold_sec (default 1 hour).

        Returns True if access OR refresh token expires soon.
        """
        now = time.time()

        access_expires = int(self._accesstoken_time) + (int(self._accesstoken_duration_day) * 86400)
        refresh_expires = int(self._refreshtoken_time) + (int(self._refreshtoken_duration_day) * 86400)

        access_remaining = access_expires - now
        refresh_remaining = refresh_expires - now

        _LOGGER.debug(
            "Token check: access expires in %.0fs, refresh expires in %.0fs, threshold=%ds",
            access_remaining, refresh_remaining, threshold_sec,
        )

        return access_remaining < threshold_sec or refresh_remaining < threshold_sec

    def refresh_tokens(self) -> dict | None:
        """Refresh tokens via MQTT using the current refreshtoken.

        Connects with refreshtoken as password, requests new tokens.
        Returns new credentials dict on success, None on failure.
        """
        _LOGGER.info("Refreshing tokens for %s...", self.tv_ip)

        result: dict[str, Any] = {"data": None}

        def on_connect(client, userdata, flags, rc):
            if rc == 0:
                client.connected_flag = True
                _LOGGER.debug("MQTT connected for token refresh")
            else:
                _LOGGER.error("MQTT connect failed for token refresh, rc=%s", rc)
                client.cancel_loop = True

        def on_disconnect(client, userdata, rc):
            client.cancel_loop = True

        def on_token(mosq, obj, msg):
            try:
                result["data"] = msg.payload.decode("utf-8")
                _LOGGER.debug("Token response: %s", result["data"])
            except Exception as e:
                _LOGGER.error("Error decoding token response: %s", e)

        # Connect with refreshtoken as password
        client = self._create_client(password=self._refreshtoken)
        client.on_connect = on_connect
        client.on_disconnect = on_disconnect

        subscribe_topic = self._topic_mobi + "platform_service/data/tokenissuance"
        client.message_callback_add(subscribe_topic, on_token)

        try:
            client.connect_async(self.tv_ip, MQTT_PORT, 60)
            client.loop_start()

            if not self._wait(
                lambda: not client.connected_flag and not client.cancel_loop,
                timeout=CONNECT_TIMEOUT,
            ) or client.cancel_loop:
                _LOGGER.error("Cannot connect to TV for token refresh")
                client.loop_stop()
                client.disconnect()
                return None

            client.subscribe(subscribe_topic, 0)
            client.publish(
                self._topic_tv_ps + "data/gettoken",
                json.dumps({"refreshtoken": self._refreshtoken}),
            )

            self._wait(
                lambda: result["data"] is None and not client.cancel_loop,
                timeout=QUERY_TIMEOUT,
            )

            client.loop_stop()
            client.disconnect()

            if not result["data"]:
                _LOGGER.error("No token response from TV")
                return None

            new_creds = json.loads(result["data"])
            new_creds.update({
                "client_id": self._client_id,
                "mqtt_username": self._username,
                "mqtt_password": self._password,
            })

            # Update internal state
            self._accesstoken = new_creds["accesstoken"]
            self._refreshtoken = new_creds["refreshtoken"]
            self._accesstoken_time = new_creds["accesstoken_time"]
            self._accesstoken_duration_day = new_creds["accesstoken_duration_day"]
            self._refreshtoken_time = new_creds["refreshtoken_time"]
            self._refreshtoken_duration_day = new_creds["refreshtoken_duration_day"]

            _LOGGER.info("Tokens refreshed successfully for %s", self.tv_ip)
            return new_creds

        except Exception as e:
            _LOGGER.error("Error refreshing tokens: %s", e)
            try:
                client.loop_stop()
                client.disconnect()
            except Exception:
                pass
            return None
