"""Hisense TV MQTT authentication module.

Handles the MQTT handshake with the TV to obtain access/refresh tokens.
PIN code is used during generate_creds() to complete the authentication.
Credentials are returned as a dict (not saved to file).
"""
import hashlib
import json
import logging
import os
import random
import re
import ssl
import time
import uuid

import paho.mqtt.client as mqtt

_LOGGER = logging.getLogger(__name__)

# Certificate files bundled with the integration
_DIR = os.path.dirname(os.path.abspath(__file__))
CERTFILE = os.path.join(_DIR, "rcm_certchain_pem.cer")
KEYFILE = os.path.join(_DIR, "rcm_pem_privkey.pkcs8")

MQTT_PORT = 36669


class AuthSession:
    """One-shot MQTT authentication session with Hisense TV.

    Usage:
        session = AuthSession(tv_ip, mac_address)
        # Step 1: connect and wait for TV to show PIN
        session.start()
        # Step 2: send PIN entered by user, get credentials back
        credentials = session.send_pin(pin_code)
        # credentials is a dict with accesstoken, refreshtoken, etc.
    """

    def __init__(self, tv_ip: str, mac_address: str | None = None):
        self.tv_ip = tv_ip
        self.mac_address = mac_address

        # MQTT state
        self._client: mqtt.Client | None = None
        self._connected = False
        self._cancel = False

        # Authentication payloads
        self._authentication_payload = None
        self._authentication_code_payload = None
        self._tokenissuance = None

        # Generated credentials
        self.client_id: str | None = None
        self.username: str | None = None
        self.password: str | None = None
        self.timestamp: int | None = None

        # Topic paths
        self._topic_tv_ui: str | None = None
        self._topic_tv_ps: str | None = None
        self._topic_mobi: str | None = None
        self._topic_brcs: str | None = None
        self._topic_remo: str | None = None

    # ── helpers ──────────────────────────────────────────────

    @staticmethod
    def _cross_sum(n: int) -> int:
        return sum(int(d) for d in str(n))

    @staticmethod
    def _md5(s: str) -> str:
        return hashlib.md5(s.encode("utf-8")).hexdigest().upper()

    # ── MQTT callbacks ───────────────────────────────────────

    def _on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            self._connected = True
            _LOGGER.debug("MQTT connected to %s", self.tv_ip)
        else:
            _LOGGER.error("MQTT connect failed, rc=%s", rc)
            self._cancel = True

    def _on_disconnect(self, client, userdata, rc):
        _LOGGER.debug("MQTT disconnected, rc=%s", rc)
        self._cancel = True

    def _on_message(self, client, userdata, msg):
        _LOGGER.debug("MQTT msg: %s  topic: %s", msg.payload.decode("utf-8", errors="replace"), msg.topic)

    def _on_authentication(self, mosq, obj, msg):
        _LOGGER.debug("Auth payload: %s", msg.payload.decode("utf-8", errors="replace"))
        self._authentication_payload = msg

    def _on_authentication_code(self, mosq, obj, msg):
        _LOGGER.debug("Auth code payload: %s", msg.payload.decode("utf-8", errors="replace"))
        self._authentication_code_payload = msg

    def _on_tokenissuance(self, mosq, obj, msg):
        _LOGGER.debug("Token payload: %s", msg.payload.decode("utf-8", errors="replace"))
        self._tokenissuance = msg

    # ── wait helper ──────────────────────────────────────────

    def _wait(self, condition, timeout: int = 30):
        """Block until condition() is False or timeout."""
        start = time.time()
        while condition():
            if self._cancel:
                raise ConnectionError("MQTT connection lost")
            if time.time() - start > timeout:
                raise TimeoutError(f"Timeout ({timeout}s) waiting for TV response")
            time.sleep(0.2)

    # ── hashes & topics ─────────────────────────────────────

    def _define_hashes(self):
        self.timestamp = int(time.time())

        if self.mac_address:
            mac = self.mac_address.upper()
        else:
            mac = ':'.join(re.findall('..', '%012x' % uuid.getnode())).upper()

        _LOGGER.debug("Using MAC: %s", mac)

        first_hash = self._md5("&vidaa#^app")
        second_hash = self._md5(f"38D65DC30F45109A369A86FCE866A85B${mac}")
        last_digit = self._cross_sum(self.timestamp) % 10
        third_hash = self._md5(f"his{last_digit}h!i@s#$v%i^d&a*a")
        fourth_hash = self._md5(f"{self.timestamp}${third_hash[:6]}")

        self.username = f"his${self.timestamp ^ 6239759785777146216}"
        self.password = fourth_hash
        self.client_id = f"{mac}$his${second_hash[:6]}_vidaacommon_001"

        _LOGGER.debug("client_id=%s  username=%s", self.client_id, self.username)

    def _define_topics(self):
        cid = self.client_id
        self._topic_tv_ui = f"/remoteapp/tv/ui_service/{cid}/"
        self._topic_tv_ps = f"/remoteapp/tv/platform_service/{cid}/"
        self._topic_mobi = f"/remoteapp/mobile/{cid}/"
        self._topic_brcs = "/remoteapp/mobile/broadcast/"
        self._topic_remo = f"/remoteapp/tv/remote_service/{cid}/"

    # ── MQTT client ──────────────────────────────────────────

    def _create_client(self, password: str) -> mqtt.Client:
        client = mqtt.Client(
            client_id=self.client_id,
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
        client.username_pw_set(username=self.username, password=password)

        client.on_connect = self._on_connect
        client.on_message = self._on_message
        client.on_disconnect = self._on_disconnect

        return client

    # ── public API ───────────────────────────────────────────

    def start(self) -> None:
        """Connect to TV and trigger the PIN dialog on screen.

        Blocks until the TV sends the authentication payload
        (i.e. the PIN window appears on screen).
        Raises ConnectionError / TimeoutError on failure.
        """
        self._define_hashes()
        self._define_topics()

        self._connected = False
        self._cancel = False
        self._authentication_payload = None
        self._authentication_code_payload = None
        self._tokenissuance = None

        client = self._create_client(password=self.password)

        # Register topic-specific callbacks
        client.message_callback_add(
            self._topic_mobi + "ui_service/data/authentication",
            self._on_authentication,
        )
        client.message_callback_add(
            self._topic_mobi + "ui_service/data/authenticationcode",
            self._on_authentication_code,
        )
        client.message_callback_add(
            self._topic_mobi + "platform_service/data/tokenissuance",
            self._on_tokenissuance,
        )

        client.connect_async(self.tv_ip, MQTT_PORT, 60)
        client.loop_start()

        # Wait for connection
        self._wait(lambda: not self._connected, timeout=15)

        # Subscribe to all needed topics
        client.subscribe([
            (self._topic_brcs + "ui_service/state", 0),
            (self._topic_tv_ui + "actions/vidaa_app_connect", 0),
            (self._topic_mobi + "ui_service/data/authentication", 0),
            (self._topic_mobi + "ui_service/data/authenticationcode", 0),
            (self._topic_brcs + "ui_service/data/hotelmodechange", 0),
            (self._topic_mobi + "platform_service/data/tokenissuance", 0),
        ])

        # Trigger PIN dialog on TV
        _LOGGER.debug("Publishing vidaa_app_connect...")
        client.publish(
            self._topic_tv_ui + "actions/vidaa_app_connect",
            '{"app_version":2,"connect_result":0,"device_type":"Mobile App"}',
        )

        # Wait for authentication payload (TV shows PIN)
        self._wait(lambda: self._authentication_payload is None, timeout=30)

        if self._authentication_payload.payload.decode() != '""':
            self.stop()
            raise RuntimeError(
                f"Unexpected auth payload: {self._authentication_payload.payload.decode()}"
            )

        self._client = client
        _LOGGER.info("PIN dialog should now be visible on TV %s", self.tv_ip)

    def send_pin(self, pin_code: str) -> dict:
        """Send PIN code and obtain credentials.

        Returns dict with: accesstoken, refreshtoken, client_id, username, password, etc.
        Raises ConnectionError / TimeoutError / RuntimeError on failure.
        """
        if self._client is None:
            raise RuntimeError("Call start() first")

        client = self._client
        self._authentication_code_payload = None

        # Send PIN
        _LOGGER.debug("Sending PIN: %s", pin_code)
        client.publish(
            self._topic_tv_ui + "actions/authenticationcode",
            json.dumps({"authNum": int(pin_code)}),
        )

        # Wait for auth code response
        self._wait(lambda: self._authentication_code_payload is None, timeout=30)

        payload = json.loads(self._authentication_code_payload.payload.decode())
        if "result" not in payload or payload["result"] != 1:
            raise RuntimeError(
                f"PIN rejected by TV: {self._authentication_code_payload.payload.decode()}"
            )

        _LOGGER.info("PIN accepted! Requesting tokens...")

        # Request tokens
        self._tokenissuance = None
        client.publish(
            self._topic_tv_ps + "data/gettoken",
            '{"refreshtoken": ""}',
        )
        client.publish(
            self._topic_tv_ui + "actions/authenticationcodeclose",
        )

        # Wait for token
        self._wait(lambda: self._tokenissuance is None, timeout=30)

        credentials = json.loads(self._tokenissuance.payload.decode())
        credentials.update({
            "client_id": self.client_id,
            "username": self.username,
            "password": self.password,
        })

        self.stop()

        _LOGGER.info("Authentication complete! Tokens received.")
        return credentials

    def stop(self):
        """Disconnect MQTT client."""
        if self._client:
            try:
                self._client.loop_stop()
                self._client.disconnect()
            except Exception:
                pass
            self._client = None
