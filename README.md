# Hisense TV Integration for Home Assistant

Integration for controlling Hisense TVs via MQTT protocol. Supports real connection to physical TVs with full control capabilities.

## Features

- TV power control (on/off via Wake-on-LAN + MQTT)
- Volume control with mute/unmute
- Input source selection (HDMI1, HDMI2, HDMI3, AV, TV)
- App launching (Netflix, YouTube, Amazon Prime, Disney+, Browser)
- TV state monitoring
- MQTT authentication and automatic token refresh

## Installation

### Step 1: Copy the integration files

Extract the `hisense_tv` archive into the `custom_components` directory of your Home Assistant configuration folder. The typical path is:

```
<HA_CONFIG_DIR>/custom_components/hisense_tv/
```

For example, if Home Assistant config is at `/mnt/dietpi_userdata/homeassistant/`:

```bash
# Create the directory if it doesn't exist
mkdir -p /mnt/dietpi_userdata/homeassistant/custom_components/hisense_tv

# Extract the archive
unzip hisense_tv.zip -d /mnt/dietpi_userdata/homeassistant/custom_components/hisense_tv/
```

After extraction, the directory structure should look like this:

```
custom_components/
└── hisense_tv/
    ├── __init__.py
    ├── auth.py
    ├── config_flow.py
    ├── const.py
    ├── HISense.py
    ├── manifest.json
    ├── media_player.py
    ├── tv_connector.py
    ├── strings.json
    ├── rcm_certchain_pem.cer   ← TLS certificate (required)
    ├── rcm_pem_privkey.pkcs8   ← TLS private key (required)
    └── README.md
```

> **Important:** The certificate files `rcm_certchain_pem.cer` and `rcm_pem_privkey.pkcs8` must be present in the same directory as the integration. They are required for MQTT/TLS communication with the TV.

### Step 2: Install dependencies

The integration requires the `paho-mqtt` Python package. Install it in the Home Assistant Python environment:

```bash
pip install paho-mqtt>=1.6.1
```

### Step 3: Restart Home Assistant

Restart Home Assistant to load the new integration:

```bash
ha core restart
```

Or restart the Home Assistant process manually if running in a custom environment.

### Step 4: Add the integration via UI

1. Open Home Assistant in a browser (`http://localhost:8123`)
2. Go to **"Settings" → "Devices & Services"**
3. Click **"+ ADD INTEGRATION"**
4. Find **"Hisense TV"** and click add
5. Follow the setup instructions:
   - **Step 1**: Enter the TV IP address
   - **Step 2**: Enter the 4-digit PIN code displayed on the TV screen

## Configuration

### Requirements

- Hisense TV with MQTT API support (Vidaa OS)
- TV must support Wake-on-LAN (WOL)
- TV and Home Assistant on the same local network

### Configuration Parameters

- **TV IP address**: IP address of your Hisense TV on the local network
- **MAC address**: Detected automatically from the ARP table
- **PIN code**: 4-digit authentication code displayed on the TV screen

## Usage

After setting up the integration, a media player entity will appear in Home Assistant:

- Control via Home Assistant UI
- Use in automations
- Voice control via assistants
- Dashboard integration

### Available Commands

- `turn_on` - turn on the TV (sends Wake-on-LAN packet, then MQTT)
- `turn_off` - turn off the TV (via MQTT)
- `volume_up` / `volume_down` - increase/decrease volume
- `volume_set` - set volume level (0-100)
- `volume_mute` - toggle mute
- `select_source` - select input source or launch app

## Troubleshooting

### Connection Issues
1. Make sure the TV is on and connected to the network
2. Verify the IP address is correct
3. Make sure the PIN code was entered correctly

### Logs
Check Home Assistant logs:
**Settings → System → Logs** (search for "hisense_tv")

## Compatibility

- Home Assistant 2024+
- Hisense TVs with Vidaa OS
- MQTT protocol on port 36669

## Credits

The MQTT communication and authentication logic is based on [nikagl/hisense](https://github.com/nikagl/hisense) by [@nikagl](https://github.com/nikagl), which implements token-based authentication for Hisense TVs with Vidaa OS.

The TLS certificate files (`rcm_certchain_pem.cer` and `rcm_pem_privkey.pkcs8`) required for MQTT communication are sourced from [d3nd3/Hisense-mqtt-keyfiles](https://github.com/d3nd3/Hisense-mqtt-keyfiles).
