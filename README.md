# @prasad-edlabadkar/homebridge-atomberg-lock

Homebridge plugin for the **Atomberg SL1 Pro Bluetooth Smart Lock** (fully compatible with **Homebridge 2.0** and **Homebridge 1.x**).

Exposes the smart lock to Apple HomeKit as a native **Lock Mechanism** and **Battery Service**.

---

## Features

- **Self-Contained**: The BLE Python communication scripts are bundled inside this plugin—no manual script copying required.
- **Apple HomeKit Integration**: Lock/Unlock through Apple Home app, Siri, and HomeKit Automations.
- **Hardware Auto-Relock Emulation**: Upon unlocking, transitions state to `UNSECURED`, then automatically returns to `SECURED` after 5 seconds to match the lock's physical clutch.
- **Battery Reporting**: Displays real-time battery percentage in Apple Home.
- **Homebridge 2.0 Ready**: Built with the modern Promise-based Homebridge 2.0 / HAP-NodeJS API.

---

## Prerequisites (on Raspberry Pi)

Make sure Python dependencies are installed in your virtual environment:
```bash
source /home/homebridge/venv/bin/activate
pip install bleak pycryptodome
```

---

## Installation

### Method A: Install from Local Directory
```bash
cd /home/homebridge/homebridge-atomberg-lock
sudo npm install -g .
```

---

## Configuration

### Option 1: Via Homebridge Web UI
1. Go to your **Homebridge UI** $\rightarrow$ **Plugins** tab.
2. Click **Settings** on **AtombergLock**.
3. Fill in your lock credentials:
   - **Lock MAC Address**: `AA:BB:CC:11:22:33`
   - **Static Master Key**: `AbCdEfGhIjKlMnOp`
   - **Lock Salt**: `1a2b3c4d`
4. Save and Restart Homebridge.

---

### Option 2: Via `config.json`
Add the accessory directly to your `/var/lib/homebridge/config.json` under `"accessories": [ ... ]`:

```json
{
  "accessory": "AtombergLock",
  "name": "Front Door Lock",
  "mac": "AA:BB:CC:11:22:33",
  "masterKey": "AbCdEfGhIjKlMnOp",
  "salt": "1a2b3c4d",
  "adapter": "hci0",
  "autoLockDelay": 5,
  "enableBattery": true
}
```
*(Or point to `"configPath": "/home/homebridge/config.json"` if you prefer using a file).*

---

## Permissions Note
Ensure the user running Homebridge (usually `homebridge`) has access to Bluetooth:
```bash
sudo usermod -aG bluetooth homebridge
```
