# @prasad-edlabadkar/homebridge-atomberg-lock

High-speed Homebridge plugin for the **Atomberg SL1 Pro Bluetooth Smart Lock** (fully compatible with **Homebridge 2.0** and **Homebridge 1.x**).

Exposes the smart lock to Apple HomeKit as a native **Lock Mechanism** and **Battery Service** with sub-second execution.

---

## Features

- **⚡ Sub-Second Speed**: Precomputed CRC tables, zero-delay GATT writes, and built-in background micro-daemon.
- **Self-Contained**: The BLE Python communication scripts are bundled inside this plugin—no external setup required.
- **Apple HomeKit Integration**: Lock/Unlock through Apple Home app, Siri, and HomeKit Automations.
- **Hardware Auto-Relock Emulation**: Upon unlocking, transitions state to `UNSECURED`, then automatically returns to `SECURED` after 5 seconds to match the lock's physical clutch.
- **Battery Reporting**: Displays real-time battery percentage in Apple Home.
- **Homebridge 2.0 Ready**: Built with the modern Promise-based Homebridge 2.0 / HAP-NodeJS API.

---

## Installation on Raspberry Pi

### 1. Install Plugin
```bash
sudo npm install -g @prasad-edlabadkar/homebridge-atomberg-lock
```
*(Or install directly from GitHub: `sudo npm install -g git+https://github.com/prasad-edlabadka/homebridge-atomberg-lock.git`)*

### 2. Configure in Homebridge
In your Homebridge Web UI **Config** tab (or `/var/lib/homebridge/config.json`), add under `"accessories": [ ... ]`:

```json
{
  "accessory": "AtombergLock",
  "name": "Front Door Lock",
  "mac": "6A:35:42:3A:5B:5C",
  "masterKey": "EPib52e5HgJWd6fq",
  "salt": "5c8f9da9",
  "adapter": "hci0",
  "autoLockDelay": 5,
  "enableBattery": true
}
```

---

## 🚀 Ultra-Speed Mode: Background Daemon (Optional, < 1s Unlocks)

To eliminate all Python startup and DBus connection overhead for **near-instant unlocks**:

1. Enable the background micro-daemon systemd service:
   ```bash
   sudo cp /var/lib/homebridge/node_modules/@prasad-edlabadkar/homebridge-atomberg-lock/atomberg-daemon.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now atomberg-daemon
   ```
2. Check status:
   ```bash
   sudo systemctl status atomberg-daemon
   ```

When the daemon is running, HomeKit unlocks trigger directly via local HTTP in **< 1 second**!
*(If the daemon is not running, the plugin automatically falls back to optimized CLI execution).*

---

## Permissions
Ensure `homebridge` has access to Bluetooth:
```bash
sudo usermod -aG bluetooth homebridge
```
