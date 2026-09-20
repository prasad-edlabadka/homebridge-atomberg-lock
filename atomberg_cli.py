#!/usr/bin/env python3
"""
Atomberg SL1 Pro Smart Lock - Standalone BLE Controller
======================================================
Standalone Python script to lock/unlock, query battery, and fetch audit logs
for the Atomberg Smart Lock over Bluetooth Low Energy (BLE).
Optimized for Raspberry Pi (including 3B+ 64-bit OS) and Linux/macOS.

Requirements:
    pip install bleak pycryptodome
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
except ImportError:
    print(
        "[ERROR] 'pycryptodome' is required. Install it using:\n"
        "    pip install pycryptodome",
        file=sys.stderr,
    )
    sys.exit(1)

try:
    from bleak import BleakClient, BleakScanner
except ImportError:
    print(
        "[ERROR] 'bleak' is required. Install it using:\n"
        "    pip install bleak",
        file=sys.stderr,
    )
    sys.exit(1)

# BLE UUIDs
WRITE_UUID = "0000fff1-0000-1000-8000-00805f9b34fb"
NOTIFY_UUID = "0000fff2-0000-1000-8000-00805f9b34fb"

# Protocol timeouts
CONNECT_TIMEOUT = 15.0
COMMAND_TIMEOUT = 6.0
DEFAULT_RETRIES = 3

logger = logging.getLogger("atomberg")


# ==============================================================================
# Cryptographic & Frame Helpers
# ==============================================================================


def encrypt_ecb(key: bytes, data: bytes) -> bytes:
    """Encrypt payload using AES-128-ECB with PKCS#7 padding."""
    return AES.new(key, AES.MODE_ECB).encrypt(pad(data, 16))


def decrypt_ecb(key: bytes, data: bytes) -> bytes:
    """Decrypt payload using AES-128-ECB and unpad PKCS#7."""
    dec = AES.new(key, AES.MODE_ECB).decrypt(data)
    try:
        return unpad(dec, 16)
    except ValueError:
        return dec


def crc16_modbus_be(data: bytes) -> bytes:
    """Compute CRC-16 Modbus checksum in Big-Endian format."""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc.to_bytes(2, "big")


def format_timestamp_ist(ts: int) -> str:
    """Format unix timestamp to human-readable IST time string."""
    try:
        from zoneinfo import ZoneInfo

        return (
            datetime.fromtimestamp(ts, timezone.utc)
            .astimezone(ZoneInfo("Asia/Kolkata"))
            .strftime("%Y-%m-%d %I:%M:%S %p IST")
        )
    except Exception:
        # Fallback to local time if zoneinfo / timezone is unavailable
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def parse_log_record(rec: bytes, slot_mappings: Optional[Dict[int, str]] = None) -> Dict[str, Any]:
    """Parse a 32-byte hardware log record into human-readable dictionary."""
    if len(rec) != 32:
        raise ValueError(f"Expected 32-byte record, got {len(rec)}")

    mappings = slot_mappings or {}
    ts = int.from_bytes(rec[0:4], "big")
    event_cat = rec[4]
    battery = rec[5]
    user_id = int.from_bytes(rec[7:9], "big")
    cred_type = rec[9]
    slot_id = int.from_bytes(rec[10:12], "big")

    event = "Hardware Event"
    cred_type_name = ""
    detail = ""
    pin_str = ""
    slot = slot_id

    def get_slot_label(s: int) -> str:
        return mappings.get(s, f"Slot {s}")

    if event_cat == 0x36:
        event = "Denied / Failed Attempt"
        if cred_type == 0x01:
            cred_type_name = "Unregistered Fingerprint"
            detail = "Unregistered Fingerprint"
        elif cred_type == 0x02:
            cred_type_name = "Wrong Keypad PIN"
            pin_len = rec[26] if len(rec) > 26 else 0
            if 0 < pin_len <= 12 and len(rec) >= (27 + pin_len):
                pin_str = rec[27 : 27 + pin_len].decode("latin1", errors="ignore")
            detail = f"Wrong Keypad PIN: {pin_str}" if pin_str else "Wrong Keypad PIN"
        elif cred_type == 0x04:
            cred_type_name = "Unregistered NFC Card"
            detail = "Unregistered NFC Card"
        else:
            cred_type_name = f"Rejected Credential (0x{cred_type:02x})"
            detail = f"Rejected Credential Type 0x{cred_type:02x}"

    elif event_cat == 0x04:
        event = "Unlocked Successfully"
        if b"MX" in rec[18:]:
            cred_type_name = "Atomberg App"
            detail = "Atomberg Mobile App (BLE)"
        elif cred_type == 0x01:
            cred_type_name = "Fingerprint"
            detail = f"Fingerprint: {get_slot_label(slot)}"
        elif cred_type == 0x04:
            cred_type_name = "NFC Card"
            card_uid = rec[18:22].hex()
            detail = f"NFC Card: {get_slot_label(slot)} (UID {card_uid})"
        elif cred_type == 0x02:
            cred_type_name = "PIN Code"
            code_str = rec[18:24].decode("latin1", errors="ignore").rstrip("\x00")
            pin_str = code_str
            detail = f"PIN Code: {code_str} (User {user_id})" if code_str else f"PIN Code (User {user_id})"
        elif cred_type == 0x00 or slot == 0:
            cred_type_name = "Atomberg App"
            detail = "Atomberg Mobile App (BLE)"
        else:
            cred_type_name = f"Credential Type 0x{cred_type:02x}"
            detail = f"Unlocked by {get_slot_label(slot)}"

    elif event_cat == 0x37:
        event = "Unlocked (Manual)"
        cred_type_name = "Physical Thumbturn"
        detail = "Physical Thumbturn"
        slot = 0

    elif event_cat == 0x08:
        event = "Credential Enrolled"
        cred_type_name = "Credential Enrollment"
        slot = int.from_bytes(rec[11:13], "big")
        detail = f"Enrolled: {get_slot_label(slot)}"

    else:
        event = f"Event 0x{event_cat:02x}"
        detail = f"Hardware Event Code 0x{event_cat:02x}"

    return {
        "timestamp": ts,
        "datetime": format_timestamp_ist(ts),
        "event": event,
        "detail": detail,
        "battery": battery,
        "credential_type": cred_type_name,
        "slot": slot,
        **({"pin": pin_str} if pin_str else {}),
    }


# ==============================================================================
# Atomberg BLE Lock Client Class
# ==============================================================================


class AtombergLockClient:
    """Client for connecting to and controlling an Atomberg Smart Lock over BLE."""

    def __init__(
        self,
        mac_address: str,
        master_key: bytes | str,
        lock_salt: bytes | str,
        adapter: Optional[str] = None,
    ):
        self.mac_address = mac_address.strip().upper()

        # Parse master key: 16 ASCII characters or 32 hex digits
        if isinstance(master_key, str):
            key_clean = master_key.strip()
            if len(key_clean) == 32:
                try:
                    self.master_key = bytes.fromhex(key_clean)
                except ValueError:
                    self.master_key = key_clean.encode("utf-8")
            else:
                self.master_key = key_clean.encode("utf-8")
        else:
            self.master_key = master_key

        if len(self.master_key) != 16:
            raise ValueError(
                f"Master key must be 16 bytes (got {len(self.master_key)} bytes). "
                "Provide a 16-character ASCII string or 32-character hex."
            )

        # Parse lock salt: 4 bytes (8 hex characters)
        if isinstance(lock_salt, str):
            salt_clean = lock_salt.strip().replace(" ", "").replace("0x", "")
            self.lock_salt = bytes.fromhex(salt_clean)
        else:
            self.lock_salt = lock_salt

        if len(self.lock_salt) != 4:
            raise ValueError(
                f"Lock salt must be 4 bytes (got {len(self.lock_salt)} bytes). "
                "Provide an 8-character hex string (e.g. '1a2b3c4d')."
            )

        self.adapter = adapter
        self.client: Optional[BleakClient] = None
        self.session_token: Optional[bytes] = None
        self.session_key: Optional[bytes] = None
        self.seq_counter: int = 5
        self.recv_queue: asyncio.Queue = asyncio.Queue()
        self.rx_buffer: bytearray = bytearray()
        self.expected_len: int = 0

    def _clear_buffers(self) -> None:
        self.rx_buffer.clear()
        self.expected_len = 0
        while not self.recv_queue.empty():
            try:
                self.recv_queue.get_nowait()
            except asyncio.QueueEmpty:
                break

    def _notification_handler(self, sender: Any, data: bytearray) -> None:
        raw = bytes(data)
        logger.debug(f"[RX CHUNK] ({len(raw)} bytes): {raw.hex(' ')}")

        if raw.startswith(b"HSJ") and len(raw) >= 5:
            self.expected_len = int.from_bytes(raw[3:5], byteorder="big")
            self.rx_buffer = bytearray(raw)
        else:
            self.rx_buffer.extend(raw)

        if self.expected_len > 0 and len(self.rx_buffer) >= self.expected_len:
            full_frame = bytes(self.rx_buffer[: self.expected_len])
            logger.debug(f"[RX FRAME COMPLETE] ({len(full_frame)} bytes): {full_frame.hex(' ')}")
            encrypted_payload = full_frame[7 : self.expected_len - 2]
            self.recv_queue.put_nowait(encrypted_payload)
            self.rx_buffer = bytearray(self.rx_buffer[self.expected_len :])
            self.expected_len = 0

    async def _send_command(self, payload: bytes, key: bytes, frame_seq: int) -> None:
        encrypted = encrypt_ecb(key, payload)
        total_len = 3 + 2 + 2 + len(encrypted) + 2

        header = (
            b"HSJ"
            + total_len.to_bytes(2, byteorder="big")
            + frame_seq.to_bytes(2, byteorder="big")
        )
        body = header + encrypted
        packet = body + crc16_modbus_be(body)

        logger.debug(f"[TX PACKET] ({len(packet)} bytes): {packet.hex(' ')}")

        for i in range(0, len(packet), 20):
            chunk = packet[i : i + 20]
            if not self.client or not self.client.is_connected:
                raise ConnectionError("Bluetooth client is disconnected during write.")
            await self.client.write_gatt_char(WRITE_UUID, chunk, response=False)
            await asyncio.sleep(0.03)

    async def _execute_step(
        self,
        payload: bytes,
        key: bytes,
        frame_seq: int,
        expected_op: Optional[bytes] = None,
        timeout: float = COMMAND_TIMEOUT,
    ) -> bytes:
        await self._send_command(payload, key, frame_seq)
        start_t = time.time()

        while (time.time() - start_t) < timeout:
            remaining = timeout - (time.time() - start_t)
            try:
                cipher_resp = await asyncio.wait_for(
                    self.recv_queue.get(), timeout=max(remaining, 0.1)
                )
            except asyncio.TimeoutError:
                break

            dec = decrypt_ecb(key, cipher_resp)
            logger.debug(f"[DECRYPTED RESP] ({len(dec)} bytes): {dec.hex(' ')}")

            if expected_op is not None and len(dec) >= 8:
                if dec[5:7] == expected_op:
                    return dec
                continue
            return dec

        op_name = expected_op.hex() if expected_op else "any"
        raise TimeoutError(f"Timed out waiting for response opcode 0x{op_name}")

    async def connect(self, retries: int = DEFAULT_RETRIES) -> None:
        """Connect to the BLE lock and register notifications with retry support."""
        last_err: Optional[Exception] = None

        client_kwargs: Dict[str, Any] = {"timeout": CONNECT_TIMEOUT}
        scanner_kwargs: Dict[str, Any] = {}

        if self.adapter:
            if sys.platform.startswith("linux"):
                client_kwargs["bluez"] = {"adapter": self.adapter}
                scanner_kwargs["bluez"] = {"adapter": self.adapter}
            else:
                client_kwargs["adapter"] = self.adapter
                scanner_kwargs["adapter"] = self.adapter

        for attempt in range(1, retries + 1):
            try:
                logger.info(
                    f"Connecting to lock {self.mac_address} (Attempt {attempt}/{retries})..."
                )

                # Attempt direct connection first (avoids active scanning collision on Broadcom/RPI chips)
                target = self.mac_address

                if attempt > 1:
                    # On retry, try finding BLEDevice object in case address type needs refreshing
                    logger.debug(f"Locating device {self.mac_address} via BLE scanner...")
                    try:
                        dev = await BleakScanner.find_device_by_address(
                            self.mac_address, timeout=4.0, **scanner_kwargs
                        )
                        if dev is not None:
                            target = dev
                            logger.debug(f"Device found in range (RSSI: {getattr(dev, 'rssi', 'N/A')} dBm)")
                            # Allow adapter to settle after stopping discovery
                            await asyncio.sleep(0.5)
                    except Exception as scan_err:
                        logger.debug(f"Scanner lookup error: {scan_err}")

                self.client = BleakClient(target, **client_kwargs)
                await self.client.connect()

                if not self.client.is_connected:
                    raise ConnectionError(f"Could not connect to {self.mac_address}")

                self._clear_buffers()
                await self.client.start_notify(NOTIFY_UUID, self._notification_handler)
                await asyncio.sleep(0.5)
                logger.info("Connected to lock successfully.")
                return
            except Exception as err:
                last_err = err
                err_msg = str(err) if str(err) else type(err).__name__
                logger.warning(f"Connection attempt {attempt} failed: {err_msg}")
                await self.disconnect()
                if attempt < retries:
                    await asyncio.sleep(2.0)

        raise ConnectionError(
            f"Failed to connect to Atomberg Lock ({self.mac_address}) after {retries} attempts: {last_err or 'Timeout'}"
        )

    async def disconnect(self) -> None:
        """Disconnect and clean up resources."""
        if self.client:
            try:
                if self.client.is_connected:
                    await self.client.stop_notify(NOTIFY_UUID)
            except Exception:
                pass
            try:
                await self.client.disconnect()
            except Exception:
                pass
        self.client = None
        self._clear_buffers()

    async def authenticate(self) -> None:
        """Perform 3-way session authentication and exchange session key."""
        logger.info("Authenticating with lock...")

        # 1. Handshake 0x00F0
        logger.debug("Sending Handshake (0x00F0)...")
        probe_cmd = bytes.fromhex("000000000200f000000000000c")
        resp_f0 = await self._execute_step(
            probe_cmd,
            self.master_key,
            frame_seq=2,
            expected_op=bytes.fromhex("00f0"),
        )
        self.session_token = resp_f0[:4]
        logger.debug(f"Session Token: {self.session_token.hex()}")

        # 2. Key Exchange 0x00F1
        logger.debug("Requesting Session Key (0x00F1)...")
        key_req = self.session_token + bytes.fromhex("0300f100000000000c")
        resp_f1 = await self._execute_step(
            key_req,
            self.master_key,
            frame_seq=2,
            expected_op=bytes.fromhex("00f1"),
        )
        if len(resp_f1) < 29:
            raise RuntimeError(f"Invalid session key response length: {len(resp_f1)}")
        self.session_key = resp_f1[13:29]
        logger.debug(f"Session Key: {self.session_key.hex()}")

        # 3. Context Synchronization 0x00F2 with dynamic Lock Salt
        logger.debug("Synchronizing Context (0x00F2)...")
        sync_cmd = (
            self.session_token
            + bytes.fromhex("0400f2000003e9000c")
            + self.lock_salt
        )
        await self._execute_step(
            sync_cmd,
            self.session_key,
            frame_seq=3,
            expected_op=bytes.fromhex("00f2"),
        )
        self.seq_counter = 5
        logger.info("Authentication successful.")

    async def unlock(self) -> int:
        """
        Calibrate time and trigger momentary unlock.
        Returns the unix timestamp of the unlock action.
        """
        if not self.session_token or not self.session_key:
            raise RuntimeError("Must authenticate before calling unlock")

        now_int = int(time.time())
        ts = now_int.to_bytes(4, byteorder="big")

        logger.info("Calibrating lock time (0x0007)...")
        time_cmd = (
            self.session_token
            + bytes.fromhex("010007000003e9000c")
            + ts
            + bytes.fromhex("004d58")
        )
        await self._execute_step(
            time_cmd,
            self.session_key,
            frame_seq=3,
            expected_op=bytes.fromhex("0007"),
        )

        logger.info("Sending Remote Unlock command (0x0001)...")
        unlock_payload = (
            self.session_token
            + bytes.fromhex("070001060103e9001500000006")
            + ts
            + bytes.fromhex("004d5800000000")
        )
        unlock_dec = await self._execute_step(
            unlock_payload,
            self.session_key,
            frame_seq=3,
            expected_op=bytes.fromhex("0001"),
        )

        acknowledged = (
            len(unlock_dec) >= 8
            and unlock_dec[5:7] == b"\x00\x01"
            and unlock_dec[7] == 0x01
        )
        if not acknowledged:
            raise RuntimeError(
                f"Atomberg unlock was not acknowledged: {unlock_dec.hex(' ')}"
            )

        logger.info(">> UNLOCKED SUCCESSFULLY <<")
        return now_int

    async def get_battery(self) -> Optional[int]:
        """Query lock battery level percentage (0-100%)."""
        if not self.session_token or not self.session_key:
            raise RuntimeError("Must authenticate before calling get_battery")

        logger.info("Querying battery percentage (0x000D)...")
        status_cmd = (
            self.session_token
            + bytes([self.seq_counter])
            + bytes.fromhex("000d000003e9000c00000000")
        )
        self.seq_counter = (self.seq_counter + 1) & 0xFF

        try:
            resp_decrypted = await self._execute_step(
                status_cmd,
                self.session_key,
                frame_seq=3,
                expected_op=bytes.fromhex("000d"),
                timeout=4.0,
            )
        except Exception as e:
            logger.warning(f"Battery status query failed: {e}")
            return None

        battery = None
        if b"MX" in resp_decrypted:
            mx_idx = resp_decrypted.index(b"MX")
            if mx_idx + 2 < len(resp_decrypted):
                battery = resp_decrypted[mx_idx + 2]
        elif len(resp_decrypted) >= 30:
            battery = resp_decrypted[29]
        elif len(resp_decrypted) >= 28:
            battery = resp_decrypted[28]

        if battery is not None and 0 <= battery <= 100:
            return battery
        return None

    async def fetch_logs(self, slot_mappings: Optional[Dict[int, str]] = None) -> List[Dict[str, Any]]:
        """Fetch all historical audit logs recorded by the lock."""
        if not self.session_token or not self.session_key:
            raise RuntimeError("Must authenticate before calling fetch_logs")

        self.seq_counter = 7
        count_req = (
            self.session_token
            + bytes([self.seq_counter])
            + bytes.fromhex("0008000003e9000c")
        )
        self.seq_counter = (self.seq_counter + 1) & 0xFF

        logger.info("Fetching audit log record count (0x0008)...")
        count_dec = await self._execute_step(
            count_req,
            self.session_key,
            frame_seq=3,
            expected_op=bytes.fromhex("0008"),
        )
        total_records = int.from_bytes(count_dec[-2:], byteorder="big")
        logger.info(f"Total log records on device: {total_records}")

        if total_records == 0:
            return []

        all_records: List[Dict[str, Any]] = []
        total_pages = (total_records + 4) // 5

        for page in range(total_pages):
            offset = page * 5
            logger.info(f"Downloading logs page {page + 1}/{total_pages} (offset {offset})...")
            fetch_req = (
                self.session_token
                + bytes([self.seq_counter])
                + bytes.fromhex("0009010003e9001f")
                + offset.to_bytes(2, byteorder="big")
                + bytes.fromhex("0005")
            )
            self.seq_counter = (self.seq_counter + 1) & 0xFF

            log_dec = await self._execute_step(
                fetch_req,
                self.session_key,
                frame_seq=3,
                expected_op=bytes.fromhex("0009"),
            )

            records_data = log_dec[15:]
            num_in_page = len(records_data) // 32
            if num_in_page == 0:
                break

            for i in range(num_in_page):
                rec = records_data[i * 32 : (i + 1) * 32]
                if len(rec) != 32 or rec[4] == 0x3D:
                    continue

                parsed = parse_log_record(rec, slot_mappings)
                parsed["index"] = len(all_records) + 1
                all_records.append(parsed)

        return all_records

    async def __aenter__(self):
        await self.connect()
        await self.authenticate()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.disconnect()


# ==============================================================================
# Helper Utilities & CLI Actions
# ==============================================================================


async def scan_ble_devices(timeout: float = 6.0, adapter: Optional[str] = None) -> None:
    """Scan for BLE devices in range and display discovered addresses."""
    print(f"[*] Scanning for BLE devices ({timeout}s timeout)...")
    scanner_kwargs: Dict[str, Any] = {}
    if adapter:
        if sys.platform.startswith("linux"):
            scanner_kwargs["bluez"] = {"adapter": adapter}
        else:
            scanner_kwargs["adapter"] = adapter

    discovered = await BleakScanner.discover(timeout=timeout, return_adv=True, **scanner_kwargs)

    print("\n" + "=" * 70)
    print(f"{'BLE MAC Address':<20} | {'RSSI':<6} | {'Device Name':<30}")
    print("-" * 70)

    atomberg_candidates = []
    for dev, adv in discovered.values():
        name = adv.local_name or dev.name or "Unknown"
        rssi = str(adv.rssi) if adv.rssi is not None else "N/A"
        print(f"{dev.address:<20} | {rssi:<6} | {name:<30}")
        if "atomberg" in name.lower() or "sl1" in name.lower() or "lock" in name.lower() or "hsj" in name.lower():
            atomberg_candidates.append((dev, adv))

    print("=" * 70)
    if atomberg_candidates:
        print("\n[+] Potential Atomberg lock device(s) found:")
        for c, adv in atomberg_candidates:
            c_name = adv.local_name or c.name or "Unknown"
            print(f"    - {c.address} ({c_name}) [RSSI: {adv.rssi} dBm]")
    else:
        print(
            "\n[i] If your lock name is hidden, check the MAC printed on the box/sticker "
            "or use extract_keys.py on an Android BTSnoop log."
        )


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Load configuration from JSON file or environment variables."""
    cfg: Dict[str, Any] = {}

    # 1. Try file
    candidates = [config_path] if config_path else ["config.json", "/etc/atomberg/config.json"]
    for p in candidates:
        if p and os.path.exists(p):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                    logger.debug(f"Loaded config from {p}")
                    break
            except Exception as e:
                logger.warning(f"Failed to read config file {p}: {e}")

    # 2. Overwrite with environment variables if present
    if os.environ.get("ATOMBERG_MAC"):
        cfg["mac"] = os.environ.get("ATOMBERG_MAC")
    if os.environ.get("ATOMBERG_KEY"):
        cfg["master_key"] = os.environ.get("ATOMBERG_KEY")
    if os.environ.get("ATOMBERG_SALT"):
        cfg["salt"] = os.environ.get("ATOMBERG_SALT")
    if os.environ.get("ATOMBERG_ADAPTER"):
        cfg["adapter"] = os.environ.get("ATOMBERG_ADAPTER")

    return cfg


async def main_async() -> int:
    parser = argparse.ArgumentParser(
        description="Atomberg SL1 Pro Bluetooth Lock Controller (Standalone)"
    )
    subparsers = parser.add_subparsers(dest="action", help="Action to execute")

    # Command: unlock
    subparsers.add_parser("unlock", help="Trigger remote door unlock (auto-relocks after ~5s)")

    # Command: lock
    subparsers.add_parser(
        "lock",
        help="Note on locking: The lock auto-relocks physically ~5s after unlocking.",
    )

    # Command: battery / status
    subparsers.add_parser("battery", help="Query lock battery percentage")
    subparsers.add_parser("status", help="Check connection and battery status")

    # Command: logs
    log_parser = subparsers.add_parser("logs", help="Download and parse recent audit log records")
    log_parser.add_argument(
        "--json", action="store_true", help="Output raw logs as JSON"
    )
    log_parser.add_argument(
        "--limit", type=int, default=20, help="Maximum log records to display (default: 20)"
    )

    # Command: scan
    subparsers.add_parser("scan", help="Scan for nearby Bluetooth Low Energy devices")

    # Global options
    parser.add_argument("-c", "--config", help="Path to config.json file")
    parser.add_argument("-m", "--mac", help="Lock BLE MAC Address (e.g. AA:BB:CC:11:22:33)")
    parser.add_argument("-k", "--key", help="Master Key (16-char ASCII string or 32-char hex)")
    parser.add_argument("-s", "--salt", help="Lock Salt (8-char hex string, e.g. 1a2b3c4d)")
    parser.add_argument(
        "-a", "--adapter", help="HCI Adapter name (e.g. hci0, hci1) on Linux/Raspberry Pi"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    # Logging setup
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    if not args.action:
        parser.print_help()
        return 1

    # Load credentials / config
    config = load_config(args.config)
    adapter = args.adapter or config.get("adapter")

    # Scan command doesn't need credentials
    if args.action == "scan":
        await scan_ble_devices(adapter=adapter)
        return 0

    if args.action == "lock":
        print("\n" + "=" * 60)
        print("  HARDWARE AUTO-RELOCK NOTICE")
        print("=" * 60)
        print(
            "The Atomberg SL1 Pro lock does not support a software 'Lock' command.\n"
            "Its physical clutch mechanism automatically relocks itself 5 seconds\n"
            "after an unlock action is triggered.\n"
        )
        return 0

    # Load credentials
    config = load_config(args.config)
    mac = args.mac or config.get("mac") or config.get("LOCK_MAC")
    key = args.key or config.get("master_key") or config.get("STATIC_MASTER_KEY")
    salt = args.salt or config.get("salt") or config.get("LOCK_SALT")
    adapter = args.adapter or config.get("adapter")
    slot_mappings = config.get("slot_mappings", {})

    # Convert slot mapping keys from string to int if needed
    formatted_mappings = {}
    for sk, sv in slot_mappings.items():
        try:
            formatted_mappings[int(sk)] = str(sv)
        except ValueError:
            pass

    if not mac or not key or not salt:
        print(
            "[ERROR] Missing credentials! Provide --mac, --key, and --salt, "
            "or define them in config.json / environment variables.",
            file=sys.stderr,
        )
        print(
            "\nExample:\n"
            "    python3 atomberg_cli.py --mac 'AA:BB:CC:11:22:33' --key 'MySecretKey12345' --salt '1a2b3c4d' unlock\n"
            "or create a config.json (see config.json.example).",
            file=sys.stderr,
        )
        return 1

    client = AtombergLockClient(
        mac_address=mac,
        master_key=key,
        lock_salt=salt,
        adapter=adapter,
    )

    try:
        async with client:
            if args.action == "unlock":
                ts = await client.unlock()
                print(f"[+] Door unlocked successfully at {format_timestamp_ist(ts)}")
                print("[i] Latch will auto-relock in ~5 seconds.")
                return 0

            elif args.action in ("battery", "status"):
                bat = await client.get_battery()
                if bat is not None:
                    print(f"[+] Atomberg Lock Battery: {bat}%")
                else:
                    print("[!] Battery query returned no data.")
                return 0

            elif args.action == "logs":
                logs = await client.fetch_logs(formatted_mappings)
                if args.json:
                    print(json.dumps(logs, indent=2))
                    return 0

                print("\n" + "=" * 80)
                print(f"{'#':<4} | {'Timestamp':<24} | {'Event':<24} | {'Detail'}")
                print("-" * 80)

                display_logs = logs[-args.limit :] if args.limit else logs
                for item in display_logs:
                    idx = item.get("index", "-")
                    dt = item.get("datetime") or "Unknown"
                    evt = item.get("event") or "Event"
                    det = item.get("detail") or ""
                    print(f"{idx:<4} | {dt:<24} | {evt:<24} | {det}")
                print("=" * 80)
                print(f"Displaying {len(display_logs)} of {len(logs)} total log records.\n")
                return 0

    except Exception as e:
        logger.error(f"Operation failed: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        return 1

    return 0


def main():
    try:
        ret = asyncio.run(main_async())
        sys.exit(ret)
    except KeyboardInterrupt:
        print("\n[!] Cancelled by user.")
        sys.exit(130)


if __name__ == "__main__":
    main()
