#!/usr/bin/env python3
"""
Atomberg SL1 Pro Smart Lock - Standalone BLE Controller (Optimized)
==================================================================
High-performance standalone Python client and micro-daemon to lock/unlock,
query battery, and fetch audit logs for Atomberg Smart Lock over BLE.

Optimized for Raspberry Pi 3B+/4/5 (64-bit) with sub-second execution,
precomputed lookup tables, and zero-dependency async HTTP micro-daemon.

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

# BLE GATT UUIDs
WRITE_UUID = "0000fff1-0000-1000-8000-00805f9b34fb"
NOTIFY_UUID = "0000fff2-0000-1000-8000-00805f9b34fb"

# Fast Protocol Timeouts (in seconds)
CONNECT_TIMEOUT = 10.0
COMMAND_TIMEOUT = 3.0
DEFAULT_RETRIES = 2

logger = logging.getLogger("atomberg")

# ==============================================================================
# Precomputed Lookup Tables & Fast Cryptography
# ==============================================================================

# 256-entry CRC16 Modbus lookup table (100x faster than bitwise loops)
CRC16_TABLE = [
    0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
    0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
    0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
    0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
    0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
    0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
    0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
    0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
    0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
    0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
    0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
    0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
    0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
    0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
    0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
    0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
    0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
    0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
    0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
    0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
    0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
    0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
    0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
    0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
    0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
    0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
    0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
    0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
    0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
    0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
    0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
    0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040,
]


def crc16_modbus_be(data: bytes) -> bytes:
    """Compute CRC-16 Modbus checksum in Big-Endian format using precomputed table."""
    crc = 0xFFFF
    for b in data:
        crc = (crc >> 8) ^ CRC16_TABLE[(crc ^ b) & 0xFF]
    return crc.to_bytes(2, "big")


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
# Optimized Atomberg BLE Lock Client Class
# ==============================================================================


class AtombergLockClient:
    """Client for high-speed BLE communication with Atomberg SL1 Pro Lock."""

    def __init__(
        self,
        mac_address: str,
        master_key: bytes | str,
        lock_salt: bytes | str,
        adapter: Optional[str] = None,
    ):
        self.mac_address = mac_address.strip().upper()

        # Parse master key
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
            raise ValueError(f"Master key must be 16 bytes (got {len(self.master_key)})")

        # Parse lock salt
        if isinstance(lock_salt, str):
            salt_clean = lock_salt.strip().replace(" ", "").replace("0x", "")
            self.lock_salt = bytes.fromhex(salt_clean)
        else:
            self.lock_salt = lock_salt

        if len(self.lock_salt) != 4:
            raise ValueError(f"Lock salt must be 4 bytes (got {len(self.lock_salt)})")

        self.adapter = adapter
        self.client: Optional[BleakClient] = None
        self.session_token: Optional[bytes] = None
        self.session_key: Optional[bytes] = None
        self.seq_counter: int = 2

        self.rx_buffer = bytearray()
        self.expected_len = 0
        self.recv_queue: asyncio.Queue[bytes] = asyncio.Queue()

    def _clear_buffers(self) -> None:
        self.rx_buffer = bytearray()
        self.expected_len = 0
        while not self.recv_queue.empty():
            try:
                self.recv_queue.get_nowait()
            except asyncio.QueueEmpty:
                break

    def _notification_handler(self, _characteristic: Any, data: bytearray) -> None:
        raw = bytes(data)
        logger.debug(f"[RX NOTIFY] ({len(raw)} bytes): {raw.hex(' ')}")

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

        # Send in 20-byte BLE chunks without artificial delays
        for i in range(0, len(packet), 20):
            chunk = packet[i : i + 20]
            if not self.client or not self.client.is_connected:
                raise ConnectionError("Bluetooth client disconnected during write.")
            await self.client.write_gatt_char(WRITE_UUID, chunk, response=False)

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
                    self.recv_queue.get(), timeout=max(remaining, 0.05)
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
        """Connect to the BLE lock and register notifications."""
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
                logger.info(f"Connecting to lock {self.mac_address} (Attempt {attempt}/{retries})...")
                target = self.mac_address

                if attempt > 1:
                    logger.debug(f"Locating device {self.mac_address} via BLE scanner...")
                    try:
                        dev = await BleakScanner.find_device_by_address(
                            self.mac_address, timeout=3.0, **scanner_kwargs
                        )
                        if dev is not None:
                            target = dev
                            await asyncio.sleep(0.2)
                    except Exception as scan_err:
                        logger.debug(f"Scanner lookup error: {scan_err}")

                self.client = BleakClient(target, **client_kwargs)
                await self.client.connect()

                if not self.client.is_connected:
                    raise ConnectionError(f"Could not connect to {self.mac_address}")

                self._clear_buffers()
                await self.client.start_notify(NOTIFY_UUID, self._notification_handler)
                logger.info("Connected to lock successfully.")
                return
            except Exception as err:
                last_err = err
                err_msg = str(err) if str(err) else type(err).__name__
                logger.warning(f"Connection attempt {attempt} failed: {err_msg}")
                await self.disconnect()
                if attempt < retries:
                    await asyncio.sleep(0.5)

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

        # 3. Context Synchronization 0x00F2
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
        """Calibrate time and trigger momentary unlock."""
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
            raise RuntimeError(f"Unlock unacknowledged: {unlock_dec.hex(' ')}")

        logger.info(">> UNLOCKED SUCCESSFULLY <<")
        return now_int

    async def fast_unlock(self) -> int:
        """Pipelined fast connect, auth, and unlock sequence."""
        await self.connect()
        try:
            await self.authenticate()
            return await self.unlock()
        finally:
            await self.disconnect()

    async def get_battery(self) -> Optional[int]:
        """Query lock battery percentage (0-100%)."""
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
                timeout=2.5,
            )
        except Exception as e:
            logger.warning(f"Battery query failed: {e}")
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
# Ultra-Fast Async HTTP Micro-Daemon (Zero External Dependencies)
# ==============================================================================


async def run_http_daemon(
    mac: str, key: str, salt: str, adapter: Optional[str] = None, port: int = 8765
) -> None:
    """Run persistent high-speed background HTTP daemon for sub-second unlocks."""
    client = AtombergLockClient(mac_address=mac, master_key=key, lock_salt=salt, adapter=adapter)
    lock_mutex = asyncio.Lock()

    print("\n" + "=" * 65)
    print("  ATOMBERG HIGH-SPEED BLE MICRO-DAEMON")
    print("=" * 65)
    print(f"[*] Target Lock MAC: {mac}")
    print(f"[*] Listening on   : http://127.0.0.1:{port}")
    print("[*] Endpoints      : GET /unlock , GET /battery , GET /status")
    print("=" * 65 + "\n")

    async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            line = await reader.readline()
            if not line:
                writer.close()
                return
            parts = line.decode().split()
            if len(parts) < 2:
                writer.close()
                return

            _method, path = parts[0], parts[1].split("?")[0]

            # Drain remaining request headers
            while True:
                hdr = await reader.readline()
                if not hdr or hdr == b"\r\n":
                    break

            status_code = "200 OK"

            if path == "/unlock":
                async with lock_mutex:
                    try:
                        logger.info("[DAEMON] Handling /unlock request...")
                        ts = await client.fast_unlock()
                        body_dict = {
                            "status": "success",
                            "unlocked": True,
                            "timestamp": ts,
                            "datetime": format_timestamp_ist(ts),
                        }
                    except Exception as e:
                        logger.error(f"[DAEMON] Unlock error: {e}")
                        status_code = "500 Internal Server Error"
                        body_dict = {"status": "error", "message": str(e)}

            elif path == "/battery":
                async with lock_mutex:
                    try:
                        logger.info("[DAEMON] Handling /battery request...")
                        async with client:
                            bat = await client.get_battery()
                        body_dict = {"status": "success", "battery": bat}
                    except Exception as e:
                        logger.error(f"[DAEMON] Battery query error: {e}")
                        status_code = "500 Internal Server Error"
                        body_dict = {"status": "error", "message": str(e)}

            elif path in ("/ping", "/status", "/health"):
                body_dict = {"status": "ok", "service": "atomberg-daemon"}

            else:
                status_code = "404 Not Found"
                body_dict = {"error": "Not Found"}

            body_bytes = json.dumps(body_dict, indent=2).encode()
            response = (
                f"HTTP/1.1 {status_code}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(body_bytes)}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode() + body_bytes

            writer.write(response)
            await writer.drain()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    server = await asyncio.start_server(handle_client, host="127.0.0.1", port=port)
    async with server:
        await server.serve_forever()


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
        description="Atomberg SL1 Pro Bluetooth Lock Controller (Optimized)"
    )
    subparsers = parser.add_subparsers(dest="action", help="Action to execute")

    subparsers.add_parser("unlock", help="Trigger fast door unlock (auto-relocks after ~5s)")
    subparsers.add_parser("battery", help="Query lock battery percentage")
    subparsers.add_parser("status", help="Check connection and battery status")

    daemon_parser = subparsers.add_parser("daemon", help="Run background HTTP micro-daemon for instant unlocks")
    daemon_parser.add_argument("--port", type=int, default=8765, help="HTTP daemon port (default: 8765)")

    log_parser = subparsers.add_parser("logs", help="Download and parse recent audit log records")
    log_parser.add_argument("--json", action="store_true", help="Output raw logs as JSON")
    log_parser.add_argument("--limit", type=int, default=20, help="Maximum log records to display (default: 20)")

    subparsers.add_parser("scan", help="Scan for nearby Bluetooth Low Energy devices")

    # Global options
    parser.add_argument("-c", "--config", help="Path to config.json file")
    parser.add_argument("-m", "--mac", help="Lock BLE MAC Address (e.g. AA:BB:CC:11:22:33)")
    parser.add_argument("-k", "--key", help="Master Key (16-char ASCII string or 32-char hex)")
    parser.add_argument("-s", "--salt", help="Lock Salt (8-char hex string, e.g. 1a2b3c4d)")
    parser.add_argument("-a", "--adapter", help="HCI Adapter name (e.g. hci0, hci1) on Linux")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")

    args = parser.parse_args()

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    if not args.action:
        parser.print_help()
        return 1

    config = load_config(args.config)
    adapter = args.adapter or config.get("adapter")

    if args.action == "scan":
        await scan_ble_devices(adapter=adapter)
        return 0

    # Load credentials
    mac = args.mac or config.get("mac") or config.get("LOCK_MAC")
    key = args.key or config.get("master_key") or config.get("STATIC_MASTER_KEY")
    salt = args.salt or config.get("salt") or config.get("LOCK_SALT")
    slot_mappings = config.get("slot_mappings", {})

    formatted_mappings = {}
    for sk, sv in slot_mappings.items():
        try:
            formatted_mappings[int(sk)] = str(sv)
        except ValueError:
            pass

    if not mac or not key or not salt:
        print(
            "[ERROR] Missing credentials! Provide --mac, --key, and --salt, "
            "or define them in config.json.",
            file=sys.stderr,
        )
        return 1

    if args.action == "daemon":
        await run_http_daemon(mac=mac, key=key, salt=salt, adapter=adapter, port=args.port)
        return 0

    client = AtombergLockClient(mac_address=mac, master_key=key, lock_salt=salt, adapter=adapter)

    try:
        if args.action == "unlock":
            ts = await client.fast_unlock()
            print(f"[+] Door unlocked successfully at {format_timestamp_ist(ts)}")
            return 0

        async with client:
            if args.action in ("battery", "status"):
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
                print(f"Displaying {len(display_logs)} of {len(logs)} total records.\n")
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
