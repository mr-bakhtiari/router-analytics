#!/usr/bin/env python3
"""Self-hosted MikroTik traffic analytics dashboard (stdlib-only runtime)."""
from __future__ import annotations

import base64
import csv
import hashlib
import hmac
import io
import ipaddress
import json
import os
import queue
import secrets
import shutil
import socket
import sqlite3
import ssl
import struct
import threading
import time
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

APP_VERSION = "1.1.7"
APP_DIR = Path(__file__).resolve().parent
STATIC_DIR = APP_DIR / "static"
DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
DB_PATH = DATA_DIR / "traffic.db"
HOST = os.getenv("LISTEN_HOST", "0.0.0.0")
PORT = int(os.getenv("LISTEN_PORT", "8080"))
ROUTER_HOST = os.getenv("ROUTER_HOST", "172.30.0.1")
ROUTER_PORT = int(os.getenv("ROUTER_PORT", "8728"))
ROUTER_USER = os.getenv("ROUTER_USER", "traffic-monitor")
ROUTER_PASSWORD = os.getenv("ROUTER_PASSWORD", "")
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"
TLS_CERT = os.getenv("TLS_CERT", "")
TLS_KEY = os.getenv("TLS_KEY", "")
IPFIX_HOST = os.getenv("IPFIX_HOST", "0.0.0.0")
IPFIX_PORT = int(os.getenv("IPFIX_PORT", "2055"))
IPFIX_SOURCE = os.getenv("IPFIX_SOURCE", ROUTER_HOST)
PBKDF2_ROUNDS = 310_000
SESSION_TTL = 8 * 3600


def csv_env(name: str, default: str = "") -> list[str]:
    return [item.strip() for item in os.getenv(name, default).split(",") if item.strip()]


def mapping_env(name: str, default: str = "") -> dict[str, str]:
    result: dict[str, str] = {}
    for item in csv_env(name, default):
        key, separator, value = item.partition("=")
        if not separator or not key.strip() or not value.strip():
            raise RuntimeError(f"{name} entries must use key=value syntax")
        result[key.strip()] = value.strip()
    return result


INTERFACES = csv_env("MONITORED_INTERFACES", "ether1,bridge")
WAN = set(csv_env("WAN_INTERFACES", "ether1"))
LAN_NETWORKS = tuple(
    (ipaddress.ip_network(network, strict=False), interface)
    for network, interface in mapping_env("LAN_NETWORKS", "192.168.88.0/24=bridge").items()
)
ROUTER_LAN_IPS = set(csv_env("ROUTER_LAN_IPS")) or {
    str(ipaddress.ip_address(int(network.network_address) + 1)) for network, _interface in LAN_NETWORKS
}
WAN_ROUTE_COMMENTS = mapping_env("WAN_ROUTE_COMMENTS")
if not INTERFACES:
    raise RuntimeError("MONITORED_INTERFACES must contain at least one interface")
if not WAN.issubset(INTERFACES):
    raise RuntimeError("WAN_INTERFACES must be a subset of MONITORED_INTERFACES")
PORT_NAMES = {
    20: "FTP data", 21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 67: "DHCP",
    68: "DHCP", 80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP", 443: "HTTPS/QUIC",
    465: "SMTPS", 587: "SMTP submission", 853: "DNS over TLS", 993: "IMAPS",
    995: "POP3S", 1194: "OpenVPN", 1701: "L2TP", 3389: "RDP", 5060: "SIP",
    5228: "Google services", 8080: "HTTP alternate", 8443: "HTTPS alternate",
}


def now_ts() -> int:
    return int(time.time())


def parse_int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value).replace(" ", ""))
    except (TypeError, ValueError):
        return default


def parse_uptime(value: str) -> int:
    total, number = 0, ""
    units = {"w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1}
    for char in value:
        if char.isdigit():
            number += char
        elif char in units and number:
            total += int(number) * units[char]
            number = ""
    return total


def password_hash(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ROUNDS)
    return f"pbkdf2-sha256${PBKDF2_ROUNDS}${base64.urlsafe_b64encode(salt).decode()}${base64.urlsafe_b64encode(digest).decode()}"


def password_verify(password: str, encoded: str) -> bool:
    try:
        scheme, rounds, salt, expected = encoded.split("$", 3)
        if scheme != "pbkdf2-sha256":
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), base64.urlsafe_b64decode(salt), int(rounds))
        return hmac.compare_digest(actual, base64.urlsafe_b64decode(expected))
    except (ValueError, TypeError):
        return False


class Database:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.local = threading.local()
        self.wal_initialized = False
        self.migrate()

    def conn(self) -> sqlite3.Connection:
        if not hasattr(self.local, "conn"):
            conn = sqlite3.connect(self.path, timeout=10, isolation_level=None)
            conn.row_factory = sqlite3.Row
            # Changing journal mode takes an exclusive lock. Do it once during
            # startup, never for every HTTP worker while IPFIX is writing.
            if not self.wal_initialized:
                conn.execute("PRAGMA journal_mode=WAL")
                self.wal_initialized = True
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA busy_timeout=3000")
            conn.execute("PRAGMA foreign_keys=ON")
            self.local.conn = conn
        return self.local.conn

    def migrate(self) -> None:
        conn = self.conn()
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS users(
          id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
          created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions(
          token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          csrf TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, last_seen INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS interface_samples(
          ts INTEGER NOT NULL, name TEXT NOT NULL, running INTEGER NOT NULL,
          rx_bytes INTEGER NOT NULL, tx_bytes INTEGER NOT NULL,
          rx_delta INTEGER NOT NULL, tx_delta INTEGER NOT NULL,
          rx_bps REAL NOT NULL, tx_bps REAL NOT NULL, reset INTEGER NOT NULL DEFAULT 0,
          PRIMARY KEY(ts,name));
        CREATE INDEX IF NOT EXISTS idx_interface_samples_name_ts ON interface_samples(name,ts);
        CREATE TABLE IF NOT EXISTS interface_hourly(
          bucket INTEGER NOT NULL, name TEXT NOT NULL, rx_bytes INTEGER NOT NULL, tx_bytes INTEGER NOT NULL,
          peak_rx_bps REAL NOT NULL, peak_tx_bps REAL NOT NULL, avg_rx_bps REAL NOT NULL, avg_tx_bps REAL NOT NULL,
          PRIMARY KEY(bucket,name));
        CREATE TABLE IF NOT EXISTS interface_daily(
          bucket INTEGER NOT NULL, name TEXT NOT NULL, rx_bytes INTEGER NOT NULL, tx_bytes INTEGER NOT NULL,
          peak_rx_bps REAL NOT NULL, peak_tx_bps REAL NOT NULL, avg_rx_bps REAL NOT NULL, avg_tx_bps REAL NOT NULL,
          PRIMARY KEY(bucket,name));
        CREATE TABLE IF NOT EXISTS health_samples(
          ts INTEGER PRIMARY KEY, cpu_load REAL NOT NULL, free_memory INTEGER NOT NULL, total_memory INTEGER NOT NULL,
          uptime INTEGER NOT NULL, usb_free INTEGER NOT NULL, usb_total INTEGER NOT NULL,
          collector_interval INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS devices(
          ip TEXT PRIMARY KEY, mac TEXT, hostname TEXT, interface TEXT, status TEXT NOT NULL,
          first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS device_traffic_minute(
          bucket INTEGER NOT NULL, ip TEXT NOT NULL, direction TEXT NOT NULL, interface TEXT NOT NULL,
          remote_port INTEGER NOT NULL, protocol INTEGER NOT NULL, scope TEXT NOT NULL,
          bytes INTEGER NOT NULL, packets INTEGER NOT NULL, flows INTEGER NOT NULL,
          PRIMARY KEY(bucket,ip,direction,interface,remote_port,protocol,scope));
        CREATE INDEX IF NOT EXISTS idx_device_minute_ip_bucket ON device_traffic_minute(ip,bucket);
        CREATE TABLE IF NOT EXISTS device_traffic_hourly(
          bucket INTEGER NOT NULL, ip TEXT NOT NULL, direction TEXT NOT NULL, interface TEXT NOT NULL,
          remote_port INTEGER NOT NULL, protocol INTEGER NOT NULL, scope TEXT NOT NULL,
          bytes INTEGER NOT NULL, packets INTEGER NOT NULL, flows INTEGER NOT NULL,
          PRIMARY KEY(bucket,ip,direction,interface,remote_port,protocol,scope));
        CREATE INDEX IF NOT EXISTS idx_device_hourly_ip_bucket ON device_traffic_hourly(ip,bucket);
        CREATE TABLE IF NOT EXISTS device_traffic_daily(
          bucket INTEGER NOT NULL, ip TEXT NOT NULL, direction TEXT NOT NULL, interface TEXT NOT NULL,
          remote_port INTEGER NOT NULL, protocol INTEGER NOT NULL, scope TEXT NOT NULL,
          bytes INTEGER NOT NULL, packets INTEGER NOT NULL, flows INTEGER NOT NULL,
          PRIMARY KEY(bucket,ip,direction,interface,remote_port,protocol,scope));
        CREATE INDEX IF NOT EXISTS idx_device_daily_ip_bucket ON device_traffic_daily(ip,bucket);
        CREATE TABLE IF NOT EXISTS events(
          id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, level TEXT NOT NULL, component TEXT NOT NULL,
          message TEXT NOT NULL);
        INSERT OR IGNORE INTO settings(key,value) VALUES
          ('collect_interval','5'),('health_interval','30'),('raw_retention_days','7'),
          ('hourly_retention_days','180'),('daily_retention_days','365'),
          ('device_minute_retention_days','7'),('device_hourly_retention_days','180'),
          ('device_daily_retention_days','365'),('timezone','UTC');
        INSERT OR IGNORE INTO schema_migrations(version,applied_at) VALUES(1,strftime('%s','now'));
        INSERT OR IGNORE INTO schema_migrations(version,applied_at) VALUES(2,strftime('%s','now'));
        INSERT OR IGNORE INTO schema_migrations(version,applied_at) VALUES(3,strftime('%s','now'));
        """)
        if ROUTER_LAN_IPS:
            placeholders = ",".join("?" for _ in ROUTER_LAN_IPS)
            values = tuple(sorted(ROUTER_LAN_IPS))
            for table in ("device_traffic_minute", "device_traffic_hourly", "device_traffic_daily", "devices"):
                conn.execute(f"DELETE FROM {table} WHERE ip IN ({placeholders})", values)

    def setting(self, key: str, default: str) -> str:
        row = self.conn().execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return row[0] if row else default

    def close_thread_connection(self) -> None:
        """Release per-request SQLite state when a HTTP worker exits."""
        conn = getattr(self.local, "conn", None)
        if conn is not None:
            try:
                conn.close()
            finally:
                del self.local.conn

    def event(self, level: str, component: str, message: str) -> None:
        self.conn().execute("INSERT INTO events(ts,level,component,message) VALUES(?,?,?,?)", (now_ts(), level, component, message[:500]))


def encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    if length < 0x4000:
        length |= 0x8000
        return struct.pack(">H", length)
    if length < 0x200000:
        length |= 0xC00000
        return bytes([(length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF])
    if length < 0x10000000:
        length |= 0xE0000000
        return struct.pack(">I", length)
    return b"\xF0" + struct.pack(">I", length)


def read_length(sock: socket.socket) -> int:
    first = sock.recv(1)
    if not first:
        raise ConnectionError("RouterOS API connection closed")
    value = first[0]
    if value & 0x80 == 0:
        return value
    if value & 0xC0 == 0x80:
        return ((value & 0x3F) << 8) | sock.recv(1)[0]
    if value & 0xE0 == 0xC0:
        tail = sock.recv(2)
        return ((value & 0x1F) << 16) | (tail[0] << 8) | tail[1]
    if value & 0xF0 == 0xE0:
        tail = sock.recv(3)
        return ((value & 0x0F) << 24) | (tail[0] << 16) | (tail[1] << 8) | tail[2]
    if value == 0xF0:
        return struct.unpack(">I", recv_exact(sock, 4))[0]
    raise ValueError("Unsupported RouterOS API word length")


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("RouterOS API connection closed")
        data.extend(chunk)
    return bytes(data)


class RouterOSAPI:
    def __init__(self, host: str, port: int, username: str, password: str):
        self.host, self.port, self.username, self.password = host, port, username, password

    def _sentence(self, sock: socket.socket, words: list[str]) -> None:
        for word in words:
            raw = word.encode()
            sock.sendall(encode_length(len(raw)) + raw)
        sock.sendall(b"\x00")

    def _read_sentence(self, sock: socket.socket) -> list[str]:
        words = []
        while True:
            length = read_length(sock)
            if length == 0:
                return words
            words.append(recv_exact(sock, length).decode(errors="replace"))

    def command(self, command: str, properties: list[str] | None = None) -> list[dict[str, str]]:
        if not self.password:
            raise RuntimeError("ROUTER_PASSWORD is not configured")
        with socket.create_connection((self.host, self.port), timeout=5) as sock:
            sock.settimeout(8)
            self._sentence(sock, ["/login", f"=name={self.username}", f"=password={self.password}"])
            reply = self._read_sentence(sock)
            if not reply or reply[0] != "!done":
                raise PermissionError("RouterOS API authentication failed")
            words = [command]
            if properties:
                words.append("=.proplist=" + ",".join(properties))
            self._sentence(sock, words)
            rows: list[dict[str, str]] = []
            while True:
                reply = self._read_sentence(sock)
                if not reply:
                    continue
                if reply[0] == "!done":
                    return rows
                if reply[0] == "!trap":
                    fields = self._fields(reply[1:])
                    raise RuntimeError(fields.get("message", "RouterOS API error"))
                if reply[0] == "!re":
                    rows.append(self._fields(reply[1:]))

    @staticmethod
    def _fields(words: list[str]) -> dict[str, str]:
        result = {}
        for word in words:
            if word.startswith("=") and "=" in word[1:]:
                key, value = word[1:].split("=", 1)
                result[key] = value
        return result


def local_interface(address: str) -> str:
    if address in ROUTER_LAN_IPS:
        return ""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return ""
    for network, interface in LAN_NETWORKS:
        if ip in network:
            return interface
    return ""


def normalize_interface_row(row: dict[str, Any], name: str | None = None) -> dict[str, Any]:
    """Add user-facing directions without losing the raw RouterOS RX/TX values."""
    interface_name = name or str(row.get("name", ""))
    is_wan = interface_name in WAN
    row["role"] = "wan" if is_wan else "lan"
    directions = {
        "download_bps": "rx_bps" if is_wan else "tx_bps",
        "upload_bps": "tx_bps" if is_wan else "rx_bps",
        "download_bytes": "rx_bytes" if is_wan else "tx_bytes",
        "upload_bytes": "tx_bytes" if is_wan else "rx_bytes",
        "download_delta": "rx_delta" if is_wan else "tx_delta",
        "upload_delta": "tx_delta" if is_wan else "rx_delta",
        "peak_download_bps": "peak_rx_bps" if is_wan else "peak_tx_bps",
        "peak_upload_bps": "peak_tx_bps" if is_wan else "peak_rx_bps",
    }
    for target, source in directions.items():
        if source in row:
            row[target] = row[source]
    return row


def protocol_name(number: int) -> str:
    return {1: "ICMP", 6: "TCP", 17: "UDP", 41: "IPv6", 47: "GRE", 50: "ESP", 58: "ICMPv6"}.get(number, str(number))


@dataclass
class IPFIXState:
    last_packet: int = 0
    packets: int = 0
    records: int = 0
    bytes_received: int = 0
    parse_errors: int = 0
    unknown_templates: int = 0
    templates: int = 0
    buffered: int = 0
    last_error: str = ""


class IPFIXCollector(threading.Thread):
    """Small IPFIX v10 receiver with bounded, aggregated SQLite writes."""

    daemon = True

    def __init__(self, db: Database, host: str = IPFIX_HOST, port: int = IPFIX_PORT):
        super().__init__(name="ipfix-collector")
        self.db, self.host, self.port = db, host, port
        self.state = IPFIXState()
        self.stop_event = threading.Event()
        self.templates: dict[tuple[int, int], list[tuple[int, int, int]]] = {}
        self.buffer: dict[tuple[int, str, str, str, int, int, str], list[int]] = {}
        self.buffer_lock = threading.Lock()
        self.last_flush = time.monotonic()

    def run(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
        sock.settimeout(1.0)
        try:
            sock.bind((self.host, self.port))
            while not self.stop_event.is_set():
                try:
                    payload, sender = sock.recvfrom(65535)
                    if IPFIX_SOURCE and sender[0] != IPFIX_SOURCE:
                        continue
                    self.parse_datagram(payload)
                except socket.timeout:
                    pass
                except Exception as exc:
                    self.state.parse_errors += 1
                    self.state.last_error = f"{type(exc).__name__}: {exc}"[:300]
                if time.monotonic() - self.last_flush >= 5 or len(self.buffer) >= 2000:
                    self.flush()
        finally:
            try:
                self.flush()
            finally:
                sock.close()

    @staticmethod
    def _uint(raw: bytes) -> int:
        return int.from_bytes(raw, "big") if raw else 0

    @staticmethod
    def _address(raw: bytes) -> str:
        try:
            return str(ipaddress.ip_address(raw)) if len(raw) in (4, 16) else ""
        except ValueError:
            return ""

    def parse_datagram(self, payload: bytes) -> None:
        if len(payload) < 16:
            raise ValueError("short IPFIX header")
        version, length, export_time, _sequence, domain = struct.unpack_from(">HHIII", payload, 0)
        if version != 10:
            raise ValueError(f"unsupported flow version {version}")
        if length < 16 or length > len(payload):
            raise ValueError("invalid IPFIX message length")
        self.state.packets += 1
        self.state.bytes_received += length
        self.state.last_packet = now_ts()
        offset = 16
        while offset + 4 <= length:
            set_id, set_length = struct.unpack_from(">HH", payload, offset)
            if set_length < 4 or offset + set_length > length:
                raise ValueError("invalid IPFIX set length")
            body = payload[offset + 4:offset + set_length]
            if set_id == 2:
                self._parse_templates(domain, body)
            elif set_id >= 256:
                self._parse_data(domain, set_id, export_time, body)
            offset += set_length

    def _parse_templates(self, domain: int, body: bytes) -> None:
        offset = 0
        while offset + 4 <= len(body):
            template_id, count = struct.unpack_from(">HH", body, offset)
            offset += 4
            if template_id < 256 or count == 0:
                break
            fields: list[tuple[int, int, int]] = []
            valid = True
            for _ in range(count):
                if offset + 4 > len(body):
                    valid = False
                    break
                field_id, field_length = struct.unpack_from(">HH", body, offset)
                offset += 4
                enterprise = 0
                if field_id & 0x8000:
                    field_id &= 0x7FFF
                    if offset + 4 > len(body):
                        valid = False
                        break
                    enterprise = struct.unpack_from(">I", body, offset)[0]
                    offset += 4
                fields.append((enterprise, field_id, field_length))
            if not valid:
                break
            self.templates[(domain, template_id)] = fields
        self.state.templates = len(self.templates)

    def _parse_data(self, domain: int, template_id: int, export_time: int, body: bytes) -> None:
        template = self.templates.get((domain, template_id))
        if not template:
            self.state.unknown_templates += 1
            return
        offset = 0
        while offset < len(body):
            start = offset
            values: dict[tuple[int, int], bytes] = {}
            for enterprise, field_id, field_length in template:
                length = field_length
                if length == 65535:
                    if offset >= len(body):
                        offset = len(body) + 1
                        break
                    length = body[offset]
                    offset += 1
                    if length == 255:
                        if offset + 2 > len(body):
                            offset = len(body) + 1
                            break
                        length = struct.unpack_from(">H", body, offset)[0]
                        offset += 2
                if offset + length > len(body):
                    offset = len(body) + 1
                    break
                values[(enterprise, field_id)] = body[offset:offset + length]
                offset += length
            if offset > len(body):
                break
            if offset == start:
                break
            self._process_record(values, export_time)
            self.state.records += 1
            if len(body) - offset < 4 and all(b == 0 for b in body[offset:]):
                break

    def _process_record(self, values: dict[tuple[int, int], bytes], export_time: int) -> None:
        get = lambda field: values.get((0, field), b"")
        byte_count = self._uint(get(1))
        if byte_count <= 0:
            return
        packet_count = self._uint(get(2))
        protocol = self._uint(get(4))
        src = self._address(get(8)) or self._address(get(27))
        dst = self._address(get(12)) or self._address(get(28))
        post_src = self._address(get(225))
        post_dst = self._address(get(226))
        src_port = self._uint(get(7))
        dst_port = self._uint(get(11))
        post_dst_port = self._uint(get(228))
        src_local = next(((candidate, local_interface(candidate)) for candidate in (src, post_src) if local_interface(candidate)), None)
        dst_local = next(((candidate, local_interface(candidate)) for candidate in (dst, post_dst) if local_interface(candidate)), None)
        if not src_local and not dst_local:
            return
        scope = "inter-lan" if src_local and dst_local and src_local[0] != dst_local[0] else "internet"
        bucket = export_time - (export_time % 60)
        entries: list[tuple[str, str, str, int]] = []
        if src_local:
            entries.append((src_local[0], "upload", src_local[1], dst_port or post_dst_port))
        if dst_local and (not src_local or dst_local[0] != src_local[0]):
            service_port = (dst_port or post_dst_port) if src_local else src_port
            entries.append((dst_local[0], "download", dst_local[1], service_port))
        with self.buffer_lock:
            for ip, direction, interface, remote_port in entries:
                key = (bucket, ip, direction, interface, min(remote_port, 65535), protocol, scope)
                aggregate = self.buffer.setdefault(key, [0, 0, 0])
                aggregate[0] += byte_count
                aggregate[1] += packet_count
                aggregate[2] += 1
            self.state.buffered = len(self.buffer)

    def flush(self) -> None:
        with self.buffer_lock:
            if not self.buffer:
                self.last_flush = time.monotonic()
                return
            pending, self.buffer = self.buffer, {}
            self.state.buffered = 0
        conn = self.db.conn()
        try:
            conn.execute("BEGIN IMMEDIATE")
            observed: dict[str, tuple[str, int]] = {}
            batch = []
            for key, aggregate in pending.items():
                batch.append((*key, *aggregate))
                bucket, ip, _direction, interface, *_rest = key
                observed[ip] = (interface, max(bucket, observed.get(ip, ("", 0))[1]))
            conn.executemany("""INSERT INTO device_traffic_minute
                (bucket,ip,direction,interface,remote_port,protocol,scope,bytes,packets,flows)
                VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(bucket,ip,direction,interface,remote_port,protocol,scope)
                DO UPDATE SET bytes=bytes+excluded.bytes,packets=packets+excluded.packets,flows=flows+excluded.flows""", batch)
            conn.executemany("""INSERT INTO devices(ip,mac,hostname,interface,status,first_seen,last_seen)
                VALUES(?,?,?,?,?,?,?) ON CONFLICT(ip) DO UPDATE SET
                interface=excluded.interface,status='flow',last_seen=MAX(devices.last_seen,excluded.last_seen)""",
                [(ip, "", "", interface, "flow", seen, seen) for ip, (interface, seen) in observed.items()])
            conn.execute("COMMIT")
            self.state.last_error = ""
        except Exception:
            conn.execute("ROLLBACK")
            with self.buffer_lock:
                for key, aggregate in pending.items():
                    target = self.buffer.setdefault(key, [0, 0, 0])
                    for i in range(3):
                        target[i] += aggregate[i]
            raise
        finally:
            self.last_flush = time.monotonic()

    def status(self) -> dict[str, Any]:
        result = dict(vars(self.state))
        result["running"] = self.is_alive()
        result["listening"] = self.is_alive() and not self.state.last_error
        result["port"] = self.port
        return result


@dataclass
class CollectorState:
    last_success: int = 0
    last_error: str = ""
    interval: int = 5
    health_interval: int = 30
    high_cpu_runs: int = 0


class Collector(threading.Thread):
    daemon = True

    def __init__(self, db: Database, api: RouterOSAPI):
        super().__init__(name="collector")
        self.db, self.api = db, api
        self.state = CollectorState()
        self.stop_event = threading.Event()
        self.previous: dict[str, tuple[int, int, int]] = {}
        self.last_health = 0
        self.last_devices = 0
        self.last_maintenance = 0
        self.last_uptime = 0
        self.last_error_log = 0

    def run(self) -> None:
        while not self.stop_event.is_set():
            started = time.monotonic()
            try:
                self.state.interval = max(5, min(60, int(self.db.setting("collect_interval", "5"))))
                self.collect_interfaces()
                if now_ts() - self.last_health >= int(self.db.setting("health_interval", "30")):
                    self.collect_health()
                if now_ts() - self.last_devices >= 60:
                    self.collect_devices()
                if now_ts() - self.last_maintenance >= 3600:
                    self.maintain()
                self.state.last_success, self.state.last_error = now_ts(), ""
            except Exception as exc:  # collector must never affect serving
                self.state.last_error = f"{type(exc).__name__}: {exc}"
                if now_ts() - self.last_error_log >= 60:
                    try:
                        self.db.event("error", "collector", self.state.last_error)
                        self.last_error_log = now_ts()
                    except Exception:
                        pass
            delay = max(0.5, self.state.interval - (time.monotonic() - started))
            self.stop_event.wait(delay)

    def collect_interfaces(self) -> None:
        rows = self.api.command("/interface/print", ["name", "type", "running", "disabled", "rx-byte", "tx-byte"])
        ts = now_ts()
        conn = self.db.conn()
        conn.execute("BEGIN IMMEDIATE")
        try:
            for row in rows:
                name = row.get("name", "")
                if name not in INTERFACES:
                    continue
                rx, tx = parse_int(row.get("rx-byte")), parse_int(row.get("tx-byte"))
                running = int(row.get("running", "false") == "true" and row.get("disabled", "false") != "true")
                previous = self.previous.get(name)
                reset, rx_delta, tx_delta, rx_bps, tx_bps = 0, 0, 0, 0.0, 0.0
                if previous:
                    p_ts, p_rx, p_tx = previous
                    elapsed = max(1, ts - p_ts)
                    if rx >= p_rx and tx >= p_tx:
                        rx_delta, tx_delta = rx - p_rx, tx - p_tx
                        rx_bps, tx_bps = rx_delta * 8 / elapsed, tx_delta * 8 / elapsed
                    else:
                        reset = 1
                self.previous[name] = (ts, rx, tx)
                conn.execute("""INSERT OR REPLACE INTO interface_samples
                    (ts,name,running,rx_bytes,tx_bytes,rx_delta,tx_delta,rx_bps,tx_bps,reset)
                    VALUES(?,?,?,?,?,?,?,?,?,?)""", (ts, name, running, rx, tx, rx_delta, tx_delta, rx_bps, tx_bps, reset))
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise

    def collect_health(self) -> None:
        resource = self.api.command("/system/resource/print")[0]
        disks = self.api.command("/disk/print", ["slot", "type", "parent", "size", "free", "fs", "mount-point"])
        uptime = parse_uptime(resource.get("uptime", ""))
        if self.last_uptime and uptime < self.last_uptime:
            self.previous.clear()
            self.db.event("warning", "collector", "Router reboot or uptime reset detected")
        self.last_uptime = uptime
        usb = next((d for d in disks if d.get("slot") == "usb1-part1"), {})
        cpu = float(resource.get("cpu-load", "0"))
        if cpu >= 70:
            self.state.high_cpu_runs += 1
            if self.state.high_cpu_runs >= 3:
                self.state.interval = min(60, max(10, self.state.interval * 2))
        else:
            self.state.high_cpu_runs = 0
        self.db.conn().execute("""INSERT OR REPLACE INTO health_samples
            (ts,cpu_load,free_memory,total_memory,uptime,usb_free,usb_total,collector_interval)
            VALUES(?,?,?,?,?,?,?,?)""", (now_ts(), cpu, parse_int(resource.get("free-memory")),
            parse_int(resource.get("total-memory")), uptime, parse_int(usb.get("free")),
            parse_int(usb.get("size")), self.state.interval))
        self.last_health = now_ts()

    def collect_devices(self) -> None:
        leases = self.api.command("/ip/dhcp-server/lease/print", ["address", "mac-address", "host-name", "server", "status", "last-seen"])
        arp = self.api.command("/ip/arp/print", ["address", "mac-address", "interface", "complete", "dynamic"])
        by_ip = {row.get("address", ""): row for row in arp if row.get("address")}
        wifi_macs: set[str] = set()
        try:
            registrations = self.api.command("/interface/wifi/registration-table/print", ["mac-address", "interface", "last-activity"])
            wifi_macs = {row.get("mac-address", "").upper() for row in registrations if row.get("mac-address")}
        except Exception:
            pass
        ts = now_ts()
        conn = self.db.conn()
        leased_ips: set[str] = set()
        for lease in leases:
            ip = lease.get("address", "")
            if not ip:
                continue
            leased_ips.add(ip)
            arp_row = by_ip.get(ip, {})
            mac = (lease.get("mac-address") or arp_row.get("mac-address", "")).upper()
            recently_seen = bool(arp_row.get("mac-address")) or mac in wifi_macs
            status = "online" if recently_seen else lease.get("status", "unknown")
            conn.execute("""INSERT INTO devices(ip,mac,hostname,interface,status,first_seen,last_seen)
                VALUES(?,?,?,?,?,?,?) ON CONFLICT(ip) DO UPDATE SET mac=excluded.mac,hostname=excluded.hostname,
                interface=excluded.interface,status=excluded.status,
                last_seen=CASE WHEN excluded.status='online' THEN excluded.last_seen ELSE devices.last_seen END""",
                (ip, mac, lease.get("host-name", ""), arp_row.get("interface", "") or local_interface(ip),
                 status, ts, ts))
        for ip, arp_row in by_ip.items():
            if ip in leased_ips or not local_interface(ip) or not arp_row.get("mac-address"):
                continue
            conn.execute("""INSERT INTO devices(ip,mac,hostname,interface,status,first_seen,last_seen)
                VALUES(?,?,?,?,?,?,?) ON CONFLICT(ip) DO UPDATE SET mac=excluded.mac,
                interface=excluded.interface,status='online',last_seen=excluded.last_seen""",
                (ip, arp_row.get("mac-address", "").upper(), "", arp_row.get("interface", "") or local_interface(ip),
                 "online", ts, ts))
        conn.execute("UPDATE devices SET status='offline' WHERE last_seen<? AND status='online'", (ts - 300,))
        self.last_devices = ts

    def maintain(self) -> None:
        conn, ts = self.db.conn(), now_ts()
        hour = ts - (ts % 3600)
        day = ts - (ts % 86400)
        conn.execute("""INSERT OR REPLACE INTO interface_hourly
          SELECT ?,name,SUM(rx_delta),SUM(tx_delta),MAX(rx_bps),MAX(tx_bps),AVG(rx_bps),AVG(tx_bps)
          FROM interface_samples WHERE ts>=? AND ts<? GROUP BY name""", (hour - 3600, hour - 3600, hour))
        conn.execute("""INSERT OR REPLACE INTO interface_daily
          SELECT ?,name,SUM(rx_bytes),SUM(tx_bytes),MAX(peak_rx_bps),MAX(peak_tx_bps),AVG(avg_rx_bps),AVG(avg_tx_bps)
          FROM interface_hourly WHERE bucket>=? AND bucket<? GROUP BY name""", (day - 86400, day - 86400, day))
        conn.execute("DELETE FROM interface_samples WHERE ts<?", (ts - int(self.db.setting("raw_retention_days", "7")) * 86400,))
        conn.execute("DELETE FROM interface_hourly WHERE bucket<?", (ts - int(self.db.setting("hourly_retention_days", "180")) * 86400,))
        conn.execute("DELETE FROM interface_daily WHERE bucket<?", (ts - int(self.db.setting("daily_retention_days", "365")) * 86400,))
        conn.execute("""INSERT OR REPLACE INTO device_traffic_hourly
          SELECT ?,ip,direction,interface,remote_port,protocol,scope,SUM(bytes),SUM(packets),SUM(flows)
          FROM device_traffic_minute WHERE bucket>=? AND bucket<?
          GROUP BY ip,direction,interface,remote_port,protocol,scope""", (hour - 3600, hour - 3600, hour))
        conn.execute("""INSERT OR REPLACE INTO device_traffic_daily
          SELECT ?,ip,direction,interface,remote_port,protocol,scope,SUM(bytes),SUM(packets),SUM(flows)
          FROM device_traffic_hourly WHERE bucket>=? AND bucket<?
          GROUP BY ip,direction,interface,remote_port,protocol,scope""", (day - 86400, day - 86400, day))
        conn.execute("DELETE FROM device_traffic_minute WHERE bucket<?", (ts - int(self.db.setting("device_minute_retention_days", "7")) * 86400,))
        conn.execute("DELETE FROM device_traffic_hourly WHERE bucket<?", (ts - int(self.db.setting("device_hourly_retention_days", "180")) * 86400,))
        conn.execute("DELETE FROM device_traffic_daily WHERE bucket<?", (ts - int(self.db.setting("device_daily_retention_days", "365")) * 86400,))
        conn.execute("DELETE FROM sessions WHERE expires_at<?", (ts,))
        conn.execute("DELETE FROM events WHERE ts<?", (ts - 30 * 86400,))
        conn.execute("PRAGMA wal_checkpoint(PASSIVE)")
        self.last_maintenance = ts


DB = Database(DB_PATH)
API = RouterOSAPI(ROUTER_HOST, ROUTER_PORT, ROUTER_USER, ROUTER_PASSWORD)
COLLECTOR = Collector(DB, API)
IPFIX = IPFIXCollector(DB)
LOGIN_ATTEMPTS: dict[str, list[int]] = {}
LOGIN_LOCK = threading.Lock()


def traffic_segments(start: int, end: int) -> list[tuple[str, int, int]]:
    """Select non-overlapping retained resolutions for a requested period."""
    current = now_ts()
    minute_boundary = ((current - int(DB.setting("device_minute_retention_days", "7")) * 86400) // 3600) * 3600
    hourly_boundary = ((current - int(DB.setting("device_hourly_retention_days", "180")) * 86400) // 86400) * 86400
    segments: list[tuple[str, int, int]] = []
    if start < hourly_boundary:
        segments.append(("device_traffic_daily", start, min(end, hourly_boundary - 1)))
    if end >= hourly_boundary and start < minute_boundary:
        segments.append(("device_traffic_hourly", max(start, hourly_boundary), min(end, minute_boundary - 1)))
    if end >= minute_boundary:
        segments.append(("device_traffic_minute", max(start, minute_boundary), end))
    return [(table, first, last) for table, first, last in segments if last >= first]


def requested_range(params: dict[str, list[str]], default_seconds: int = 86400) -> tuple[int, int]:
    end = min(now_ts(), parse_int(params.get("end", [now_ts()])[0], now_ts()))
    start = max(0, parse_int(params.get("start", [end - default_seconds])[0], end - default_seconds))
    if end <= start or end - start > 366 * 86400:
        raise ValueError("invalid date range")
    return start, end


class Handler(SimpleHTTPRequestHandler):
    server_version = "L009Analytics/1.1"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(STATIC_DIR), **kwargs)

    def log_message(self, fmt: str, *args: Any) -> None:
        pass

    def finish(self) -> None:
        try:
            super().finish()
        finally:
            # ThreadingHTTPServer creates a worker for every request. Without
            # this, each worker can retain SQLite page caches until GC runs.
            DB.close_thread_connection()

    def end_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'")
        self.send_header("Cache-Control", "no-store" if self.path.startswith("/api/") else "public, max-age=300")
        super().end_headers()

    def json_body(self) -> dict[str, Any]:
        size = min(parse_int(self.headers.get("Content-Length")), 64 * 1024)
        return json.loads(self.rfile.read(size) or b"{}")

    def respond_json(self, data: Any, status: int = 200) -> None:
        raw = json.dumps(data, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def session(self) -> sqlite3.Row | None:
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        token = cookie.get("session")
        if not token:
            return None
        token_hash = hashlib.sha256(token.value.encode()).hexdigest()
        row = DB.conn().execute("""SELECT s.*,u.username FROM sessions s JOIN users u ON u.id=s.user_id
            WHERE token_hash=? AND expires_at>?""", (token_hash, now_ts())).fetchone()
        if row:
            DB.conn().execute("UPDATE sessions SET last_seen=? WHERE token_hash=?", (now_ts(), token_hash))
        return row

    def require_auth(self, csrf: bool = False) -> sqlite3.Row | None:
        session = self.session()
        if not session:
            self.respond_json({"error": "authentication required"}, 401)
            return None
        if csrf and not hmac.compare_digest(self.headers.get("X-CSRF-Token", ""), session["csrf"]):
            self.respond_json({"error": "invalid CSRF token"}, 403)
            return None
        return session

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path == "/api/status":
            setup = DB.conn().execute("SELECT COUNT(*) FROM users").fetchone()[0] > 0
            session = self.session()
            return self.respond_json({"version": APP_VERSION, "setup": setup, "authenticated": bool(session),
                                      "csrf": session["csrf"] if session else ""})
        if path.startswith("/api/") and not self.require_auth():
            return
        params = urllib.parse.parse_qs(parsed.query)
        if path == "/api/overview":
            return self.api_overview()
        if path == "/api/interfaces":
            return self.api_interfaces()
        if path == "/api/history":
            return self.api_history(params)
        if path == "/api/devices":
            return self.api_devices(params)
        if path == "/api/device-history":
            return self.api_device_history(params)
        if path == "/api/device-ports":
            return self.api_device_ports(params)
        if path == "/api/device-export.csv":
            return self.api_device_export(params)
        if path == "/api/health":
            return self.api_health()
        if path == "/api/events":
            rows = [dict(r) for r in DB.conn().execute("SELECT * FROM events ORDER BY ts DESC LIMIT 100")]
            return self.respond_json({"events": rows})
        if path == "/api/settings":
            rows = DB.conn().execute("SELECT key,value FROM settings ORDER BY key")
            return self.respond_json({"settings": {r[0]: r[1] for r in rows}})
        if path == "/api/export.csv":
            return self.api_export(params)
        if path == "/api/live":
            return self.api_live()
        if path.startswith("/api/"):
            return self.respond_json({"error": "not found"}, 404)
        if path == "/":
            self.path = "/index.html"
        return super().do_GET()

    def do_POST(self) -> None:
        path = urllib.parse.urlparse(self.path).path
        try:
            body = self.json_body()
        except (json.JSONDecodeError, UnicodeDecodeError):
            return self.respond_json({"error": "invalid JSON"}, 400)
        if path == "/api/setup":
            return self.api_setup(body)
        if path == "/api/login":
            return self.api_login(body)
        session = self.require_auth(csrf=True)
        if not session:
            return
        if path == "/api/logout":
            cookie = SimpleCookie(self.headers.get("Cookie", ""))
            if cookie.get("session"):
                DB.conn().execute("DELETE FROM sessions WHERE token_hash=?", (hashlib.sha256(cookie["session"].value.encode()).hexdigest(),))
            self.send_response(204)
            self.send_header("Set-Cookie", "session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict")
            return self.end_headers()
        if path == "/api/password":
            current, new = str(body.get("current", "")), str(body.get("new", ""))
            row = DB.conn().execute("SELECT password_hash FROM users WHERE id=?", (session["user_id"],)).fetchone()
            if not row or not password_verify(current, row[0]):
                return self.respond_json({"error": "current password is incorrect"}, 403)
            if len(new) < 12:
                return self.respond_json({"error": "new password must be at least 12 characters"}, 400)
            DB.conn().execute("UPDATE users SET password_hash=?,updated_at=? WHERE id=?", (password_hash(new), now_ts(), session["user_id"]))
            DB.conn().execute("DELETE FROM sessions WHERE user_id=?", (session["user_id"],))
            return self.respond_json({"ok": True})
        if path == "/api/settings":
            allowed = {"collect_interval": (5, 60), "health_interval": (15, 300), "raw_retention_days": (1, 30),
                       "hourly_retention_days": (7, 365), "daily_retention_days": (30, 730),
                       "device_minute_retention_days": (1, 14), "device_hourly_retention_days": (7, 365),
                       "device_daily_retention_days": (30, 730)}
            for key, limits in allowed.items():
                if key in body:
                    value = int(body[key])
                    if not limits[0] <= value <= limits[1]:
                        return self.respond_json({"error": f"{key} is outside safe bounds"}, 400)
                    DB.conn().execute("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)", (key, str(value)))
            return self.respond_json({"ok": True})
        return self.respond_json({"error": "not found"}, 404)

    def api_setup(self, body: dict[str, Any]) -> None:
        if DB.conn().execute("SELECT COUNT(*) FROM users").fetchone()[0]:
            return self.respond_json({"error": "setup already completed"}, 409)
        username, password = str(body.get("username", "admin")).strip(), str(body.get("password", ""))
        if len(username) < 3 or len(password) < 12:
            return self.respond_json({"error": "username must be 3+ characters and password 12+ characters"}, 400)
        ts = now_ts()
        DB.conn().execute("INSERT INTO users(username,password_hash,created_at,updated_at) VALUES(?,?,?,?)",
                          (username, password_hash(password), ts, ts))
        return self.respond_json({"ok": True}, 201)

    def api_login(self, body: dict[str, Any]) -> None:
        remote = self.client_address[0]
        with LOGIN_LOCK:
            attempts = [t for t in LOGIN_ATTEMPTS.get(remote, []) if t > now_ts() - 900]
            LOGIN_ATTEMPTS[remote] = attempts
            if len(attempts) >= 8:
                return self.respond_json({"error": "too many attempts; retry later"}, 429)
        row = DB.conn().execute("SELECT * FROM users WHERE username=?", (str(body.get("username", "")),)).fetchone()
        if not row or not password_verify(str(body.get("password", "")), row["password_hash"]):
            with LOGIN_LOCK:
                LOGIN_ATTEMPTS.setdefault(remote, []).append(now_ts())
            time.sleep(0.35)
            return self.respond_json({"error": "invalid credentials"}, 401)
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
        DB.conn().execute("INSERT INTO sessions(token_hash,user_id,csrf,created_at,expires_at,last_seen) VALUES(?,?,?,?,?,?)",
                          (hashlib.sha256(token.encode()).hexdigest(), row["id"], csrf, now_ts(), now_ts() + SESSION_TTL, now_ts()))
        self.send_response(200)
        cookie = f"session={token}; Path=/; Max-Age={SESSION_TTL}; HttpOnly; SameSite=Strict"
        if COOKIE_SECURE:
            cookie += "; Secure"
        self.send_header("Set-Cookie", cookie)
        raw = json.dumps({"ok": True, "csrf": csrf}).encode()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def api_overview(self) -> None:
        conn = DB.conn()
        latest = [normalize_interface_row(dict(r)) for r in conn.execute("""SELECT s.* FROM interface_samples s JOIN
            (SELECT name,MAX(ts) ts FROM interface_samples GROUP BY name) x ON x.name=s.name AND x.ts=s.ts ORDER BY s.name""")]
        health = conn.execute("SELECT * FROM health_samples ORDER BY ts DESC LIMIT 1").fetchone()
        routes = []
        try:
            routes = API.command("/ip/route/print", ["comment", "active", "disabled", "routing-table", "dst-address", "distance", "gateway", "immediate-gw"])
        except Exception:
            pass
        wan = {}
        for name in sorted(WAN):
            route_comment = WAN_ROUTE_COMMENTS.get(name, "")
            route = next((r for r in routes if route_comment and r.get("comment") == route_comment), {})
            if not route:
                route = next((r for r in routes if r.get("dst-address") == "0.0.0.0/0" and
                    (r.get("gateway") == name or f"%{name}" in r.get("immediate-gw", ""))), {})
            iface = next((r for r in latest if r["name"] == name), {})
            wan[name] = {"link": bool(iface.get("running")), "internet_route_active": route.get("active") == "true"}
        active = next((name for name in sorted(WAN) if wan[name]["internet_route_active"]), "unknown")
        return self.respond_json({"interfaces": latest, "health": dict(health) if health else None, "wan": wan,
            "active_wan": active, "collector": self.collector_status(), "db_bytes": DB_PATH.stat().st_size if DB_PATH.exists() else 0})

    def api_interfaces(self) -> None:
        rows = [normalize_interface_row(dict(r)) for r in DB.conn().execute("""SELECT s.* FROM interface_samples s JOIN
            (SELECT name,MAX(ts) ts FROM interface_samples GROUP BY name) x ON x.name=s.name AND x.ts=s.ts ORDER BY s.name""")]
        return self.respond_json({"interfaces": rows})

    def api_history(self, params: dict[str, list[str]]) -> None:
        name = params.get("interface", [INTERFACES[0]])[0]
        if name not in INTERFACES:
            return self.respond_json({"error": "invalid interface"}, 400)
        end = min(now_ts(), parse_int(params.get("end", [now_ts()])[0], now_ts()))
        start = max(0, parse_int(params.get("start", [end - 86400])[0], end - 86400))
        if end <= start or end - start > 366 * 86400:
            return self.respond_json({"error": "invalid date range"}, 400)
        bucket = max(5, min(86400, parse_int(params.get("bucket", [60])[0], 60)))
        rows = [normalize_interface_row(dict(r), name) for r in DB.conn().execute("""SELECT (ts/?)*? bucket,SUM(rx_delta) rx_bytes,
            SUM(tx_delta) tx_bytes,AVG(rx_bps) rx_bps,AVG(tx_bps) tx_bps,MAX(rx_bps) peak_rx_bps,
            MAX(tx_bps) peak_tx_bps FROM interface_samples WHERE name=? AND ts>=? AND ts<=?
            GROUP BY bucket ORDER BY bucket""", (bucket, bucket, name, start, end))]
        return self.respond_json({"interface": name, "start": start, "end": end, "bucket": bucket, "samples": rows})

    def api_devices(self, params: dict[str, list[str]]) -> None:
        try:
            start, end = requested_range(params)
        except ValueError as exc:
            return self.respond_json({"error": str(exc)}, 400)
        totals: dict[str, dict[str, int]] = {}
        for table, first, last in traffic_segments(start, end):
            for row in DB.conn().execute(f"""SELECT ip,direction,SUM(bytes) bytes,SUM(packets) packets,
                SUM(flows) flows FROM {table} WHERE bucket BETWEEN ? AND ? GROUP BY ip,direction""", (first, last)):
                item = totals.setdefault(row["ip"], {"upload_bytes": 0, "download_bytes": 0, "packets": 0, "flows": 0})
                item[f"{row['direction']}_bytes"] += row["bytes"] or 0
                item["packets"] += row["packets"] or 0
                item["flows"] += row["flows"] or 0
        rows = []
        for record in DB.conn().execute("SELECT * FROM devices ORDER BY last_seen DESC"):
            item = dict(record)
            item.update(totals.get(item["ip"], {"upload_bytes": 0, "download_bytes": 0, "packets": 0, "flows": 0}))
            item["total_bytes"] = item["upload_bytes"] + item["download_bytes"]
            item["online"] = item["last_seen"] >= now_ts() - 300
            rows.append(item)
        rows.sort(key=lambda row: (row["total_bytes"], row["last_seen"]), reverse=True)
        status = IPFIX.status()
        accounting = "active" if status["last_packet"] >= now_ts() - 120 else "waiting"
        return self.respond_json({"devices": rows, "accounting": accounting, "flow": status,
            "start": start, "end": end,
            "limitation": "Devices behind a downstream NAT router are visible only as that upstream router."})

    def _device_request(self, params: dict[str, list[str]]) -> tuple[str, int, int] | None:
        ip = params.get("ip", [""])[0]
        try:
            parsed = str(ipaddress.ip_address(ip))
        except ValueError:
            self.respond_json({"error": "invalid IP address"}, 400)
            return None
        if not local_interface(parsed):
            self.respond_json({"error": "IP is outside monitored LAN networks"}, 400)
            return None
        try:
            start, end = requested_range(params)
        except ValueError as exc:
            self.respond_json({"error": str(exc)}, 400)
            return None
        return parsed, start, end

    def api_device_history(self, params: dict[str, list[str]]) -> None:
        request = self._device_request(params)
        if not request:
            return
        ip, start, end = request
        bucket = max(60, min(86400, parse_int(params.get("bucket", [300])[0], 300)))
        port = parse_int(params.get("port", [0])[0])
        interface = params.get("interface", [""])[0]
        scope = params.get("scope", [""])[0]
        samples: dict[int, dict[str, int]] = {}
        for table, first, last in traffic_segments(start, end):
            conditions, values = ["ip=?", "bucket BETWEEN ? AND ?"], [ip, first, last]
            if 0 < port <= 65535:
                conditions.append("remote_port=?")
                values.append(port)
            if interface in INTERFACES:
                conditions.append("interface=?")
                values.append(interface)
            if scope in {"internet", "inter-lan"}:
                conditions.append("scope=?")
                values.append(scope)
            sql = f"""SELECT (bucket/?)*? sample,direction,SUM(bytes) bytes,SUM(packets) packets,
                SUM(flows) flows FROM {table} WHERE {' AND '.join(conditions)} GROUP BY sample,direction"""
            for row in DB.conn().execute(sql, [bucket, bucket, *values]):
                item = samples.setdefault(row["sample"], {"bucket": row["sample"], "upload_bytes": 0,
                    "download_bytes": 0, "packets": 0, "flows": 0})
                item[f"{row['direction']}_bytes"] += row["bytes"] or 0
                item["packets"] += row["packets"] or 0
                item["flows"] += row["flows"] or 0
        return self.respond_json({"ip": ip, "start": start, "end": end, "bucket": bucket,
            "samples": [samples[key] for key in sorted(samples)]})

    def api_device_ports(self, params: dict[str, list[str]]) -> None:
        request = self._device_request(params)
        if not request:
            return
        ip, start, end = request
        totals: dict[tuple[int, int, str], dict[str, int]] = {}
        for table, first, last in traffic_segments(start, end):
            for row in DB.conn().execute(f"""SELECT remote_port,protocol,scope,direction,SUM(bytes) bytes,
                SUM(packets) packets,SUM(flows) flows FROM {table} WHERE ip=? AND bucket BETWEEN ? AND ?
                GROUP BY remote_port,protocol,scope,direction""", (ip, first, last)):
                key = (row["remote_port"], row["protocol"], row["scope"])
                item = totals.setdefault(key, {"upload_bytes": 0, "download_bytes": 0, "packets": 0, "flows": 0})
                item[f"{row['direction']}_bytes"] += row["bytes"] or 0
                item["packets"] += row["packets"] or 0
                item["flows"] += row["flows"] or 0
        rows = []
        for (port, protocol, scope), item in totals.items():
            item.update({"port": port, "service": PORT_NAMES.get(port, "Other"),
                         "protocol": protocol_name(protocol), "protocol_number": protocol, "scope": scope})
            item["total_bytes"] = item["upload_bytes"] + item["download_bytes"]
            rows.append(item)
        rows.sort(key=lambda row: row["total_bytes"], reverse=True)
        return self.respond_json({"ip": ip, "start": start, "end": end, "ports": rows[:200]})

    def api_device_export(self, params: dict[str, list[str]]) -> None:
        request = self._device_request(params)
        if not request:
            return
        ip, start, end = request
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["bucket_utc", "device_ip", "direction", "interface", "remote_port", "protocol",
                         "scope", "bytes", "packets", "flows"])
        for table, first, last in traffic_segments(start, end):
            for row in DB.conn().execute(f"""SELECT * FROM {table} WHERE ip=? AND bucket BETWEEN ? AND ?
                ORDER BY bucket,direction,remote_port""", (ip, first, last)):
                writer.writerow([datetime.fromtimestamp(row["bucket"], timezone.utc).isoformat(), ip,
                    row["direction"], row["interface"], row["remote_port"], protocol_name(row["protocol"]),
                    row["scope"], row["bytes"], row["packets"], row["flows"]])
        raw = output.getvalue().encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="device-{ip}-{start}-{end}.csv"')
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def api_health(self) -> None:
        latest = DB.conn().execute("SELECT * FROM health_samples ORDER BY ts DESC LIMIT 1").fetchone()
        integrity = DB.conn().execute("PRAGMA quick_check").fetchone()[0]
        disk = shutil.disk_usage(DATA_DIR)
        return self.respond_json({"health": dict(latest) if latest else None, "collector": self.collector_status(),
            "database": {"path": str(DB_PATH), "bytes": DB_PATH.stat().st_size if DB_PATH.exists() else 0,
                         "integrity": integrity}, "container": {"status": "running", "version": APP_VERSION},
            "filesystem": {"free": disk.free, "total": disk.total}, "ipfix": IPFIX.status()})

    def collector_status(self) -> dict[str, Any]:
        return {"last_success": COLLECTOR.state.last_success, "last_error": COLLECTOR.state.last_error,
                "interval": COLLECTOR.state.interval, "running": COLLECTOR.is_alive()}

    def api_export(self, params: dict[str, list[str]]) -> None:
        name = params.get("interface", [INTERFACES[0]])[0]
        if name not in INTERFACES:
            return self.respond_json({"error": "invalid interface"}, 400)
        end, start = parse_int(params.get("end", [now_ts()])[0]), parse_int(params.get("start", [now_ts()-86400])[0])
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["timestamp_utc", "interface", "role", "running", "rx_bytes_total", "tx_bytes_total",
                         "rx_bytes_delta", "tx_bytes_delta", "rx_bps", "tx_bps", "download_bytes_delta",
                         "upload_bytes_delta", "download_bps", "upload_bps", "counter_reset"])
        for row in DB.conn().execute("SELECT * FROM interface_samples WHERE name=? AND ts BETWEEN ? AND ? ORDER BY ts", (name, start, end)):
            item = normalize_interface_row(dict(row))
            writer.writerow([datetime.fromtimestamp(item["ts"], timezone.utc).isoformat(), item["name"], item["role"],
                item["running"], item["rx_bytes"], item["tx_bytes"], item["rx_delta"], item["tx_delta"],
                item["rx_bps"], item["tx_bps"], item["download_delta"], item["upload_delta"],
                item["download_bps"], item["upload_bps"], item["reset"]])
        raw = output.getvalue().encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="{name}-{start}-{end}.csv"')
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def api_live(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        try:
            for _ in range(120):
                rows = [dict(r) for r in DB.conn().execute("""SELECT s.* FROM interface_samples s JOIN
                    (SELECT name,MAX(ts) ts FROM interface_samples GROUP BY name) x ON x.name=s.name AND x.ts=s.ts""")]
                self.wfile.write(b"data: " + json.dumps({"interfaces": rows}).encode() + b"\n\n")
                self.wfile.flush()
                time.sleep(5)
        except (BrokenPipeError, ConnectionResetError):
            pass


def main() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    COLLECTOR.start()
    IPFIX.start()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    server.daemon_threads = True
    if TLS_CERT and TLS_KEY:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(TLS_CERT, TLS_KEY)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        COLLECTOR.stop_event.set()
        IPFIX.stop_event.set()
        server.server_close()


if __name__ == "__main__":
    main()
