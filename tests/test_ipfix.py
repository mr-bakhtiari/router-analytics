import importlib.util
import hashlib
import http.client
import ipaddress
import os
import struct
import sys
import time
import threading
import unittest
from pathlib import Path


TEST_DATA = str(Path(__file__).parents[2] / "test-data-ipfix")
Path(TEST_DATA).mkdir(parents=True, exist_ok=True)
os.environ["DATA_DIR"] = TEST_DATA
os.environ["MONITORED_INTERFACES"] = "wan1,lan1"
os.environ["WAN_INTERFACES"] = "wan1"
os.environ["LAN_NETWORKS"] = "192.0.2.0/24=lan1"
os.environ["ROUTER_LAN_IPS"] = "192.0.2.1"
spec = importlib.util.spec_from_file_location("dashboard_app", Path(__file__).parents[1] / "app" / "app.py")
app = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = app
spec.loader.exec_module(app)


FIELDS = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (1, 8), (2, 8)]


def message(sets, export_time):
    body = b"".join(sets)
    return struct.pack(">HHIII", 10, 16 + len(body), export_time, 1, 77) + body


def template_set():
    record = struct.pack(">HH", 256, len(FIELDS)) + b"".join(struct.pack(">HH", *field) for field in FIELDS)
    return struct.pack(">HH", 2, 4 + len(record)) + record


def data_set(src, dst, src_port, dst_port, protocol, byte_count, packets):
    record = ipaddress.ip_address(src).packed + ipaddress.ip_address(dst).packed
    record += struct.pack(">HHBQQ", src_port, dst_port, protocol, byte_count, packets)
    return struct.pack(">HH", 256, 4 + len(record)) + record


class IPFIXTests(unittest.TestCase):
    def setUp(self):
        self.db = app.Database(Path(TEST_DATA) / f"case-{time.time_ns()}.db")
        self.collector = app.IPFIXCollector(self.db)
        self.ts = int(time.time())
        self.collector.parse_datagram(message([template_set()], self.ts))

    def test_outbound_and_inbound_are_accounted_to_device(self):
        outbound = data_set("192.0.2.10", "8.8.8.8", 50000, 53, 17, 1000, 10)
        inbound = data_set("8.8.8.8", "192.0.2.10", 53, 50000, 17, 2000, 20)
        self.collector.parse_datagram(message([outbound, inbound], self.ts))
        self.collector.flush()
        rows = list(self.db.conn().execute("SELECT * FROM device_traffic_minute ORDER BY direction"))
        self.assertEqual(2, len(rows))
        by_direction = {row["direction"]: row for row in rows}
        self.assertEqual(2000, by_direction["download"]["bytes"])
        self.assertEqual(1000, by_direction["upload"]["bytes"])
        self.assertEqual(53, by_direction["download"]["remote_port"])
        self.assertEqual(53, by_direction["upload"]["remote_port"])
        self.assertEqual("lan1", by_direction["upload"]["interface"])

    def test_ignores_non_lan_flow(self):
        flow = data_set("8.8.8.8", "1.1.1.1", 53, 51000, 17, 900, 3)
        self.collector.parse_datagram(message([flow], self.ts))
        self.collector.flush()
        count = self.db.conn().execute("SELECT COUNT(*) FROM device_traffic_minute").fetchone()[0]
        self.assertEqual(0, count)


class DeviceAPITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = app.ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.token = "unit-test-session"
        ts = int(time.time())
        conn = app.DB.conn()
        conn.execute("INSERT OR IGNORE INTO users(id,username,password_hash,created_at,updated_at) VALUES(1,'tester','x',?,?)", (ts, ts))
        conn.execute("INSERT OR REPLACE INTO sessions(token_hash,user_id,csrf,created_at,expires_at,last_seen) VALUES(?,1,'csrf',?,?,?)",
                     (hashlib.sha256(cls.token.encode()).hexdigest(), ts, ts + 3600, ts))
        conn.execute("INSERT OR REPLACE INTO devices(ip,mac,hostname,interface,status,first_seen,last_seen) VALUES(?,?,?,?,?,?,?)",
                     ("192.0.2.222", "AA:BB:CC:DD:EE:FF", "test-device", "lan1", "online", ts, ts))
        conn.execute("DELETE FROM device_traffic_minute WHERE ip='192.0.2.222'")
        bucket = ts - ts % 60
        conn.execute("""INSERT OR REPLACE INTO device_traffic_minute
            (bucket,ip,direction,interface,remote_port,protocol,scope,bytes,packets,flows)
            VALUES(?,?,?,?,?,?,?,?,?,?)""", (bucket, "192.0.2.222", "upload", "lan1", 443, 6, "internet", 1111, 10, 2))
        conn.execute("""INSERT OR REPLACE INTO device_traffic_minute
            (bucket,ip,direction,interface,remote_port,protocol,scope,bytes,packets,flows)
            VALUES(?,?,?,?,?,?,?,?,?,?)""", (bucket, "192.0.2.222", "download", "lan1", 443, 6, "internet", 2222, 20, 2))

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    @classmethod
    def get_json(cls, path):
        connection = http.client.HTTPConnection("127.0.0.1", cls.server.server_port, timeout=5)
        connection.request("GET", path, headers={"Cookie": f"session={cls.token}"})
        response = connection.getresponse()
        payload = __import__("json").loads(response.read())
        connection.close()
        return response.status, payload

    def test_device_totals_history_and_ports(self):
        end = int(time.time()) + 1
        start = end - 3600
        status, devices = self.get_json(f"/api/devices?start={start}&end={end}")
        self.assertEqual(200, status)
        device = next(row for row in devices["devices"] if row["ip"] == "192.0.2.222")
        self.assertEqual(3333, device["total_bytes"])
        status, history = self.get_json(f"/api/device-history?ip=192.0.2.222&start={start}&end={end}&bucket=300")
        self.assertEqual(200, status)
        self.assertEqual(1111, history["samples"][0]["upload_bytes"])
        status, ports = self.get_json(f"/api/device-ports?ip=192.0.2.222&start={start}&end={end}")
        self.assertEqual(200, status)
        self.assertEqual(443, ports["ports"][0]["port"])
        self.assertEqual(3333, ports["ports"][0]["total_bytes"])


if __name__ == "__main__":
    unittest.main()
