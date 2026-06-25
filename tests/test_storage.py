import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import importlib
sys.modules['net_analyzer'] = importlib.import_module('net-analyzer')

from net_analyzer.models import FlowRecord
from net_analyzer.storage import Storage


class TestStorage(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.db = Storage(os.path.join(self.dir, "t.db"))

    def tearDown(self):
        self.db.close()
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_window_and_history(self):
        for i, n in enumerate([4, 5, 6]):
            wid = self.db.add_window(f"t{i}", float(i))
            self.db.add_traffic(wid, FlowRecord(ip="8.8.8.8", packet_count=n, byte_count=n * 100))
        self.assertEqual(sorted(self.db.get_ip_packet_history("8.8.8.8", 10)), [4, 5, 6])

    def test_known_ip_upsert(self):
        self.assertEqual(self.db.known_ip_count(), 0)
        self.db.upsert_known_ip("1.2.3.4", "now", country="US", org="acme")
        self.db.upsert_known_ip("1.2.3.4", "later")  # should not wipe country/org
        row = self.db.get_known_ip("1.2.3.4")
        self.assertEqual(row["country"], "US")
        self.assertEqual(row["last_seen"], "later")
        self.assertEqual(self.db.known_ip_count(), 1)

    def test_beacon_contacts_trim(self):
        for t in range(40):
            self.db.add_beacon_contact("9.9.9.9", float(t), keep=32)
        contacts = self.db.get_beacon_contacts("9.9.9.9")
        self.assertEqual(len(contacts), 32)
        self.assertEqual(contacts[-1], 39.0)   # newest retained
        self.assertEqual(contacts[0], 8.0)     # oldest trimmed away

    def test_alerts_and_summary(self):
        self.db.add_alert("t", 1.0, "CRITICAL", "PORT_SCAN", "1.2.3.4", "scan", 0.9)
        self.db.add_alert("t", 2.0, "WARNING", "VOLUME_SPIKE", "8.8.8.8", "spike")
        s = self.db.summary()
        self.assertEqual(s["critical"], 1)
        self.assertEqual(s["warning"], 1)
        self.assertEqual(s["total_alerts"], 2)


if __name__ == "__main__":
    unittest.main()
