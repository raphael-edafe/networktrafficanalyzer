"""End-to-end: push crafted scapy packets through the analyzer (no capture privileges
needed) and assert the right detectors fired. This is the integration safety net."""
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.all import IP, TCP, Raw

from netanalyser.analyzer import Analyzer
from netanalyser.config import Config
from netanalyser.enrich import Enricher, ThreatIntel
from netanalyser.storage import Storage

MY = "10.0.0.5"


def cfg():
    return Config.from_dict({
        "my_ip": MY, "window_seconds": 10, "enable_geo": False,
        "threat_blocklist_file": "", "anomaly_min_samples": 3,
        "exfil_bytes_threshold": 500000, "port_scan_threshold": 5,
    })


class TestAnalyzerEndToEnd(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.cfg = cfg()
        self.cfg.log_file = os.path.join(self.dir, "alerts.log")
        self.db = Storage(os.path.join(self.dir, "t.db"))
        self.threat = ThreatIntel(self.cfg)
        self.threat.ips.add("185.220.101.5")
        self.an = Analyzer(self.cfg, self.db, Enricher(self.cfg), self.threat, notifier=None)

    def tearDown(self):
        self.db.close()
        shutil.rmtree(self.dir, ignore_errors=True)

    def categories(self):
        return {r["category"] for r in self.db.recent_alerts(200)}

    def severities_for(self, category):
        return {r["severity"] for r in self.db.recent_alerts(200) if r["category"] == category}

    def test_port_scan_and_suspicious_port(self):
        for i, dport in enumerate([20, 21, 22, 23, 80, 135, 445, 3389, 8080]):
            p = IP(src="45.155.205.233", dst=MY) / TCP(sport=40000 + i, dport=dport, flags="S")
            self.an.process_packet(p, 1.0 + i * 0.01)
        self.an.finalize_window(10.0)
        cats = self.categories()
        self.assertIn("PORT_SCAN", cats)
        self.assertIn("SUSPICIOUS_PORT", cats)

    def test_threat_intel_hit(self):
        p = IP(src="185.220.101.5", dst=MY) / TCP(sport=1234, dport=443, flags="S")
        self.an.process_packet(p, 1.0)
        self.an.finalize_window(10.0)
        self.assertIn("THREAT_INTEL", self.categories())

    def test_exfil_outbound(self):
        for i in range(60):
            p = IP(src=MY, dst="9.9.9.9") / TCP(sport=5000, dport=443, flags="PA") / Raw(b"\x00" * 12000)
            self.an.process_packet(p, 1.0 + i * 0.01)
        self.an.finalize_window(10.0)
        self.assertIn("EXFIL", self.categories())

    def _replay(self, packets, window=10.0):
        """Drive packets through the analyzer exactly like CLI replay, cutting
        (and finalizing empty) windows as packet time advances."""
        window_end = None
        for t, p in packets:
            if window_end is None:
                window_end = t + window
            while t >= window_end:
                self.an.finalize_window(window_end)
                window_end += window
            self.an.process_packet(p, t)
        if window_end is not None:
            self.an.finalize_window(window_end)

    def test_beaconing_across_windows(self):
        # 8 regular contacts 60s apart, with quiet gaps between -> beaconing (WARNING).
        pkts = [(k * 60.0, IP(src="91.92.240.10", dst=MY) / TCP(dport=8443, flags="PA"))
                for k in range(8)]
        self._replay(pkts)
        self.assertIn("BEACONING", self.categories())
        self.assertEqual(self.severities_for("BEACONING"), {"WARNING"})

    def test_steady_stream_is_not_beaconing(self):
        # Same peer present every single window (no gaps) must NOT be called a beacon.
        pkts = [(float(t), IP(src="91.92.240.10", dst=MY) / TCP(dport=8443, flags="PA"))
                for t in range(0, 100, 2)]
        self._replay(pkts)
        self.assertNotIn("BEACONING", self.categories())

    def test_beacon_to_trusted_org_is_suppressed(self):
        # Pre-label the peer as a trusted cloud org -> its periodic chatter is ignored.
        self.db.upsert_known_ip("91.92.240.10", "t", org="as8075 microsoft corporation")
        pkts = [(k * 60.0, IP(src="91.92.240.10", dst=MY) / TCP(dport=8443, flags="PA"))
                for k in range(8)]
        self._replay(pkts)
        self.assertNotIn("BEACONING", self.categories())

    def test_beacon_to_blocklisted_ip_is_critical(self):
        self.threat.ips.add("91.92.240.10")
        pkts = [(k * 60.0, IP(src="91.92.240.10", dst=MY) / TCP(dport=8443, flags="PA"))
                for k in range(8)]
        self._replay(pkts)
        self.assertIn("CRITICAL", self.severities_for("BEACONING"))

    def test_multicast_is_ignored(self):
        # mDNS/SSDP-style multicast must never be tracked or alerted on.
        pkts = [(k * 60.0, IP(src=MY, dst="239.255.255.250") / TCP(dport=1900, flags="PA"))
                for k in range(8)]
        self._replay(pkts)
        self.assertNotIn("BEACONING", self.categories())
        self.assertNotIn("NEW_IP", self.categories())


if __name__ == "__main__":
    unittest.main()
