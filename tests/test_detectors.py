import os
import sys
import unittest
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import importlib
sys.modules['net_analyzer'] = importlib.import_module('net-analyzer')

from net_analyzer import detectors
from net_analyzer.models import FlowRecord

BEACON_CFG = SimpleNamespace(beacon_min_hits=6, beacon_min_interval=5.0,
                             beacon_max_interval=3600.0, beacon_max_cv=0.08)


class TestDetectors(unittest.TestCase):
    def test_port_scan_fires_above_threshold(self):
        rec = FlowRecord(ip="203.0.113.66", ports=set(range(20, 35)))
        alerts = detectors.detect_port_scan(rec, threshold=5)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].category, "PORT_SCAN")

    def test_port_scan_quiet_below_threshold(self):
        rec = FlowRecord(ip="203.0.113.66", ports={80, 443})
        self.assertEqual(detectors.detect_port_scan(rec, threshold=5), [])

    def test_suspicious_ports(self):
        rec = FlowRecord(ip="9.9.9.9", ports={80, 3389, 445})
        cats = detectors.detect_suspicious_ports(rec, {21, 23, 445, 3389, 5900})
        self.assertEqual({a.message.split("port ")[1].split()[0] for a in cats}, {"445", "3389"})

    def test_volume_anomaly_zscore(self):
        rec = FlowRecord(ip="8.8.8.8", packet_count=120)
        history = [3, 5, 4, 6, 5]
        alerts = detectors.detect_volume_anomaly(rec, history, 3.5, 4, min_packets=50)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].category, "VOLUME_SPIKE")

    def test_volume_anomaly_needs_enough_history(self):
        rec = FlowRecord(ip="8.8.8.8", packet_count=120)
        self.assertEqual(detectors.detect_volume_anomaly(rec, [3, 4], 3.5, 4, 50), [])

    def test_volume_anomaly_ignores_normal(self):
        rec = FlowRecord(ip="8.8.8.8", packet_count=6)
        self.assertEqual(detectors.detect_volume_anomaly(rec, [3, 5, 4, 6, 5], 3.5, 4, 50), [])

    def test_volume_anomaly_respects_min_packets_floor(self):
        # Statistically a huge spike (baseline 1 -> 20), but below the absolute floor.
        rec = FlowRecord(ip="8.8.8.8", packet_count=20)
        self.assertEqual(detectors.detect_volume_anomaly(rec, [1, 1, 1, 1], 3.5, 4, 50), [])

    def test_exfil(self):
        self.assertEqual(detectors.detect_exfil(FlowRecord(ip="x", bytes_out=10), 500000), [])
        big = detectors.detect_exfil(FlowRecord(ip="x", bytes_out=700000), 500000)
        self.assertEqual(big[0].category, "EXFIL")

    def test_beacon_regular_is_flagged(self):
        alert = detectors.detect_beacon("198.51.100.23", [0, 60, 120, 180, 240, 300], BEACON_CFG)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.category, "BEACONING")
        self.assertEqual(alert.severity, "WARNING")   # CRITICAL only when also blocklisted
        self.assertGreater(alert.confidence, 0.8)

    def test_beacon_jittery_is_ignored(self):
        self.assertIsNone(
            detectors.detect_beacon("1.2.3.4", [0, 10, 60, 61, 200, 260], BEACON_CFG))

    def test_beacon_too_few_hits(self):
        self.assertIsNone(detectors.detect_beacon("1.2.3.4", [0, 60, 120], BEACON_CFG))


if __name__ == "__main__":
    unittest.main()
