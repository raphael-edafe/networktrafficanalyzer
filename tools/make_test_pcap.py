"""Generate a synthetic demo.pcap that exercises every detector.

Run:  python tools/make_test_pcap.py
Then: python -c "import importlib,sys; sys.modules['net_analyzer']=importlib.import_module('net-analyzer'); from net_analyzer.cli import main; main(['--pcap','demo.pcap','--no-geo'])"

The crafted traffic (against my_ip 192.168.0.103) contains:
  * benign baseline traffic from 8.8.8.8 / 93.184.216.34
  * a VOLUME_SPIKE  (8.8.8.8 suddenly sends 120 packets)
  * a PORT_SCAN + SUSPICIOUS_PORT burst from 45.155.205.233
  * BEACONING       (91.92.240.10 phones home every 60s — caught behaviourally,
                     it is deliberately NOT on the blocklist)
  * EXFIL           (a big outbound transfer to 185.220.101.5)
  * THREAT_INTEL    (45.155.205.233 and 185.220.101.5 are on the demo blocklist)
"""
import os

from scapy.all import IP, TCP, Raw, wrpcap

MY = "192.168.0.103"
pkts = []


def add(t, src, dst, sport, dport, payload=b"", flags="S"):
    p = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    if payload:
        p = p / Raw(load=payload)
    p.time = float(t)
    pkts.append(p)


# --- benign baseline across windows 0..4 (slightly noisy counts so MAD > 0) ---
baseline_counts = [3, 5, 4, 6, 5]
for w, n in enumerate(baseline_counts):
    for i in range(n):
        add(w * 10 + i * 0.1, "8.8.8.8", MY, 443, 51000 + i, b"x" * 200, flags="PA")
    for i in range(2):
        add(w * 10 + i * 0.2, "93.184.216.34", MY, 443, 52000 + i, b"y" * 150, flags="PA")

# --- VOLUME_SPIKE: 8.8.8.8 floods 120 packets in window 5 (t=50..60) ---
for i in range(120):
    add(50 + i * 0.05, "8.8.8.8", MY, 443, 53000 + i, b"x" * 100, flags="PA")

# --- BEACONING: 91.92.240.10 contacts every 60s, very low jitter ---
for k in range(6):
    t = k * 60.0
    add(t, "91.92.240.10", MY, 8443, 49000, b"ping", flags="PA")
    add(t + 0.05, MY, "91.92.240.10", 49000, 8443, b"pong", flags="PA")

# --- PORT_SCAN + SUSPICIOUS_PORT from 45.155.205.233 (window t=60..70) ---
scan_ports = [20, 21, 22, 23, 25, 80, 110, 135, 139, 443, 445, 3389, 5900, 8080]
for i, dport in enumerate(scan_ports):
    add(65 + i * 0.05, "45.155.205.233", MY, 40000 + i, dport, flags="S")

# --- EXFIL: large outbound transfer to 185.220.101.5 (window t=60..70) ---
for i in range(60):
    add(66 + i * 0.01, MY, "185.220.101.5", 50500, 443, b"\x00" * 12000, flags="PA")

pkts.sort(key=lambda p: p.time)
out = os.path.join(os.path.dirname(__file__), "..", "demo.pcap")
out = os.path.abspath(out)
wrpcap(out, pkts)
print(f"Wrote {len(pkts)} packets -> {out}")
