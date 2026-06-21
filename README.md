# Network Traffic Analyzer

[![tests](https://github.com/raphael-edafe/networktrafficanalyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/raphael-edafe/networktrafficanalyzer/actions/workflows/ci.yml)

A lightweight, host-based **intrusion-detection system** in Python. It captures
live network traffic (or replays a saved `.pcap`), aggregates it into time
windows, and runs a set of behavioural detectors that flag the things that
actually matter on a home or small-office network: port scans, malware
**beaconing/C2**, data **exfiltration**, traffic from **known-malicious IPs**,
and statistically anomalous volume spikes — surfaced live on a web dashboard.

> Built for **authorised** monitoring of your own network and for security
> learning. Live capture requires admin/root (raw sockets).

---

## Highlights

- **Live capture *and* offline PCAP replay** — same engine, so detections are
  reproducible and testable without admin rights or waiting for real traffic.
- **Behavioural detection, not just thresholds:**
  - **Beaconing / C2** — finds periodic "phone-home" traffic by measuring the
    jitter (coefficient of variation) of inter-contact intervals.
  - **Robust volume anomalies** — modified *z*-score (median/MAD), which a single
    spike can't poison the way a plain moving average can.
  - **Port-scan** detection on inbound SYN attempts (ignores return traffic).
  - **Data exfiltration** — large outbound transfers to a single peer.
  - **Threat intelligence** — IP/CIDR blocklist (local file and/or remote feed).
  - **New-IP** detection with geo/org-aware severity.
- **Persistent baselines** in SQLite — "new IP" and volume baselines survive
  restarts (the original kept everything in memory and forgot on every restart).
- **Live web dashboard** — Chart.js traffic graphs, top talkers, severity
  breakdown, and a colour-coded alert feed, polling a JSON API.
- **Webhook notifications** (Discord/Slack-style) for high-severity alerts.
- **Tested** — 19 unit + integration tests, no admin rights needed.

---

## Architecture

```
                 ┌──────────────────────── netanalyser package ────────────────────────┐
  live NIC ─┐    │                                                                      │
            ├──▶ │  cli ──▶ analyzer ──▶ detectors (portscan / beacon / exfil / volume  │
  .pcap  ───┘    │            │                       / threat-intel / new-IP)          │
                 │            ├──▶ enrich (geo + threat-intel blocklist)                 │
                 │            └──▶ storage (SQLite: baselines, windows, alerts) ◀──┐     │
                 └──────────────────────────────┬──────────────────────────────────┘    │
                                                 │ writes                                 │
                              alerts.log  ◀──────┤                                        │
                              webhook     ◀──────┘                                        │
                                                 │ reads                                  │
                              dashboard.py (Flask + Chart.js)  ◀──────────────────────────┘
```

The sniffer and the dashboard share one SQLite database (WAL mode), so the
dashboard can read while capture is writing — no more racy JSON hand-off file.

---

## Quickstart

```bash
pip install -r requirements.txt

# 1) See it work immediately — generate a synthetic capture and analyse it:
python tools/make_test_pcap.py
python -m netanalyser --pcap demo.pcap --no-geo

# 2) Watch it live on the dashboard (separate terminal):
python dashboard.py            # http://127.0.0.1:5000

# 3) Live capture (needs admin/root; Windows needs Npcap installed):
python -m netanalyser --iface "Wi-Fi"
python -m netanalyser --list-interfaces      # if unsure of the name
```

The demo capture deliberately contains a port scan, a malware beacon, an
exfiltration burst, a volume spike, and traffic to blocklisted IPs — so every
detector lights up.

---

## Detections

| Category          | What it catches                                   | Severity |
|-------------------|---------------------------------------------------|----------|
| `THREAT_INTEL`    | Peer on a known-malicious IP/CIDR blocklist       | CRITICAL |
| `PORT_SCAN`       | One peer hitting many ports (inbound SYNs)        | CRITICAL |
| `SUSPICIOUS_PORT` | Inbound connection to FTP/Telnet/SMB/RDP/VNC      | CRITICAL |
| `BEACONING`       | Regular, low-jitter periodic contact (C2 pattern) | WARNING* |
| `EXFIL`           | Large outbound transfer to a single peer          | WARNING  |
| `VOLUME_SPIKE`    | Packet count far above the robust baseline        | WARNING  |
| `NEW_IP`          | First-ever contact (INFO if a trusted org)        | INFO/WARN|

\* Periodic traffic is common on real networks (keepalives, telemetry), so beaconing
is a WARNING by default and is **upgraded to CRITICAL only when the peer is also on the
threat blocklist**. Beacons to trusted cloud orgs, and all multicast/broadcast/link-local
"network noise", are suppressed entirely.

---

## Configuration (`config.json`)

| Key | Meaning |
|-----|---------|
| `my_ip` | IP of the host you're protecting (defines in/out direction) |
| `window_seconds` | Aggregation window length |
| `suspicious_ports` | Sensitive service ports to alert on |
| `port_scan_threshold` | Distinct ports before a scan is declared |
| `anomaly_z_threshold` / `anomaly_min_samples` / `anomaly_min_packets` | Volume-anomaly sensitivity / warm-up / absolute floor |
| `beacon_*` | Beacon hit count, interval bounds, max jitter (CV) |
| `trusted_org_keywords` | Orgs treated as routine: their new IPs are INFO and their beacons are suppressed |
| `exfil_bytes_threshold` | Outbound bytes per window that count as exfil |
| `threat_blocklist_file` / `threat_blocklist_url` | Local + remote blocklist sources |
| `notify_webhook_url` / `notify_min_severity` | Webhook alerts (Discord/Slack) |
| `enable_geo` / `ipinfo_token` | ipinfo.io enrichment (token lifts rate limits) |
| `alert_cooldown_seconds` | Suppress identical repeat alerts |

For real threat intel, point `threat_blocklist_url` at a live feed (e.g. FireHOL
level1, Spamhaus DROP, an AbuseIPDB export).

---

## Tests

```bash
python -m unittest discover -s tests -v
```

`test_detectors.py` covers the pure detection maths; `test_storage.py` covers
persistence; `test_analyzer.py` pushes crafted packets end-to-end through the
engine (including beaconing across windows) — all without capturing live traffic.

---

## Docker

```bash
docker build -t netanalyser .
docker run --rm -v "$PWD:/data" netanalyser --pcap /data/demo.pcap --no-geo
```

See the comments in the `Dockerfile` for the dashboard and live-capture commands.

---

## Limitations & scope

This is a learning / home-network tool, not a hardened production IDS. Specifically:

- **Host-based:** it only sees traffic to/from the machine it runs on. To watch a whole
  network you'd need a SPAN/mirror port or to run it on a gateway.
- **The bundled blocklist is a tiny sample.** For real protection, point
  `threat_blocklist_url` at a live feed (FireHOL, Spamhaus DROP, AbuseIPDB).
- **The dashboard has no authentication** — keep it bound to `localhost` (the default);
  don't expose it to a network.
- **Live capture needs admin/root**, plus Npcap on Windows.
- **Geo/threat enrichment depends on a third-party API** (ipinfo.io) and degrades
  gracefully when offline.
- **SQLite + per-window processing** is fine for a host; it isn't built for
  high-throughput backbone traffic.

---

