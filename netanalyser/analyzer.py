"""Core engine: turns packets into windowed flow records and runs the detectors.

Time is threaded through explicitly (`now`) so the exact same code path drives
both live capture (now = wall clock) and PCAP replay (now = packet timestamp).
"""
import threading
from datetime import datetime

from scapy.layers.inet import IP, TCP

from . import detectors
from .enrich import Enricher, ThreatIntel, is_noise, is_private
from .models import FlowRecord


class Analyzer:
    def __init__(self, config, storage, enricher=None, threatintel=None, notifier=None):
        self.cfg = config
        self.db = storage
        self.enricher = enricher if enricher is not None else Enricher(config)
        self.threat = threatintel if threatintel is not None else ThreatIntel(config)
        self.notifier = notifier
        self.window = {}                 # peer ip -> FlowRecord
        self._lock = threading.Lock()    # guards self.window (capture thread vs window thread)
        self._cooldown = {}              # (category, ip) -> last epoch alerted
        self._prev_active = set()        # external peers seen in the previous window (beacon edges)
        # If the DB has never seen an IP, treat the first window as baseline-seeding
        # (don't scream "NEW IP" about every host on the network the first time).
        self.first_run = self.db.known_ip_count() == 0
        self.alert_counts = {"INFO": 0, "WARNING": 0, "CRITICAL": 0}

    # ---- packet ingestion ---------------------------------------------------
    def process_packet(self, packet, now: float):
        if not packet.haslayer(IP):
            return
        ip = packet[IP]
        src, dst, length = ip.src, ip.dst, len(packet)
        if src == self.cfg.my_ip and dst == self.cfg.my_ip:
            return  # loopback

        inbound = dst == self.cfg.my_ip
        outbound = src == self.cfg.my_ip
        peer = src if inbound else dst if outbound else src  # passive obs -> count the sender

        if peer in self.cfg.ignored_ips or is_noise(peer):
            return

        # Count only inbound SYN-without-ACK packets toward the port-scan tally: those
        # are connection *attempts*. Counting return/established traffic would make any
        # busy server look like it's being port-scanned.
        syn_port = None
        if inbound and packet.haslayer(TCP):
            flags = int(packet[TCP].flags)
            if (flags & 0x02) and not (flags & 0x10):
                syn_port = int(packet[TCP].dport)

        with self._lock:
            rec = self.window.get(peer)
            if rec is None:
                rec = self.window[peer] = FlowRecord(ip=peer, is_local=is_private(peer))
            rec.packet_count += 1
            rec.byte_count += length
            if inbound:
                rec.bytes_in += length
                if syn_port is not None:
                    rec.ports.add(syn_port)
            elif outbound:
                rec.bytes_out += length

    # ---- window finalisation ------------------------------------------------
    def finalize_window(self, now: float):
        # Atomically take the window and hand the capture thread a fresh one, so the
        # (potentially slow) detector/DB work below never blocks packet capture.
        with self._lock:
            window = self.window
            self.window = {}

        ts = datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S")
        window_id = self.db.add_window(ts, now)
        active_external = []

        print(f"\n--- Window {ts} ({len(window)} active peers) ---")
        for ip, rec in window.items():
            print(f"{ip}: {rec.packet_count} pkts, {rec.byte_count} bytes "
                  f"(in {rec.bytes_in} / out {rec.bytes_out})")

            history = self.db.get_ip_packet_history(ip, self.cfg.anomaly_min_samples + 6)
            self.db.add_traffic(window_id, rec)

            if not rec.is_local:
                active_external.append(ip)

            for alert in self._run_detectors(rec, history, now):
                self._emit(alert, now)

        # Beaconing is judged per external peer across windows. Record a contact only
        # on the rising edge (peer absent last window) so steady streams don't look
        # periodic — genuine beacons go quiet between check-ins.
        current_active = set(active_external)
        for ip in active_external:
            if ip not in self._prev_active:
                self.db.add_beacon_contact(ip, now, self.cfg.beacon_history)
                # Don't bother flagging periodic chatter to well-known cloud/CDN orgs —
                # that's almost always telemetry/keepalive, not C2.
                known = self.db.get_known_ip(ip)
                org = (known["org"] if known else "") or ""
                if Enricher.is_trusted_org(org, self.cfg.trusted_org_keywords):
                    continue
                contacts = self.db.get_beacon_contacts(ip)
                alert = detectors.detect_beacon(ip, contacts, self.cfg)
                if alert:
                    # A beacon to a known-malicious IP is the real deal -> CRITICAL.
                    if self.threat.is_malicious(ip):
                        alert.severity = "CRITICAL"
                    self._emit(alert, now)
        self._prev_active = current_active

        self.first_run = False

    def _run_detectors(self, rec, history, now):
        alerts = []
        # Threat-intel hit (cheap set lookup) — only meaningful for external peers.
        if not rec.is_local and self.threat.is_malicious(rec.ip):
            alerts.append(self._threat_alert(rec.ip))

        # New-IP detection (with geo-aware severity).
        if not rec.is_local:
            known = self.db.get_known_ip(rec.ip)
            if known is None:
                geo = self.enricher.geo(rec.ip)
                if not self.first_run:
                    trusted = Enricher.is_trusted_org(geo["org"], self.cfg.trusted_org_keywords)
                    alerts.append(self._new_ip_alert(rec.ip, trusted))
                self.db.upsert_known_ip(
                    rec.ip, self._ts(now), geo["country"], geo["org"],
                    geo["lat"], geo["lon"], int(self.threat.is_malicious(rec.ip)))
            else:
                self.db.upsert_known_ip(rec.ip, self._ts(now))

        alerts += detectors.detect_suspicious_ports(rec, self.cfg.suspicious_ports)
        alerts += detectors.detect_port_scan(rec, self.cfg.port_scan_threshold)
        alerts += detectors.detect_volume_anomaly(
            rec, history, self.cfg.anomaly_z_threshold, self.cfg.anomaly_min_samples,
            self.cfg.anomaly_min_packets)
        alerts += detectors.detect_exfil(rec, self.cfg.exfil_bytes_threshold)
        return alerts

    # ---- alert emission -----------------------------------------------------
    def _emit(self, alert, now: float):
        key = (alert.category, alert.ip)
        last = self._cooldown.get(key)
        if last is not None and (now - last) < self.cfg.alert_cooldown_seconds:
            return  # rate-limit identical alerts
        self._cooldown[key] = now

        geo_display = ""
        if alert.ip and not is_private(alert.ip):
            geo_display = f" [{self.enricher.geo(alert.ip)['display']}]"
        conf = f" (conf {alert.confidence})" if alert.confidence is not None else ""
        line = f"[{self._ts(now)}] [{alert.severity}] {alert.message}{geo_display}{conf}"
        print(line)

        with open(self.cfg.log_file, "a") as f:
            f.write(line + "\n")
        self.db.add_alert(self._ts(now), now, alert.severity, alert.category,
                          alert.ip, alert.message + geo_display, alert.confidence)
        self.alert_counts[alert.severity] = self.alert_counts.get(alert.severity, 0) + 1
        if self.notifier:
            self.notifier.send(alert)

    def _threat_alert(self, ip):
        from .models import Alert
        return Alert("CRITICAL", "THREAT_INTEL",
                     f"{ip} is on a known-malicious blocklist", ip=ip)

    def _new_ip_alert(self, ip, trusted):
        from .models import Alert
        sev = "INFO" if trusted else "WARNING"
        return Alert(sev, "NEW_IP", f"NEW IP: {ip} has never been seen before", ip=ip)

    @staticmethod
    def _ts(now: float) -> str:
        return datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S")
