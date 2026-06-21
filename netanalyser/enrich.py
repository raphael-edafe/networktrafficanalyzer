"""IP enrichment: geolocation (ipinfo.io) + threat-intel blocklist lookups."""
import ipaddress
import os

import requests


def is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def is_noise(ip: str) -> bool:
    """Network housekeeping that isn't a real 'peer': multicast (mDNS/SSDP),
    link-local, broadcast, loopback, reserved. We don't track or alert on these."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return (a.is_multicast or a.is_link_local or a.is_reserved
            or a.is_unspecified or a.is_loopback)


class Enricher:
    """Cached geo lookups. Falls back gracefully when offline or rate-limited."""

    def __init__(self, config):
        self.enabled = config.enable_geo
        self.token = config.ipinfo_token
        self.cache = {}

    def geo(self, ip: str) -> dict:
        if ip in self.cache:
            return self.cache[ip]
        if is_private(ip):
            result = {"display": "Local network", "org": "", "country": "", "lat": None, "lon": None}
            self.cache[ip] = result
            return result
        if not self.enabled:
            result = {"display": "(geo disabled)", "org": "", "country": "", "lat": None, "lon": None}
            self.cache[ip] = result
            return result
        try:
            url = f"https://ipinfo.io/{ip}/json"
            params = {"token": self.token} if self.token else None
            data = requests.get(url, params=params, timeout=2).json()
            country = data.get("country", "Unknown")
            org = data.get("org", "Unknown org")
            lat = lon = None
            if "loc" in data:
                try:
                    lat, lon = (float(x) for x in data["loc"].split(","))
                except (ValueError, TypeError):
                    pass
            result = {"display": f"{country}, {org}", "org": org.lower(),
                      "country": country, "lat": lat, "lon": lon}
        except Exception:
            result = {"display": "Lookup failed", "org": "", "country": "", "lat": None, "lon": None}
        self.cache[ip] = result
        return result

    @staticmethod
    def is_trusted_org(org_lower: str, keywords) -> bool:
        return any(k in org_lower for k in keywords)


class ThreatIntel:
    """Loads known-bad IPs/CIDRs from a local file and/or a remote feed at startup."""

    def __init__(self, config):
        self.ips = set()
        self.networks = []
        path = config.threat_blocklist_file
        if path and os.path.exists(path):
            with open(path) as f:
                self._ingest(f.read())
        if config.threat_blocklist_url:
            try:
                self._ingest(requests.get(config.threat_blocklist_url, timeout=5).text)
            except Exception:
                pass  # offline / unreachable feed is non-fatal

    def _ingest(self, text: str):
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", ";")):
                continue
            token = line.split()[0]
            try:
                if "/" in token:
                    self.networks.append(ipaddress.ip_network(token, strict=False))
                else:
                    ipaddress.ip_address(token)
                    self.ips.add(token)
            except ValueError:
                continue

    def __len__(self):
        return len(self.ips) + len(self.networks)

    def is_malicious(self, ip: str) -> bool:
        if ip in self.ips:
            return True
        if self.networks:
            try:
                addr = ipaddress.ip_address(ip)
                return any(addr in net for net in self.networks)
            except ValueError:
                return False
        return False
