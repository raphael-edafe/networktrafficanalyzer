"""Command-line entrypoint: live capture or offline PCAP replay."""
import argparse
import sys
import time

from .analyzer import Analyzer
from .config import Config
from .enrich import Enricher, ThreatIntel
from .notify import Notifier
from .storage import Storage


def build(args):
    cfg = Config.load(args.config)
    if args.no_geo:
        cfg.enable_geo = False
    storage = Storage(cfg.db_file)
    analyzer = Analyzer(cfg, storage, Enricher(cfg), ThreatIntel(cfg), Notifier(cfg))
    return cfg, storage, analyzer


def run_live(cfg, analyzer, iface):
    # Capture on a background thread (AsyncSniffer) so the main thread only sleeps
    # between windows. scapy's blocking sniff() swallows Ctrl+C; time.sleep() does
    # not — so this makes the interrupt actually work, and capture never pauses
    # while a window is being processed.
    from scapy.all import AsyncSniffer, get_working_ifaces
    names = [i.name for i in get_working_ifaces()]
    if iface and iface not in names:
        print(f"Interface {iface!r} not found. Available interfaces:")
        for n in names:
            print(f"  {n}")
        print("\nTip: pass one of the names above with --iface, e.g. --iface \"Wi-Fi\"")
        return
    print(f"Live capture on {iface or 'default iface'} — Ctrl+C to stop. "
          f"Alerts -> {cfg.log_file}, state -> {cfg.db_file}")
    sniffer = AsyncSniffer(prn=lambda p: analyzer.process_packet(p, time.time()),
                           iface=iface, store=False)
    sniffer.start()
    try:
        while True:
            time.sleep(cfg.window_seconds)
            analyzer.finalize_window(time.time())
    except KeyboardInterrupt:
        print("\nStopping…")
    finally:
        try:
            sniffer.stop()
        except Exception:
            pass
        analyzer.finalize_window(time.time())
        print("Stopped.")


def run_replay(cfg, analyzer, path):
    from scapy.all import PcapReader
    print(f"Replaying {path} (window={cfg.window_seconds}s)")
    window_end = None
    last = None
    with PcapReader(path) as reader:
        for pkt in reader:
            if not hasattr(pkt, "time"):
                continue
            now = float(pkt.time)
            last = now
            if window_end is None:
                window_end = now + cfg.window_seconds
            while now >= window_end:
                analyzer.finalize_window(window_end)
                window_end += cfg.window_seconds
            analyzer.process_packet(pkt, now)
    if last is not None:
        analyzer.finalize_window(window_end if window_end else last)
    c = analyzer.alert_counts
    print(f"\nReplay complete. Alerts — CRITICAL: {c['CRITICAL']}, "
          f"WARNING: {c['WARNING']}, INFO: {c['INFO']}")


def main(argv=None):
    p = argparse.ArgumentParser(prog="netanalyser",
                                description="Network traffic analyser / lightweight IDS")
    p.add_argument("-c", "--config", default="config.json", help="path to config.json")
    p.add_argument("--pcap", help="analyse a saved .pcap file instead of live capture")
    p.add_argument("--iface", help="network interface for live capture")
    p.add_argument("--no-geo", action="store_true", help="disable network geo lookups (offline)")
    p.add_argument("--list-interfaces", action="store_true", help="list capture interfaces and exit")
    args = p.parse_args(argv)

    if args.list_interfaces:
        from scapy.all import get_if_list
        print("\n".join(get_if_list()))
        return 0

    cfg, storage, analyzer = build(args)
    try:
        if args.pcap:
            run_replay(cfg, analyzer, args.pcap)
        else:
            run_live(cfg, analyzer, args.iface)
    finally:
        storage.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
