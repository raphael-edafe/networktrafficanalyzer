"""Backward-compatible entrypoint.

The project lives in the `net-analyzer` package. This shim keeps
the old `python sniff_test.py` muscle memory working (live capture). For PCAP
replay, interfaces, etc. use the CLI entrypoint directly.
"""
import importlib, sys
sys.modules['net_analyzer'] = importlib.import_module('net-analyzer')
from net_analyzer.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
