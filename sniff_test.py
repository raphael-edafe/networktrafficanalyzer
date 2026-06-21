"""Backward-compatible entrypoint.

The project has been restructured into the `netanalyser` package. This shim keeps
the old `python sniff_test.py` muscle memory working (live capture). For PCAP
replay, interfaces, etc. use the CLI:  python -m netanalyser --help
"""
from netanalyser.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
