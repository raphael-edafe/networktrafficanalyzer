# Network Traffic Analyser
#
# Build:
#   docker build -t netanalyser .
#
# Offline PCAP analysis (works anywhere, no special privileges):
#   docker run --rm -v "$PWD:/data" netanalyser --pcap /data/demo.pcap --no-geo
#
# Web dashboard (reads the DB written by the analyser):
#   docker run --rm -p 5000:5000 -v "$PWD:/data" --entrypoint python netanalyser dashboard.py
#
# Live capture needs host networking + raw-socket capability:
#   docker run --rm --net=host --cap-add=NET_RAW --cap-add=NET_ADMIN netanalyser --iface eth0
FROM python:3.12-slim

# libpcap is required by scapy for live capture.
RUN apt-get update && apt-get install -y --no-install-recommends libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

ENTRYPOINT ["python", "-m", "netanalyser"]
CMD ["--help"]
