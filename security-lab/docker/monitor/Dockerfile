FROM ubuntu:22.04

# Traffic monitoring container
# Captures network traffic for analysis and PCAP generation

RUN apt-get update && apt-get install -y \
    tcpdump \
    tshark \
    python3 \
    python3-pip \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Install Python libraries for traffic parsing
RUN pip3 install --no-cache-dir \
    scapy \
    pyshark

RUN mkdir -p /pcaps /data /scripts

COPY monitor.sh /scripts/monitor.sh
RUN chmod +x /scripts/monitor.sh

WORKDIR /data

CMD ["tail", "-f", "/dev/null"]
