FROM ubuntu:22.04

# Attacker container with common security testing tools
# Used for controlled attack scenario execution

RUN apt-get update && apt-get install -y \
    nmap \
    hping3 \
    netcat-openbsd \
    tcpdump \
    curl \
    wget \
    python3 \
    python3-pip \
    openssh-client \
    dnsutils \
    iputils-ping \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Install Python libraries for attack scripts
RUN pip3 install --no-cache-dir \
    scapy \
    requests

# Create directories for scenarios and output
RUN mkdir -p /scenarios /pcaps /output

WORKDIR /scenarios

# Default command keeps container running
CMD ["tail", "-f", "/dev/null"]
