#!/bin/bash

# Network traffic monitoring script
# Captures traffic and generates PCAPs for analysis

INTERFACE=${INTERFACE:-eth0}
OUTPUT_DIR=${OUTPUT_DIR:-/pcaps}
DURATION=${DURATION:-300}  # Default 5 minutes

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_FILE="${OUTPUT_DIR}/capture_${TIMESTAMP}.pcap"

echo "Starting traffic capture on $INTERFACE"
echo "Output: $OUTPUT_FILE"
echo "Duration: $DURATION seconds"

tcpdump -i $INTERFACE -w $OUTPUT_FILE -G $DURATION -W 1

echo "Capture complete: $OUTPUT_FILE"
