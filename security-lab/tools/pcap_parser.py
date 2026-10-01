#!/usr/bin/env python3

"""
PCAP Parser for Intriqo

Parses PCAP files and extracts network flows in a format compatible
with the Java NetworkFlow domain model.

Outputs JSON that can be consumed by the detection engine for testing.
"""

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any
from collections import defaultdict

try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP
except ImportError:
    print("Error: scapy not installed. Install with: pip3 install scapy")
    sys.exit(1)


class NetworkFlowExtractor:
    """Extracts network flows from PCAP files."""
    
    PROTOCOL_MAP = {
        6: "TCP",
        17: "UDP",
        1: "ICMP",
    }
    
    def __init__(self, pcap_file: str):
        self.pcap_file = pcap_file
        self.flows = defaultdict(lambda: {
            'packets': 0,
            'bytes': 0,
            'first_seen': None,
            'last_seen': None,
        })
    
    def parse(self) -> List[Dict[str, Any]]:
        """Parse PCAP and extract flows."""
        print(f"Parsing PCAP: {self.pcap_file}")
        
        try:
            packets = rdpcap(self.pcap_file)
        except Exception as e:
            print(f"Error reading PCAP: {e}")
            return []
        
        print(f"Processing {len(packets)} packets...")
        
        for packet in packets:
            if IP in packet:
                self._process_packet(packet)
        
        # Convert flows to NetworkFlow format
        network_flows = []
        for flow_key, flow_data in self.flows.items():
            network_flow = self._to_network_flow(flow_key, flow_data)
            if network_flow:
                network_flows.append(network_flow)
        
        print(f"Extracted {len(network_flows)} flows")
        return network_flows
    
    def _process_packet(self, packet):
        """Process a single packet and update flow statistics."""
        ip = packet[IP]
        
        # Determine protocol
        if TCP in packet:
            transport = packet[TCP]
            proto_num = 6
            src_port = transport.sport
            dst_port = transport.dport
        elif UDP in packet:
            transport = packet[UDP]
            proto_num = 17
            src_port = transport.sport
            dst_port = transport.dport
        elif ICMP in packet:
            proto_num = 1
            src_port = 0
            dst_port = 0
        else:
            return  # Skip other protocols
        
        # Create flow key (5-tuple)
        flow_key = (
            ip.src,
            ip.dst,
            src_port,
            dst_port,
            proto_num
        )
        
        # Update flow statistics
        flow = self.flows[flow_key]
        flow['packets'] += 1
        flow['bytes'] += len(packet)
        
        timestamp = datetime.fromtimestamp(float(packet.time))
        if flow['first_seen'] is None:
            flow['first_seen'] = timestamp
        flow['last_seen'] = timestamp
    
    def _to_network_flow(self, flow_key, flow_data) -> Dict[str, Any]:
        """Convert internal flow representation to NetworkFlow JSON."""
        src_ip, dst_ip, src_port, dst_port, proto_num = flow_key
        
        # Calculate duration
        if flow_data['first_seen'] and flow_data['last_seen']:
            duration_ms = int((flow_data['last_seen'] - flow_data['first_seen']).total_seconds() * 1000)
        else:
            duration_ms = 0
        
        protocol = self.PROTOCOL_MAP.get(proto_num, "OTHER")
        
        return {
            "timestamp": flow_data['first_seen'].isoformat() + "Z",
            "sourceAddress": src_ip,
            "destinationAddress": dst_ip,
            "sourcePort": src_port,
            "destinationPort": dst_port,
            "protocol": protocol,
            "packetCount": flow_data['packets'],
            "byteCount": flow_data['bytes'],
            "durationMillis": duration_ms
        }


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 pcap_parser.py <pcap_file> [output_file]")
        print("\nExamples:")
        print("  python3 pcap_parser.py capture.pcap")
        print("  python3 pcap_parser.py capture.pcap flows.json")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    if not Path(pcap_file).exists():
        print(f"Error: File not found: {pcap_file}")
        sys.exit(1)
    
    # Extract flows
    extractor = NetworkFlowExtractor(pcap_file)
    flows = extractor.parse()
    
    # Prepare output
    output = {
        "source": pcap_file,
        "extractedAt": datetime.now().isoformat() + "Z",
        "flowCount": len(flows),
        "flows": flows
    }
    
    # Write output
    if output_file:
        with open(output_file, 'w') as f:
            json.dump(output, f, indent=2)
        print(f"\nFlows written to: {output_file}")
    else:
        print("\n" + "="*60)
        print("EXTRACTED FLOWS (JSON)")
        print("="*60)
        print(json.dumps(output, indent=2))
    
    # Print summary
    print("\n" + "="*60)
    print("FLOW SUMMARY")
    print("="*60)
    
    # Group by source IP
    flows_by_source = defaultdict(lambda: defaultdict(set))
    for flow in flows:
        src = flow['sourceAddress']
        dst_port = flow['destinationPort']
        dst = flow['destinationAddress']
        flows_by_source[src]['ports'].add(dst_port)
        flows_by_source[src]['targets'].add(dst)
    
    print(f"\nTotal flows: {len(flows)}")
    print(f"Unique source IPs: {len(flows_by_source)}")
    print()
    
    for src_ip in sorted(flows_by_source.keys()):
        data = flows_by_source[src_ip]
        distinct_ports = len(data['ports'])
        distinct_targets = len(data['targets'])
        print(f"Source: {src_ip}")
        print(f"  Distinct destination ports: {distinct_ports}")
        print(f"  Distinct targets: {distinct_targets}")
        
        if distinct_ports >= 10:
            print(f"  ⚠️  LIKELY PORT SCAN (threshold: 10 ports)")
        print()


if __name__ == "__main__":
    main()
