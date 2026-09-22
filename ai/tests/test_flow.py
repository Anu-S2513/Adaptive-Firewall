import sys
import os

sys.path.append(
    os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )
)

from features.flow_aggregator import process_packet

# First packet: forward direction
packet1 = {
    "source_ip": "192.168.1.10",
    "destination_ip": "8.8.8.8",
    "source_port": 50000,
    "destination_port": 443,
    "protocol": "TCP",
    "packet_size": 100,
    "ttl": 64,
    "tcp_flags": "S"
}


# Second packet: forward direction
packet2 = {
    "source_ip": "192.168.1.10",
    "destination_ip": "8.8.8.8",
    "source_port": 50000,
    "destination_port": 443,
    "protocol": "TCP",
    "packet_size": 200,
    "ttl": 64,
    "tcp_flags": "A"
}


# Third packet: reverse direction
packet3 = {
    "source_ip": "8.8.8.8",
    "destination_ip": "192.168.1.10",
    "source_port": 443,
    "destination_port": 50000,
    "protocol": "TCP",
    "packet_size": 150,
    "ttl": 64,
    "tcp_flags": "A"
}


print("\nProcessing Packet 1...")
print(process_packet(packet1))

print("\nProcessing Packet 2...")
print(process_packet(packet2))

print("\nProcessing Packet 3...")
print(process_packet(packet3))