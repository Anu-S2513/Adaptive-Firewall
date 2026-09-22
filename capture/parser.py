from scapy.all import IP, TCP, UDP, ICMP
from datetime import datetime


def parse_packet(packet):
    """
    Convert a Scapy packet into a structured dictionary.
    """

    # Ignore packets that do not contain an IP layer
    if not packet.haslayer(IP):
        return None

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst

    ttl = packet[IP].ttl

    # Default values
    protocol = "OTHER"
    source_port = 0
    destination_port = 0
    tcp_flags = ""

    # TCP packet
    if packet.haslayer(TCP):

        protocol = "TCP"
        source_port = packet[TCP].sport
        destination_port = packet[TCP].dport
        tcp_flags = str(packet[TCP].flags)

    # UDP packet
    elif packet.haslayer(UDP):

        protocol = "UDP"
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport

    # ICMP packet
    elif packet.haslayer(ICMP):

        protocol = "ICMP"

    return {
        "timestamp": datetime.now(),

        "source_ip": source_ip,
        "destination_ip": destination_ip,

        "source_port": source_port,
        "destination_port": destination_port,

        "protocol": protocol,

        "packet_size": len(packet),

        "ttl": ttl,

        "tcp_flags": tcp_flags
    }