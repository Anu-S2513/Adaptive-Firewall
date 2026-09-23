
import sys
import os
import time

from scapy.all import IP, TCP

# ==========================================
# ADD PROJECT ROOT
# ==========================================

project_root = os.path.dirname(
    os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))
    )
)

sys.path.append(project_root)


# ==========================================
# IMPORT SENTINELAI MODULES
# ==========================================

from capture.parser import parse_packet
from ai.realtime_detector import analyze_packet


# ==========================================
# CREATE SIMULATED PACKET
# ==========================================

def create_packet():

    packet = (
        IP(
            src="192.168.1.100",
            dst="192.168.1.200"
        )
        /
        TCP(
            sport=12345,
            dport=21,
            flags="S"
        )
    )

    return packet


# ==========================================
# MAIN TEST
# ==========================================

print("=" * 60)
print("       SENTINELAI - REAL-TIME PIPELINE TEST")
print("=" * 60)

print()
print("Creating simulated network packets...")

for i in range(5):

    packet = create_packet()

    parsed_packet = parse_packet(packet)

    if parsed_packet is None:
        print("Packet parsing failed.")
        sys.exit(1)

    print(
        f"Packet {i + 1}/5 parsed successfully."
    )

    result = analyze_packet(
        parsed_packet
    )

    if result is None:
        print(
            "Waiting for enough packets "
            "to create a flow..."
        )
    else:

        print()
        print("-" * 60)
        print("REAL-TIME PIPELINE RESULT")
        print("-" * 60)

        print(
            f"Prediction         : "
            f"{result['prediction']}"
        )

        print(
            f"Attack Probability : "
            f"{result['attack_probability']:.4f}"
        )

        print(
            f"Firewall Action    : "
            f"{result['firewall_action']}"
        )

        print(
            f"Enforcement Status : "
            f"{result['enforcement_status']}"
        )

        print(
            f"Message            : "
            f"{result['enforcement_message']}"
        )

        print("-" * 60)

    time.sleep(0.1)


print()
print("=" * 60)
print("REAL-TIME PIPELINE TEST COMPLETED")
print("=" * 60)

