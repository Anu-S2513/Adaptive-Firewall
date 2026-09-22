import sys
import os

from scapy.all import sniff


# --------------------------------------------------
# Add project root to Python path
# --------------------------------------------------

project_root = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

sys.path.append(project_root)


# --------------------------------------------------
# Import SentinelAI modules
# --------------------------------------------------

from capture.parser import parse_packet
from ai.realtime_detector import analyze_packet


# --------------------------------------------------
# Statistics
# --------------------------------------------------

captured_count = 0
normal_count = 0
attack_count = 0


# --------------------------------------------------
# Packet callback
# --------------------------------------------------

def packet_callback(packet):

    global captured_count
    global normal_count
    global attack_count

    # Parse real Scapy packet
    parsed_packet = parse_packet(packet)

    # Ignore non-IP packets
    if parsed_packet is None:
        return

    captured_count += 1

    try:

        # Send packet through:
        # Flow → Features → ML → Firewall Decision
        result = analyze_packet(parsed_packet)

        # Flow is still collecting packets
        if result is None:
            return

        prediction = result["prediction"]
        probability = result["attack_probability"]
        firewall_action = result["firewall_action"]

        # ------------------------------------------
        # Count results
        # ------------------------------------------

        if prediction == "ATTACK":
            attack_count += 1
        else:
            normal_count += 1

        # ------------------------------------------
        # Display result
        # ------------------------------------------

        print("=" * 60)

        print(f"PACKET #{captured_count}")

        print(
            f"{parsed_packet['source_ip']}:"
            f"{parsed_packet['source_port']}"
        )

        print("        ↓")

        print(
            f"{parsed_packet['destination_ip']}:"
            f"{parsed_packet['destination_port']}"
        )

        print(
            f"\nProtocol: {parsed_packet['protocol']}"
        )

        print(
            f"Packet Size: "
            f"{parsed_packet['packet_size']} bytes"
        )

        print("\nML RESULT")

        print(
            f"Prediction: {prediction}"
        )

        print(
            f"Attack Probability: "
            f"{probability:.4f}"
        )

        print("\nADAPTIVE FIREWALL")

        print(
            f"Firewall Action: {firewall_action}"
        )

        print("-" * 60)

        print(
            f"Total Packets: {captured_count} | "
            f"NORMAL: {normal_count} | "
            f"ATTACK: {attack_count}"
        )

    except Exception as error:

        print(
            f"ML Analysis Error: {error}"
        )


# --------------------------------------------------
# Start Capture
# --------------------------------------------------

print("=" * 60)
print("       SENTINELAI - REAL TIME DETECTION")
print("=" * 60)

print("\nStatus: Starting packet capture...")
print("Open websites or use the internet normally.")
print("Press CTRL + C to stop.\n")


try:

    sniff(
        prn=packet_callback,
        store=False
    )


except KeyboardInterrupt:

    print("\n\nCapture stopped by user.")


finally:

    print("\n" + "=" * 60)

    print("FINAL STATISTICS")

    print("=" * 60)

    print(
        f"Total Packets Captured: "
        f"{captured_count}"
    )

    print(
        f"Normal Predictions: "
        f"{normal_count}"
    )

    print(
        f"Attack Predictions: "
        f"{attack_count}"
    )