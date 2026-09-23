
import sys
import os
import time

from scapy.all import sniff

# ============================================================
# PROJECT PATH
# ============================================================

project_root = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

sys.path.append(project_root)

# ============================================================
# SENTINELAI MODULES
# ============================================================

from capture.parser import parse_packet
from ai.realtime_detector import analyze_packet


# ============================================================
# STATISTICS
# ============================================================

captured_count = 0
prediction_count = 0
normal_count = 0
attack_count = 0

latest_probability = 0.0
latest_action = "WAITING"

last_display_time = time.time()


# ============================================================
# PACKET CALLBACK
# ============================================================

def packet_callback(packet):

    global captured_count
    global prediction_count
    global normal_count
    global attack_count
    global latest_probability
    global latest_action
    global last_display_time

    # --------------------------------------------------------
    # Parse packet
    # --------------------------------------------------------

    parsed_packet = parse_packet(packet)

    if parsed_packet is None:
        return

    captured_count += 1

    # --------------------------------------------------------
    # Run SentinelAI analysis
    # --------------------------------------------------------

    try:

        result = analyze_packet(parsed_packet)

        # Flow does not have enough packets yet
        if result is None:
            return

        prediction_count += 1

        prediction = result["prediction"]
        probability = result["attack_probability"]
        firewall_action = result["firewall_action"]

        latest_probability = probability
        latest_action = firewall_action

        # ----------------------------------------------------
        # ATTACK DETECTED
        # ----------------------------------------------------

        if prediction == "ATTACK":

            attack_count += 1

            print()
            print("!" * 60)
            print("              🚨 ATTACK DETECTED 🚨")
            print("!" * 60)

            print(
                f"Source      : "
                f"{parsed_packet['source_ip']}:"
                f"{parsed_packet['source_port']}"
            )

            print(
                f"Destination : "
                f"{parsed_packet['destination_ip']}:"
                f"{parsed_packet['destination_port']}"
            )

            print(
                f"Protocol    : {parsed_packet['protocol']}"
            )

            print(
                f"Probability : {probability:.2f}"
            )

            print(
                f"Prediction  : {prediction}"
            )

            print(
                f"Firewall    : {firewall_action}"
            )

            print("!" * 60)
            print()

        else:

            normal_count += 1

        # ----------------------------------------------------
        # PERIODIC STATUS
        # ----------------------------------------------------

        current_time = time.time()

        # Display status every 5 seconds
        if current_time - last_display_time >= 5:

            print()
            print("-" * 60)
            print("SENTINELAI STATUS")
            print("-" * 60)

            print(
                f"Packets Captured : {captured_count}"
            )

            print(
                f"Predictions      : {prediction_count}"
            )

            print(
                f"Normal           : {normal_count}"
            )

            print(
                f"Attacks          : {attack_count}"
            )

            print(
                f"Latest Risk      : "
                f"{latest_probability:.2f}"
            )

            print(
                f"Latest Action    : "
                f"{latest_action}"
            )

            print("-" * 60)

            last_display_time = current_time

    except Exception as error:

        print(
            f"\n[ERROR] ML analysis failed: {error}"
        )


# ============================================================
# START SENTINELAI
# ============================================================

print("=" * 60)
print("       SENTINELAI - REAL TIME NETWORK MONITOR")
print("=" * 60)

print()
print("Status : RUNNING")
print()
print("Monitoring network traffic...")
print("Status updates appear every 5 seconds.")
print("Press CTRL+C to stop.")
print()


# ============================================================
# START PACKET CAPTURE
# ============================================================

try:

    sniff(
        prn=packet_callback,
        store=False
    )

except KeyboardInterrupt:

    print()
    print()
    print("=" * 60)
    print("           SENTINELAI - STOPPED")
    print("=" * 60)

finally:

    print()
    print("FINAL STATISTICS")
    print("-" * 60)

    print(
        f"Packets Captured : {captured_count}"
    )

    print(
        f"Predictions      : {prediction_count}"
    )

    print(
        f"Normal           : {normal_count}"
    )

    print(
        f"Attacks          : {attack_count}"
    )

    print(
        f"Latest Risk      : {latest_probability:.2f}"
    )

    print(
        f"Latest Action    : {latest_action}"
    )

    print("-" * 60)
    print("SentinelAI monitoring stopped.")
    print("=" * 60)

