from datetime import datetime
import statistics


# Stores all active network flows
flows = {}


def get_protocol_number(protocol):
    """
    Convert protocol names into IP protocol numbers
    compatible with the training dataset.
    """

    protocol_map = {
        "TCP": 6,
        "UDP": 17,
        "ICMP": 1,
        "OTHER": 0
    }

    return protocol_map.get(protocol, 0)


def get_flow_key(packet):
    """
    Create a unique key for identifying a network flow.

    Both directions of the same connection
    will belong to the same flow.
    """

    endpoint1 = (
        packet["source_ip"],
        str(packet["source_port"])
    )

    endpoint2 = (
        packet["destination_ip"],
        str(packet["destination_port"])
    )

    # Sort endpoints so forward and backward
    # packets belong to the same flow
    endpoints = sorted([endpoint1, endpoint2])

    return (
        endpoints[0],
        endpoints[1],
        packet["protocol"]
    )


def create_flow(packet):
    """
    Create a new network flow.
    """

    now = datetime.now()

    return {
        "start_time": now,
        "last_time": now,

        # First packet defines the initiator
        "initiator_ip": packet["source_ip"],
        "initiator_port": str(packet["source_port"]),

        "forward_packets": 0,
        "backward_packets": 0,

        "forward_bytes": 0,
        "backward_bytes": 0,

        "packet_sizes": [],

        "syn_count": 0,
        "ack_count": 0,
        "rst_count": 0,
        "fin_count": 0
    }


def update_flow(flow, packet):
    """
    Update flow statistics using a real captured packet.
    """

    now = datetime.now()
    flow["last_time"] = now

    packet_size = packet["packet_size"]

    # Determine packet direction
    if (
        packet["source_ip"] == flow["initiator_ip"]
        and str(packet["source_port"]) == flow["initiator_port"]
    ):
        flow["forward_packets"] += 1
        flow["forward_bytes"] += packet_size

    else:
        flow["backward_packets"] += 1
        flow["backward_bytes"] += packet_size

    # Store packet size
    flow["packet_sizes"].append(packet_size)

    # Count TCP flags
    flags = str(packet["tcp_flags"])

    if "S" in flags:
        flow["syn_count"] += 1

    if "A" in flags:
        flow["ack_count"] += 1

    if "R" in flags:
        flow["rst_count"] += 1

    if "F" in flags:
        flow["fin_count"] += 1


def process_packet(
    packet,
    minimum_packets=5,
    prediction_interval=10
):
    """
    Add a real packet to its network flow.

    Prediction logic:

    Packets 1-4  -> Collect data
    Packet 5     -> Prediction
    Packets 6-14 -> Collect data
    Packet 15    -> Prediction
    Packets 16-24 -> Collect data
    Packet 25     -> Prediction
    """

    flow_key = get_flow_key(packet)

    # Create flow if it does not already exist
    if flow_key not in flows:
        flows[flow_key] = create_flow(packet)

    flow = flows[flow_key]

    # Update flow using the current real packet
    update_flow(flow, packet)

    total_packets = (
        flow["forward_packets"]
        + flow["backward_packets"]
    )

    # Do not predict until enough packets exist
    if total_packets < minimum_packets:
        return None

    # First prediction at packet 5
    if total_packets == minimum_packets:
        return get_flow_features(flow, packet)

    # Predict every 10 packets after the first prediction
    if (
        total_packets - minimum_packets
    ) % prediction_interval == 0:

        return get_flow_features(flow, packet)

    # No prediction for this packet
    return None


def get_flow_features(flow, packet):
    """
    Convert real flow statistics into the exact
    features required by the ML model.
    """

    duration = (
        flow["last_time"]
        - flow["start_time"]
    ).total_seconds()

    # Prevent division by zero
    if duration <= 0:
        duration = 0.000001

    total_packets = (
        flow["forward_packets"]
        + flow["backward_packets"]
    )

    total_bytes = (
        flow["forward_bytes"]
        + flow["backward_bytes"]
    )

    packet_sizes = flow["packet_sizes"]

    # Mean packet size
    packet_mean = statistics.mean(packet_sizes)

    # Standard deviation of packet sizes
    if len(packet_sizes) > 1:
        packet_std = statistics.stdev(packet_sizes)
    else:
        packet_std = 0

    # Return features in the SAME format
    # used during model training
    return {
        "Protocol": get_protocol_number(
            packet["protocol"]
        ),

        "Flow Duration": duration,

        "Total Fwd Packets": flow["forward_packets"],

        "Total Backward Packets": flow["backward_packets"],

        "Fwd Packets Length Total": flow["forward_bytes"],

        "Bwd Packets Length Total": flow["backward_bytes"],

        "Flow Bytes/s": total_bytes / duration,

        "Flow Packets/s": total_packets / duration,

        "Packet Length Mean": packet_mean,

        "Packet Length Std": packet_std,

        "SYN Flag Count": flow["syn_count"],

        "ACK Flag Count": flow["ack_count"],

        "RST Flag Count": flow["rst_count"],

        "FIN Flag Count": flow["fin_count"]
    }