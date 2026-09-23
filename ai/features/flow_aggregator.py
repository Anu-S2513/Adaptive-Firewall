from datetime import datetime
import statistics


# Stores all active network flows
flows = {}


def get_protocol_number(protocol):
    """
    Convert protocol names into the numeric protocol values
    used by the training dataset.
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
    Create a unique key for a bidirectional network flow.

    Packets travelling in both directions of the same
    connection are placed into the same flow.
    """

    endpoint1 = (
        packet["source_ip"],
        str(packet["source_port"])
    )

    endpoint2 = (
        packet["destination_ip"],
        str(packet["destination_port"])
    )

    # Sort endpoints so both directions produce
    # the same flow key.
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

        # First packet establishes the flow initiator.
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
    Update the statistics of an existing flow.
    """

    now = datetime.now()
    flow["last_time"] = now

    packet_size = packet["packet_size"]

    # --------------------------------------------------
    # Determine packet direction
    # --------------------------------------------------

    if (
        packet["source_ip"] == flow["initiator_ip"]
        and str(packet["source_port"]) == flow["initiator_port"]
    ):
        flow["forward_packets"] += 1
        flow["forward_bytes"] += packet_size

    else:
        flow["backward_packets"] += 1
        flow["backward_bytes"] += packet_size

    # --------------------------------------------------
    # Store packet size
    # --------------------------------------------------

    flow["packet_sizes"].append(packet_size)

    # --------------------------------------------------
    # Count TCP flags
    # --------------------------------------------------

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
    Add a captured packet to its corresponding flow.

    Prediction schedule:

        Packets 1-4   -> collect
        Packet 5      -> predict
        Packets 6-14  -> collect
        Packet 15     -> predict
        Packets 16-24 -> collect
        Packet 25     -> predict
        ...

    Returns:
        Feature dictionary when prediction is due.
        None otherwise.
    """

    flow_key = get_flow_key(packet)

    # Create a new flow when necessary.
    if flow_key not in flows:
        flows[flow_key] = create_flow(packet)

    flow = flows[flow_key]

    # Add the current packet to the flow.
    update_flow(flow, packet)

    total_packets = (
        flow["forward_packets"]
        + flow["backward_packets"]
    )

    # --------------------------------------------------
    # Wait until minimum number of packets is reached
    # --------------------------------------------------

    if total_packets < minimum_packets:
        return None

    # --------------------------------------------------
    # First prediction
    # --------------------------------------------------

    if total_packets == minimum_packets:
        return get_flow_features(flow, packet)

    # --------------------------------------------------
    # Subsequent predictions
    # --------------------------------------------------

    if (
        total_packets - minimum_packets
    ) % prediction_interval == 0:

        return get_flow_features(flow, packet)

    return None


def get_flow_features(flow, packet):
    """
    Convert the current flow statistics into the
    14 features expected by the Random Forest model.
    """

    # ==================================================
    # FLOW DURATION
    # ==================================================

    # The training dataset uses microseconds.
    duration = (
        flow["last_time"]
        - flow["start_time"]
    ).total_seconds() * 1_000_000

    # Prevent zero/negative duration.
    if duration <= 0:
        duration = 1

    # Convert microseconds to seconds ONLY for
    # calculating rate-based features.
    duration_seconds = duration / 1_000_000

    # ==================================================
    # BASIC FLOW COUNTS
    # ==================================================

    total_packets = (
        flow["forward_packets"]
        + flow["backward_packets"]
    )

    total_bytes = (
        flow["forward_bytes"]
        + flow["backward_bytes"]
    )

    packet_sizes = flow["packet_sizes"]

    # ==================================================
    # PACKET SIZE STATISTICS
    # ==================================================

    packet_mean = statistics.mean(packet_sizes)

    if len(packet_sizes) > 1:
        # Population standard deviation.
        packet_std = statistics.pstdev(packet_sizes)
    else:
        packet_std = 0

    # ==================================================
    # RATE FEATURES
    # ==================================================

    flow_bytes_per_second = (
        total_bytes / duration_seconds
    )

    flow_packets_per_second = (
        total_packets / duration_seconds
    )

    # ==================================================
    # RETURN EXACT 14 MODEL FEATURES
    # ==================================================

    return {
        "Protocol": get_protocol_number(
            packet["protocol"]
        ),

        "Flow Duration": duration,

        "Total Fwd Packets":
            flow["forward_packets"],

        "Total Backward Packets":
            flow["backward_packets"],

        "Fwd Packets Length Total":
            flow["forward_bytes"],

        "Bwd Packets Length Total":
            flow["backward_bytes"],

        "Flow Bytes/s":
            flow_bytes_per_second,

        "Flow Packets/s":
            flow_packets_per_second,

        "Packet Length Mean":
            packet_mean,

        "Packet Length Std":
            packet_std,

        "SYN Flag Count":
            flow["syn_count"],

        "ACK Flag Count":
            flow["ack_count"],

        "RST Flag Count":
            flow["rst_count"],

        "FIN Flag Count":
            flow["fin_count"]
    }