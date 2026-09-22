import platform


def enforce_firewall_action(
    action,
    source_ip=None
):
    """
    Execute the firewall decision.

    Current version:
    - ALLOW   -> no action
    - MONITOR -> no action
    - BLOCK   -> simulation only

    Actual Windows firewall blocking will be
    enabled after the controlled test is verified.
    """

    if action == "ALLOW":

        return {
            "status": "ALLOWED",
            "message": "Traffic allowed."
        }

    elif action == "MONITOR":

        return {
            "status": "MONITORING",
            "message": "Traffic is being monitored."
        }

    elif action == "BLOCK":

        return {
            "status": "BLOCKED",
            "message": (
                f"Block decision generated for "
                f"{source_ip}"
            )
        }

    else:

        return {
            "status": "UNKNOWN",
            "message": "Unknown firewall action."
        }