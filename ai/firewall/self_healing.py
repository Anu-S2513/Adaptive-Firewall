import threading
import time

from ai.firewall.firewall_enforcer import remove_block


# Temporary block duration
BLOCK_DURATION = 60

# Keep track of IPs that already have a recovery timer
recovery_tasks = {}

# Lock protects recovery_tasks when multiple threads are running
recovery_lock = threading.Lock()


def schedule_recovery(source_ip, duration=BLOCK_DURATION):
    """
    Schedule automatic recovery for a blocked source IP.

    Only one recovery task is allowed for each source IP.
    """

    if not source_ip:
        return

    with recovery_lock:

        # Do not create another timer if this IP
        # already has a recovery task.
        if source_ip in recovery_tasks:
            print(
                f"[SELF-HEALING] Recovery already scheduled "
                f"for {source_ip}"
            )
            return

        thread = threading.Thread(
            target=_recover_source,
            args=(source_ip, duration),
            daemon=True
        )

        recovery_tasks[source_ip] = thread

        thread.start()


def _recover_source(source_ip, duration):
    """
    Wait for the temporary block period,
    then remove the firewall block.
    """

    try:

        print(
            f"[SELF-HEALING] {source_ip} "
            f"will be recovered in {duration} seconds"
        )

        time.sleep(duration)

        result = remove_block(source_ip)

        print(
            f"[SELF-HEALING] {source_ip} -> "
            f"{result['status']} | "
            f"{result['message']}"
        )

    finally:

        # Allow this IP to have a new recovery
        # task in the future.
        with recovery_lock:
            recovery_tasks.pop(source_ip, None)