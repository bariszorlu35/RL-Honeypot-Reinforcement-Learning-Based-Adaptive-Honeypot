"""Static baseline honeypot for RL-Honeypot.

Listens on 127.0.0.1:2323. Uses a fixed strategy:
  - UNKNOWN commands   → SILENT_ERROR
  - All other commands → FAKE_SUCCESS

Run with: python honeypot_static.py
"""

import math
import socket
import threading
import time
import uuid

import config
import database
from response_strategies import categorize_command, get_response


def _compute_engagement(duration: float, command_count: int) -> float:
    """Compute session engagement score (static mode uses UNKNOWN behaviour coeff=1.0)."""
    return duration * math.log(command_count + 1) * 1.0


def _handle_client(conn: socket.socket, addr: tuple) -> None:
    """Handle a single attacker connection in its own thread."""
    session_id = uuid.uuid4().hex[:8]
    start_time = time.time()
    command_count = 0
    categories_seen: set = set()
    attacker_profile = "unknown"

    print(f"[Static Honeypot] New connection {addr[0]}:{addr[1]} → session {session_id}")

    try:
        conn.sendall(config.HONEYPOT_BANNER.encode())

        while True:
            try:
                data = conn.recv(1024)
            except (ConnectionResetError, OSError):
                break
            if not data:
                break

            raw = data.decode(errors="replace").strip()
            if not raw:
                continue

            # Allow simulator to pass the attacker profile as a special handshake line
            if raw.startswith("#PROFILE:"):
                attacker_profile = raw.split(":", 1)[1].strip()
                conn.sendall(b"$ ")
                continue

            command_count += 1
            category = categorize_command(raw)
            categories_seen.add(category)

            # Fixed strategy: unknown commands get an error, everything else fake success
            action_id = 0 if category == "UNKNOWN" else 1
            action_name = config.ACTION_NAMES[action_id]

            _, response_text = get_response(action_id, raw)
            try:
                conn.sendall((response_text + "\r\n$ ").encode())
            except OSError:
                break

            database.log_command(
                session_id=session_id,
                command=raw,
                category=category,
                action_taken=action_name,
                reward=0.0,  # Static mode has no reward signal
                timestamp=time.time(),
            )

            print(
                f"[Static Honeypot] Session {session_id}: "
                f"cmd={raw!r} category={category} action={action_name}"
            )

    except Exception as exc:
        print(f"[Static Honeypot] Session {session_id} error: {exc}")
    finally:
        duration = time.time() - start_time
        engagement = _compute_engagement(duration, command_count)
        if command_count > 0:
            database.log_session(
                mode="static",
                session_id=session_id,
                attacker_profile=attacker_profile,
                start_time=start_time,
                duration=duration,
                command_count=command_count,
                unique_categories=len(categories_seen),
                behavior_class="UNKNOWN",  # Static mode does not classify behaviour
                engagement_score=engagement,
                total_reward=0.0,
            )
        conn.close()
        if command_count == 0:
            print(f"[Static Honeypot] Session {session_id} closed before commands; not logged.")
        else:
            print(
                f"[Static Honeypot] Session {session_id} ended: "
                f"duration={duration:.1f}s cmds={command_count} "
                f"profile={attacker_profile}"
            )


def run() -> None:
    """Start the static honeypot server and accept connections until Ctrl+C."""
    database.init_db()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((config.HOST, config.STATIC_PORT))
    server.listen(10)
    server.settimeout(1.0)  # Allows the loop to check for KeyboardInterrupt

    print(f"[Static Honeypot] Listening on {config.HOST}:{config.STATIC_PORT}")
    print("[Static Honeypot] Press Ctrl+C to stop.")

    try:
        while True:
            try:
                conn, addr = server.accept()
            except socket.timeout:
                continue
            thread = threading.Thread(
                target=_handle_client,
                args=(conn, addr),
                daemon=True,
            )
            thread.start()
    except KeyboardInterrupt:
        print("\n[Static Honeypot] Shutting down gracefully.")
    finally:
        server.close()


if __name__ == "__main__":
    run()
