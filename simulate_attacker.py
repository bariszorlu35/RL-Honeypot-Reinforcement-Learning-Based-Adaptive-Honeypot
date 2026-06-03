"""Local attacker simulator for RL-Honeypot.

Connects ONLY to 127.0.0.1. Simulates three attacker profiles with
realistic command pools and inter-command timing.

Usage:
    python simulate_attacker.py --mode static --sessions 30
    python simulate_attacker.py --mode rl --sessions 30
    python simulate_attacker.py --mode rl --sessions 10 --profile operator
"""

import argparse
import random
import socket
import time
from typing import Dict, Optional

import config

# ---------------------------------------------------------------------------
# Attacker profile definitions
# ---------------------------------------------------------------------------

PROFILES: Dict[str, dict] = {
    "bot": {
        "description": "Automated credential stuffer. Rapid and repetitive.",
        "command_pool": [
            "user admin",
            "pass admin",
            "pass 123456",
            "pass password",
            "user root",
            "pass root",
            "login admin admin",
            "login root root",
        ],
        "inter_command_delay": (0.1, 0.3),
        "session_length": (5, 15),
        "repeat_probability": 0.7,
    },
    "script_kiddie": {
        "description": "Runs a recon script. Some diversity but mechanical.",
        "command_pool": [
            "ls",
            "ls -la",
            "pwd",
            "whoami",
            "uname -a",
            "cat /etc/passwd",
            "wget http://127.0.0.1/fake_tool.sh",
            "sh fake_tool.sh",
            "chmod 777 fake_tool.sh",
        ],
        "inter_command_delay": (0.5, 2.0),
        "session_length": (8, 20),
        "repeat_probability": 0.2,
    },
    "operator": {
        "description": "Methodical human operator. High diversity, thinking pauses.",
        "command_pool": [
            "ls",
            "pwd",
            "whoami",
            "id",
            "uname -a",
            "ls -la /home",
            "ls /var/www",
            "cat /etc/passwd",
            "ps aux",
            "netstat -an",
            "ifconfig",
            "cat /var/www/html/config.php",
            "find / -name '*.conf' 2>/dev/null",
            "wget http://127.0.0.1/backup.tar.gz",
            "tar -xzf backup.tar.gz",
            "python3 scan.py",
            "crontab -l",
            "cat /etc/crontab",
        ],
        "inter_command_delay": (2.0, 8.0),
        "session_length": (15, 40),
        "repeat_probability": 0.05,
    },
}

# Default mix: 40 % bot, 30 % script_kiddie, 30 % operator
_DEFAULT_MIX = ["bot"] * 4 + ["script_kiddie"] * 3 + ["operator"] * 3


def _run_session(
    host: str,
    port: int,
    profile_name: str,
    session_num: int,
    total: int,
) -> Dict:
    """Connect to the honeypot, send commands per the chosen profile, and return stats.

    Opens a TCP connection to localhost only. All commands are plain text strings.
    No shellcode or exploit payloads are ever sent.
    """
    profile = PROFILES[profile_name]
    session_length = random.randint(*profile["session_length"])
    command_pool: list = profile["command_pool"]
    delay_range: tuple = profile["inter_command_delay"]
    repeat_prob: float = profile["repeat_probability"]

    commands_sent = 0
    session_start = time.time()
    last_cmd = ""

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(10.0)
            sock.connect((host, port))

            # Read and discard the banner
            try:
                sock.recv(512)
            except socket.timeout:
                pass

            # Send attacker profile as a special metadata line (honeypot logs it)
            sock.sendall(f"#PROFILE:{profile_name}\n".encode())
            time.sleep(0.05)
            try:
                sock.recv(256)
            except socket.timeout:
                pass

            for _ in range(session_length):
                # Decide whether to repeat the last command (simulates scripted behaviour)
                if last_cmd and random.random() < repeat_prob:
                    cmd = last_cmd
                else:
                    cmd = random.choice(command_pool)
                last_cmd = cmd

                try:
                    sock.sendall((cmd + "\n").encode())
                    commands_sent += 1
                    sock.recv(4096)  # Read and discard the honeypot response
                except (socket.timeout, OSError):
                    break

                delay = random.uniform(*delay_range)
                time.sleep(delay)

    except (ConnectionRefusedError, OSError) as exc:
        print(f"[Simulator] Could not connect to {host}:{port} — {exc}")
        print(f"[Simulator] Is the honeypot running? Check that it is listening on port {port}.")
        return {"profile": profile_name, "commands": 0, "duration": 0.0, "error": True}

    duration = time.time() - session_start

    print(
        f"[Simulator] Session {session_num}/{total} | "
        f"profile={profile_name} | "
        f"commands={commands_sent} | "
        f"duration={duration:.1f}s"
    )

    return {
        "profile": profile_name,
        "commands": commands_sent,
        "duration": duration,
        "error": False,
    }


def run_simulation(mode: str, n_sessions: int, forced_profile: str = "") -> None:
    """Run n_sessions attacker sessions against the chosen honeypot.

    Args:
        mode:           'static' targets port 2323, 'rl' targets port 2324.
        n_sessions:     Number of attacker sessions to simulate.
        forced_profile: If non-empty, every session uses this profile.
    """
    port = config.STATIC_PORT if mode == "static" else config.RL_PORT
    host = config.HOST  # Always 127.0.0.1

    print(f"[Simulator] Starting {n_sessions} sessions → {host}:{port} ({mode} mode)")
    if forced_profile:
        print(f"[Simulator] Forced profile: {forced_profile}")
    else:
        print("[Simulator] Profile mix: 40% bot / 30% script_kiddie / 30% operator")

    results = []
    profile_counts: Dict[str, int] = {}

    for i in range(1, n_sessions + 1):
        profile_name = forced_profile if forced_profile else random.choice(_DEFAULT_MIX)
        stats = _run_session(host, port, profile_name, i, n_sessions)
        results.append(stats)
        profile_counts[profile_name] = profile_counts.get(profile_name, 0) + 1

    # Print summary
    successful = [r for r in results if not r.get("error")]
    total_cmds = sum(r["commands"] for r in successful)
    total_dur = sum(r["duration"] for r in successful)
    n_ok = len(successful)
    avg_cmds = total_cmds / max(n_ok, 1)
    avg_dur = total_dur / max(n_ok, 1)

    breakdown = "  ".join(
        f"{k}={v}" for k, v in sorted(profile_counts.items())
    )
    print(
        f"\n[Simulator] Done. Total: {n_sessions} sessions | "
        f"Avg duration: {avg_dur:.1f}s | Avg commands: {avg_cmds:.1f}"
    )
    print(f"Profile breakdown: {breakdown}")


def main() -> None:
    """Parse CLI arguments and launch the simulation."""
    parser = argparse.ArgumentParser(
        description="RL-Honeypot attacker simulator — localhost only, academic use"
    )
    parser.add_argument(
        "--mode",
        choices=["static", "rl"],
        required=True,
        help="Target honeypot: 'static' (port 2323) or 'rl' (port 2324)",
    )
    parser.add_argument(
        "--sessions",
        type=int,
        default=10,
        help="Number of attacker sessions to simulate (default: 10)",
    )
    parser.add_argument(
        "--profile",
        choices=list(PROFILES.keys()),
        default="",
        help="Force a single attacker profile; default is a 40/30/30 mix",
    )
    args = parser.parse_args()
    run_simulation(args.mode, args.sessions, args.profile)


if __name__ == "__main__":
    main()
