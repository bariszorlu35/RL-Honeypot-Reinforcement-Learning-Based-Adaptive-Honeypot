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
            # Credential stuffing patterns (all fake)
            "user admin", "pass admin", "pass 123456", "pass password",
            "user root", "pass root", "login admin admin", "login root root",
            "user administrator", "pass admin123", "user test", "pass test",
            "login ubuntu ubuntu", "user guest", "pass guest",
            "pass 1234", "pass qwerty", "user oracle", "pass oracle",
            "login pi raspberry",
        ],
        "inter_command_delay": (0.1, 0.3),
        "session_length": (5, 20),
        "repeat_probability": 0.7,
    },
    "script_kiddie": {
        "description": "Runs public scripts. RECON + basic SCAN, mechanical.",
        "command_pool": [
            # Temel keşif
            "ls", "ls -la", "pwd", "whoami", "uname -a", "id",
            # Dosya erişimi
            "cat /etc/passwd", "cat /etc/hosts",
            "wget http://127.0.0.1/backup.tar.gz",
            # Araç tabanlı tarama
            "nmap -sV 127.0.0.1",
            "nmap -p 22,80,443 127.0.0.1",
            "nikto -h 127.0.0.1",
            "dirb http://127.0.0.1",
            # Script çalıştırma
            "sh fake_tool.sh", "chmod 777 fake_tool.sh",
            "python3 -c 'import os; print(os.getcwd())'",
            # Basit kalıcılık
            "crontab -l",
            "crontab -e",
        ],
        "inter_command_delay": (0.5, 2.5),
        "session_length": (8, 25),
        "repeat_probability": 0.2,
    },
    "operator": {
        "description": "Methodical human operator. Full TTP chain, thinking pauses.",
        "command_pool": [
            # Keşif
            "ls", "ls -la", "pwd", "whoami", "id", "uname -a",
            "ps aux", "netstat -an", "ss -tlnp", "ifconfig",
            "history", "env", "w", "last",
            # Sistem/ağ keşfi
            "cat /etc/passwd", "cat /etc/hosts", "cat /proc/version",
            "cat /var/www/html/config.php",
            "find / -name '*.conf' 2>/dev/null",
            "find / -name '*.env' 2>/dev/null",
            "ls -la /home", "ls /var/www", "ls /opt",
            # Tarama araçları
            "nmap -A 127.0.0.1",
            "nmap -sV --script vuln 127.0.0.1",
            "nikto -h http://127.0.0.1",
            # Dosya erişimi / veri sızdırma
            "wget http://127.0.0.1/backup.tar.gz",
            "tar -xzf backup.tar.gz",
            "cat config.env",
            "strings backup.tar.gz",
            # Sömürü araçları
            "sqlmap -u 'http://127.0.0.1/?id=1' --dbs",
            "hydra -l admin -P /tmp/pass.txt ssh://127.0.0.1",
            # Exec / post-exploit (simüle edilmiş araç çağrıları)
            "python3 scan.py",
            "nc -zv 127.0.0.1 4444",
            "bash exploit.sh",
            # Kalıcılık
            "crontab -l", "crontab -e",
            "systemctl list-units",
            "echo 'export PATH=$PATH:/tmp' | tee /etc/profile.d/path.sh",
            "useradd -m sysmon",
        ],
        "inter_command_delay": (2.0, 8.0),
        "session_length": (15, 45),
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
    delay_scale: float,
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

                delay = random.uniform(*delay_range) * delay_scale
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


def run_simulation(
    mode: str,
    n_sessions: int,
    forced_profile: str = "",
    delay_scale: float = 1.0,
) -> None:
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
    if delay_scale != 1.0:
        print(f"[Simulator] Delay scale: {delay_scale:g}x")

    results = []
    profile_counts: Dict[str, int] = {}

    for i in range(1, n_sessions + 1):
        profile_name = forced_profile if forced_profile else random.choice(_DEFAULT_MIX)
        stats = _run_session(host, port, profile_name, i, n_sessions, delay_scale)
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
    parser.add_argument(
        "--delay-scale",
        type=float,
        default=1.0,
        help="Multiply profile sleep delays by this value; use 0.05 for fast demos",
    )
    args = parser.parse_args()
    run_simulation(args.mode, args.sessions, args.profile, max(args.delay_scale, 0.0))


if __name__ == "__main__":
    main()
