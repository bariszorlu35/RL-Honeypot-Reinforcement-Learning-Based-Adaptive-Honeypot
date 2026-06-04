"""One-command local demo launcher for RL-Honeypot.

Starts the Streamlit dashboard, RL honeypot, and optional bot-free demo traffic
from one terminal. Press Ctrl+C once to stop the managed processes.
"""

import argparse
import os
import signal
import shutil
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path
from typing import Iterable, Optional

import config
import database


ROOT = Path(__file__).resolve().parent
VENV_DIR = ROOT / ".venv"
VENV_PYTHON = VENV_DIR / "bin" / "python"
REQUIREMENTS = ROOT / "requirements.txt"


def _in_venv() -> bool:
    return Path(sys.prefix).resolve() == VENV_DIR.resolve()


def _ensure_venv() -> None:
    """Create .venv and install requirements when the user runs system Python."""
    if VENV_PYTHON.exists():
        return

    builder_python = sys.executable
    preferred_python = shutil.which("python3.11")
    if preferred_python:
        builder_python = preferred_python

    print(f"[Demo] Creating .venv with {builder_python}...")
    subprocess.check_call([builder_python, "-m", "venv", str(VENV_DIR)])
    subprocess.check_call([str(VENV_PYTHON), "-m", "pip", "install", "--upgrade", "pip"])
    subprocess.check_call([str(VENV_PYTHON), "-m", "pip", "install", "-r", str(REQUIREMENTS)])


def _reexec_into_venv() -> None:
    if _in_venv():
        return
    _ensure_venv()
    os.execv(str(VENV_PYTHON), [str(VENV_PYTHON), *sys.argv])


def _port_open(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.4)
        try:
            sock.connect((host, port))
            return True
        except OSError:
            return False


def _wait_for_port(name: str, host: str, port: int, timeout: float = 20.0) -> None:
    start = time.time()
    while time.time() - start < timeout:
        if _port_open(host, port):
            print(f"[Demo] {name} is ready on {host}:{port}")
            return
        time.sleep(0.25)
    raise RuntimeError(f"{name} did not open {host}:{port} within {timeout:.0f}s")


def _stream_output(name: str, proc: subprocess.Popen) -> None:
    assert proc.stdout is not None
    for line in proc.stdout:
        print(f"[{name}] {line.rstrip()}")


def _start_process(
    name: str,
    args: Iterable[str],
    env: Optional[dict] = None,
) -> subprocess.Popen:
    proc = subprocess.Popen(
        list(args),
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    thread = threading.Thread(target=_stream_output, args=(name, proc), daemon=True)
    thread.start()
    return proc


def _stop_processes(processes: list[subprocess.Popen]) -> None:
    for proc in processes:
        if proc.poll() is None:
            proc.send_signal(signal.SIGINT)

    deadline = time.time() + 8
    for proc in processes:
        while proc.poll() is None and time.time() < deadline:
            time.sleep(0.1)
        if proc.poll() is None:
            proc.terminate()


def _run_traffic(args: argparse.Namespace) -> int:
    command = [
        sys.executable,
        "simulate_attacker.py",
        "--mode",
        "rl",
        "--sessions",
        str(args.sessions),
        "--profile",
        args.profile,
        "--delay-scale",
        str(args.delay_scale),
    ]
    print(
        "[Demo] Generating traffic: "
        f"{args.sessions} {args.profile} session(s), delay scale {args.delay_scale:g}x"
    )
    return subprocess.call(command, cwd=ROOT)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Start RL-Honeypot dashboard, honeypot, and demo traffic together."
    )
    parser.add_argument(
        "--sessions",
        type=int,
        default=12,
        help="Bot-free demo traffic session count",
    )
    parser.add_argument(
        "--profile",
        choices=["operator", "script_kiddie"],
        default="operator",
        help="Bot-free attacker profile for generated traffic",
    )
    parser.add_argument(
        "--delay-scale",
        type=float,
        default=0.03,
        help="Multiply simulator delays; lower values make traffic easier to demo",
    )
    parser.add_argument(
        "--dashboard-port",
        type=int,
        default=8501,
        help="Streamlit dashboard port",
    )
    parser.add_argument(
        "--slow-response-delay",
        type=float,
        default=0.0,
        help="Override SLOW_RESPONSE wait time for demo responsiveness",
    )
    parser.add_argument(
        "--reset-db",
        action="store_true",
        help="Clear old session/command rows before starting",
    )
    parser.add_argument(
        "--no-traffic",
        action="store_true",
        help="Start dashboard and honeypot but do not run the simulator",
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Do not open the dashboard URL in the default browser",
    )
    parser.add_argument(
        "--keep-running",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Keep dashboard and honeypot alive after traffic generation",
    )
    return parser.parse_args()


def main() -> int:
    _reexec_into_venv()
    args = parse_args()

    database.init_db()
    if args.reset_db:
        database.clear_db()
        print("[Demo] Database cleared.")

    env = os.environ.copy()
    env["RL_HP_SLOW_RESPONSE_DELAY"] = str(args.slow_response_delay)
    env["RL_HP_STATUS_INTERVAL"] = env.get("RL_HP_STATUS_INTERVAL", "10")

    dashboard_url = f"http://localhost:{args.dashboard_port}"
    processes: list[subprocess.Popen] = []

    try:
        if _port_open(config.HOST, config.RL_PORT):
            raise RuntimeError(
                f"Port {config.RL_PORT} is already in use. Stop the existing honeypot first."
            )

        if _port_open("127.0.0.1", args.dashboard_port):
            print(f"[Demo] Dashboard already appears to be running at {dashboard_url}")
        else:
            processes.append(_start_process(
                "Dashboard",
                [
                    sys.executable,
                    "-m",
                    "streamlit",
                    "run",
                    "dashboard.py",
                    "--server.headless",
                    "true",
                    "--server.port",
                    str(args.dashboard_port),
                ],
                env=env,
            ))
            _wait_for_port("Dashboard", "127.0.0.1", args.dashboard_port)

        processes.append(_start_process(
            "RL",
            [sys.executable, "honeypot_rl.py"],
            env=env,
        ))
        _wait_for_port("RL honeypot", config.HOST, config.RL_PORT)

        if not args.no_browser:
            webbrowser.open(dashboard_url)
            print(f"[Demo] Dashboard opened: {dashboard_url}")
        else:
            print(f"[Demo] Dashboard URL: {dashboard_url}")

        if not args.no_traffic:
            traffic_code = _run_traffic(args)
            if traffic_code != 0:
                print(f"[Demo] Traffic generator exited with code {traffic_code}")

        print("[Demo] System is running. Press Ctrl+C to stop everything.")
        if args.keep_running:
            while True:
                time.sleep(1)
        return 0

    except KeyboardInterrupt:
        print("\n[Demo] Stopping...")
        return 0
    except Exception as exc:
        print(f"[Demo] Error: {exc}")
        return 1
    finally:
        _stop_processes(processes)


if __name__ == "__main__":
    raise SystemExit(main())
