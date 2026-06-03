"""Response strategy templates for RL-Honeypot.

ALL output is simulated fake text. No real commands are ever executed.
Fake credentials are clearly marked and are not real.
"""

import time
from typing import Tuple

import config

# ---------------------------------------------------------------------------
# Command categorisation map
# ---------------------------------------------------------------------------

COMMAND_CATEGORIES = {
    "AUTH": [
        "login", "user", "pass", "su", "sudo", "passwd",
    ],
    "RECON": [
        "ls", "dir", "pwd", "whoami", "uname", "id", "ps",
        "netstat", "ifconfig", "ip",
    ],
    "FILE": [
        "cat", "wget", "curl", "get", "put", "download",
        "upload", "ftp", "scp", "cp", "mv", "tar", "find",
    ],
    "EXEC": [
        "sh", "bash", "exec", "python", "python3", "perl", "ruby", "php",
    ],
    "PERSIST": [
        "crontab", "chmod", "chown", "echo", "tee",
        "systemctl", "service",
    ],
    "UNKNOWN": [],
}

# ---------------------------------------------------------------------------
# Pre-built fake outputs (entirely simulated, never executed)
# ---------------------------------------------------------------------------

_FAKE_LS_OUTPUT = (
    "total 64\r\n"
    "drwxr-xr-x 5 ubuntu ubuntu  4096 Jan 10 09:12 .\r\n"
    "drwxr-xr-x 3 root   root    4096 Jan  5 08:00 ..\r\n"
    "-rw-r--r-- 1 ubuntu ubuntu  1234 Jan 10 09:10 README.txt\r\n"
    "-rw-r--r-- 1 ubuntu ubuntu 18432 Jan 10 09:11 backup.tar.gz\r\n"
    "-rw------- 1 ubuntu ubuntu   512 Jan 10 09:09 config.env\r\n"
    "-rw-r--r-- 1 ubuntu ubuntu  8192 Jan  9 14:30 db_backup.sql\r\n"
    "-rwxr-xr-x 1 ubuntu ubuntu  2048 Jan  8 11:05 monitor.sh\r\n"
)

# FAKE CREDENTIAL — for honeypot simulation only; not real
_FAKE_CONFIG_ENV = (
    "# Application configuration\r\n"
    "APP_ENV=production\r\n"
    "DB_HOST=127.0.0.1\r\n"
    "DB_PORT=5432\r\n"
    "DB_NAME=appdb\r\n"
    "DB_USER=admin\r\n"          # FAKE CREDENTIAL — honeypot bait only
    "DB_PASS=honeypot123\r\n"    # FAKE CREDENTIAL — honeypot bait only
    "SECRET_KEY=fake-not-real-abc123\r\n"  # FAKE — honeypot bait
    "API_TOKEN=hp-fake-token-00000\r\n"    # FAKE — honeypot bait
)

_FAKE_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\r\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\n"
    "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\r\n"
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\r\n"
)

_DECOY_LURE_HINTS = [
    (
        "\r\n[notice] A backup archive was detected at /opt/backup.tar.gz\r\n"
        "         It may contain sensitive configuration files.\r\n"
    ),
    "\r\n[notice] Config snapshot available: /tmp/config.env.bak\r\n",
    (
        "\r\n[notice] Database dump found at /var/backups/db_backup.sql\r\n"
        "         Last modified 2 hours ago.\r\n"
    ),
]

_HONEYTRAP_HINTS = [
    (
        "\r\n[info] Admin portal detected at http://127.0.0.1:8080/admin\r\n"
        "       Use: wget http://127.0.0.1:8080/admin/export\r\n"
    ),
    (
        "\r\n[info] Credentials archive at /opt/creds.tar.gz\r\n"
        "       Extract with: tar -xzf /opt/creds.tar.gz\r\n"
    ),
    (
        "\r\n[info] Privileged script available: /opt/scripts/monitor.sh\r\n"
        "       Run: bash /opt/scripts/monitor.sh --dump-config\r\n"
    ),
]

_lure_idx = 0
_trap_idx = 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def categorize_command(command: str) -> str:
    """Return the category string for a raw command string.

    Matches on the first word (verb) of the command.
    Falls through to UNKNOWN if no category matches.
    """
    cmd_lower = command.strip().lower()
    parts = cmd_lower.split()
    first_word = parts[0] if parts else ""

    for category, keywords in COMMAND_CATEGORIES.items():
        if category == "UNKNOWN":
            continue
        if first_word in keywords:
            return category

    # Secondary pass: prefix match for compound keywords
    for category, keywords in COMMAND_CATEGORIES.items():
        if category == "UNKNOWN":
            continue
        for kw in keywords:
            if cmd_lower.startswith(kw + " ") or cmd_lower == kw:
                return category

    return "UNKNOWN"


def _context_response(command: str) -> str:
    """Build a context-aware fake success response based on the command verb."""
    cmd_lower = command.strip().lower()
    first_word = cmd_lower.split()[0] if cmd_lower.split() else cmd_lower

    if first_word in ("ls", "dir"):
        return _FAKE_LS_OUTPUT
    if first_word == "pwd":
        return "/home/ubuntu\r\n"
    if first_word == "whoami":
        return "root\r\n"
    if first_word == "id":
        return "uid=0(root) gid=0(root) groups=0(root)\r\n"
    if first_word == "uname":
        return (
            "Linux ubuntu-lab 5.4.0-42-generic "
            "#46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020 "
            "x86_64 x86_64 x86_64 GNU/Linux\r\n"
        )
    if first_word == "cat":
        if "passwd" in cmd_lower:
            return _FAKE_PASSWD
        if "config" in cmd_lower or ".env" in cmd_lower or ".php" in cmd_lower:
            return _FAKE_CONFIG_ENV
        if "crontab" in cmd_lower:
            return "# m h dom mon dow command\r\n# 0 * * * * /opt/scripts/monitor.sh\r\n"
        return "[file contents]\r\n"
    if first_word == "ps":
        return (
            "  PID TTY          TIME CMD\r\n"
            "    1 ?        00:00:01 systemd\r\n"
            "  423 ?        00:00:00 sshd\r\n"
            " 1042 pts/0    00:00:00 bash\r\n"
            " 1087 pts/0    00:00:00 ps\r\n"
        )
    if first_word == "netstat":
        return (
            "Active Internet connections\r\n"
            "Proto  Local Address      Foreign Address  State\r\n"
            "tcp    0.0.0.0:22         0.0.0.0:*        LISTEN\r\n"
            "tcp    127.0.0.1:5432     0.0.0.0:*        LISTEN\r\n"
            "tcp    127.0.0.1:8080     0.0.0.0:*        LISTEN\r\n"
        )
    if first_word == "ifconfig":
        return (
            "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n"
            "        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255\r\n"
        )
    if first_word in ("wget", "curl"):
        return "Connecting... 200 OK\r\nSaved to: 'index.html'\r\n"
    if first_word in ("tar",):
        return "backup.tar.gz extracted successfully.\r\n"
    if first_word in ("find",):
        return (
            "/etc/apache2/apache2.conf\r\n"
            "/etc/mysql/my.conf\r\n"
            "/var/www/html/config.php\r\n"
        )
    if first_word in ("su", "sudo"):
        return "Password: \r\n"
    if first_word in ("python", "python3"):
        return "Python 3.8.10 (default, Nov 14 2022, 12:59:47)\r\n>>> \r\n"
    if first_word == "crontab":
        return "# m h dom mon dow command\r\n# 0 5 * * 1 /opt/scripts/monitor.sh\r\n"
    if first_word in ("chmod", "chown"):
        return ""  # Silently succeeds — realistic Unix behaviour
    if first_word == "systemctl":
        return "● sshd.service - OpenSSH Daemon\r\n   Active: active (running)\r\n"
    if first_word == "sh" or first_word == "bash":
        return "$ \r\n"

    return f"Command executed.\r\n"


# ---------------------------------------------------------------------------
# Strategy implementations
# ---------------------------------------------------------------------------

def strategy_silent_error(command: str) -> str:
    """Return a generic error without revealing system details."""
    first_word = command.strip().split()[0] if command.strip() else command
    return f"-bash: {first_word}: command not found\r\n"


def strategy_fake_success(command: str) -> str:
    """Return a realistic-looking fake success response."""
    return _context_response(command)


def strategy_decoy_lure(command: str) -> str:
    """Return fake success plus a hint toward seemingly valuable files."""
    global _lure_idx
    base = _context_response(command)
    hint = _DECOY_LURE_HINTS[_lure_idx % len(_DECOY_LURE_HINTS)]
    _lure_idx += 1
    return base + hint


def strategy_slow_response(command: str) -> Tuple[float, str]:
    """Return (delay_seconds, response_text) imposing an artificial delay.

    The caller is responsible for sleeping before sending the response.
    """
    return config.SLOW_RESPONSE_DELAY, _context_response(command)


def strategy_honeytrap_offer(command: str) -> str:
    """Return fake success plus a honeytrap hint toward a high-value target."""
    global _trap_idx
    base = _context_response(command)
    trap = _HONEYTRAP_HINTS[_trap_idx % len(_HONEYTRAP_HINTS)]
    _trap_idx += 1
    return base + trap


def get_response(action_id: int, command: str) -> Tuple[float, str]:
    """Dispatch to the correct strategy and return (delay_seconds, response_text).

    Args:
        action_id: Integer key from config.ACTION_NAMES.
        command:   Raw command string received from the attacker.

    Returns:
        (delay_seconds, text_to_send) — delay is 0.0 unless SLOW_RESPONSE.
    """
    if action_id == 0:
        return 0.0, strategy_silent_error(command)
    if action_id == 1:
        return 0.0, strategy_fake_success(command)
    if action_id == 2:
        return 0.0, strategy_decoy_lure(command)
    if action_id == 3:
        delay, text = strategy_slow_response(command)
        return delay, text
    if action_id == 4:
        return 0.0, strategy_honeytrap_offer(command)
    # Fallback for any unexpected action_id
    return 0.0, strategy_silent_error(command)
