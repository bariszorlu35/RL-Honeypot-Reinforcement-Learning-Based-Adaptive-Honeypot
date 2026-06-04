"""Configuration constants for RL-Honeypot.

All tunable parameters live here. No magic numbers anywhere else in the project.
"""

import os

HOST = "127.0.0.1"
STATIC_PORT = 2323
RL_PORT = 2324
DB_PATH = "honeypot.db"
Q_TABLE_PATH = "q_table.json"

# Q-learning hyperparameters
ALPHA = 0.1           # Learning rate
GAMMA = 0.9           # Discount factor
EPSILON_START = 1.0   # Start fully exploratory
EPSILON_MIN = 0.05    # Never drop below 5% exploration
EPSILON_DECAY = 0.9997 # Multiply epsilon by this after each episode
                       # 0.995 → min sonra ~1.400 oturum (çok erken)
                       # 0.9997 → min sonra ~20.000 oturum (tüm eğitimi kapsar)
ACTION_PRIOR_WEIGHT = 20.0
# Domain-informed policy prior used only during exploitation.
# 0.0 disables it and returns to pure Q-value argmax.

# Reward weights
W_ENGAGE = 1.0    # Engagement continuation reward
W_DIVERSITY = 1.5 # New command category reward
W_BOT = 2.0       # Bot-like behaviour penalty magnitude
W_LURE = 3.0      # Decoy/lure interaction bonus

# Behaviour classification thresholds
BOT_SCORE_THRESHOLD = 3
HUMAN_SCORE_THRESHOLD = 2
FAST_TEMPO_CPM = 60   # Commands per minute above which tempo is FAST
SLOW_TEMPO_CPM = 10   # Commands per minute below which tempo is SLOW

def _float_from_env(name: str, default: float) -> float:
    """Read a float environment override, falling back to default on mistakes."""
    try:
        return float(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


# Response timing
SLOW_RESPONSE_DELAY = _float_from_env(
    "RL_HP_SLOW_RESPONSE_DELAY",
    2.0,
)  # seconds added by SLOW_RESPONSE strategy
IDLE_STATUS_INTERVAL = _float_from_env(
    "RL_HP_STATUS_INTERVAL",
    15.0,
)  # seconds between "waiting for traffic" status lines

# Action names (for logging and display)
ACTION_NAMES = {
    0: "SILENT_ERROR",
    1: "FAKE_SUCCESS",
    2: "DECOY_LURE",
    3: "SLOW_RESPONSE",
    4: "HONEYTRAP_OFFER",
}

HONEYPOT_BANNER = "\r\nUbuntu 20.04.3 LTS\r\nlogin: "

# ── Fix 4: Genişletilmiş state temsili ────────────────────────────────────────
STATE_WINDOW_SIZE = 3     # Pencere 3: 9^3×3×3×3 = ~19.7k teorik state
                          # Pencere 5 çok büyük olur, yakınsama güçleşir
DEPTH_EARLY_MAX   = 5     # 1-5 komut  → EARLY
DEPTH_MID_MAX     = 15    # 6-15 komut → MID  (16+ → LATE)

# ── Fix 5: TTP aşama bazlı reward ─────────────────────────────────────────────
# Kill-chain'de ne kadar derinde → o kadar değerli istihbarat
CATEGORY_WEIGHTS = {
    "AUTH":    0.5,   # Credential stuffing: yaygın, düşük değer
    "RECON":   1.0,   # Keşif: temel değer
    "SCAN":    1.4,   # Araç bazlı tarama (nmap, nikto): aktif keşif
    "FILE":    1.3,   # Dosya erişimi: saldırgan bir şey buldu
    "EXEC":    1.8,   # Komut çalıştırma: yüksek değer
    "EXPLOIT": 2.2,   # Aktif sömürü girişimi (sqlmap, hydra): en kritik
    "PERSIST": 2.0,   # Kalıcılık: çok yüksek değer
    "UNKNOWN": 0.8,   # Tanınmayan komut: temel altı
}
# HONEYTRAP_OFFER follow bonusu (EXEC/PERSIST/FILE after action 4)
W_HONEYTRAP = 2.5   # DECOY_LURE'dan biraz düşük
TTP_PROGRESSION_BONUS = 1.5   # Kill-chain'de ilerleme bonusu
EXEC_PERSIST_BONUS    = 1.5   # EXEC/PERSIST kategorisi ek bonusu

# ── Fix 1: Exploration bonusu ──────────────────────────────────────────────────
EXPLORATION_BONUS = 0.3   # Daha önce hiç görülmemiş state'e girildiğinde
