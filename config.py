"""Configuration constants for RL-Honeypot.

All tunable parameters live here. No magic numbers anywhere else in the project.
"""

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
EPSILON_DECAY = 0.995 # Multiply epsilon by this after each episode

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

# Response timing
SLOW_RESPONSE_DELAY = 2.0  # seconds added by SLOW_RESPONSE strategy

# Action names (for logging and display)
ACTION_NAMES = {
    0: "SILENT_ERROR",
    1: "FAKE_SUCCESS",
    2: "DECOY_LURE",
    3: "SLOW_RESPONSE",
    4: "HONEYTRAP_OFFER",
}

HONEYPOT_BANNER = "\r\nUbuntu 20.04.3 LTS\r\nlogin: "
