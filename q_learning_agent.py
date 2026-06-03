"""Q-learning agent components for RL-Honeypot.

Provides BehaviorClassifier, StateBuilder, QLearningAgent, and RewardCalculator.
"""

import json
import math
import random
import threading
from collections import deque
from typing import Dict, Optional, Tuple

import config


# ---------------------------------------------------------------------------
# Behaviour Classifier
# ---------------------------------------------------------------------------

class BehaviorClassifier:
    """Classifies attacker behaviour as BOT, HUMAN, or UNKNOWN.

    Maintains rolling observations of commands, timestamps, and categories
    to score bot-like vs. human-like signals per session.
    """

    def __init__(self) -> None:
        self._timestamps: list = []
        self._categories: list = []
        self._commands: list = []
        self._consecutive_same: int = 0
        self._last_cmd: str = ""

    def update(self, command: str, category: str, timestamp: float) -> None:
        """Record a new command observation."""
        self._timestamps.append(timestamp)
        self._categories.append(category)
        self._commands.append(command)

        if command == self._last_cmd:
            self._consecutive_same += 1
        else:
            self._consecutive_same = 0
        self._last_cmd = command

    def _commands_per_minute(self) -> float:
        """Compute current commands-per-minute rate from timestamps."""
        if len(self._timestamps) < 2:
            return 0.0
        elapsed = self._timestamps[-1] - self._timestamps[0]
        if elapsed <= 0:
            return 0.0
        return (len(self._timestamps) - 1) / elapsed * 60.0

    def _inter_command_delay_std(self) -> float:
        """Return standard deviation of gaps between consecutive commands.

        Returns a very large value when fewer than 3 commands have been seen,
        so new sessions are not mis-classified from insufficient data.
        """
        if len(self._timestamps) < 3:
            return 999.0
        gaps = [
            self._timestamps[i] - self._timestamps[i - 1]
            for i in range(1, len(self._timestamps))
        ]
        mean = sum(gaps) / len(gaps)
        variance = sum((g - mean) ** 2 for g in gaps) / len(gaps)
        return math.sqrt(variance)

    def classify(self) -> str:
        """Return 'BOT', 'HUMAN', or 'UNKNOWN' based on accumulated signals."""
        cpm = self._commands_per_minute()
        delay_std = self._inter_command_delay_std()
        total = len(self._commands)
        unique_cats = len(set(self._categories))
        auth_fraction = self._categories.count("AUTH") / max(total, 1)
        has_unknown_cmd = "UNKNOWN" in self._categories

        bot_score = 0
        human_score = 0

        # --- Bot signals ---
        if cpm > config.FAST_TEMPO_CPM:
            bot_score += 1
        if self._consecutive_same >= 3:
            bot_score += 1
        if delay_std < 0.3:
            bot_score += 1
        if auth_fraction > 0.85 and total >= 5:
            bot_score += 1

        # --- Human signals ---
        if cpm < config.SLOW_TEMPO_CPM and total >= 3:
            human_score += 1
        if total >= 10 and unique_cats >= 3:
            human_score += 1
        if has_unknown_cmd:
            human_score += 1
        if delay_std > 1.5:
            human_score += 1

        if bot_score >= config.BOT_SCORE_THRESHOLD:
            return "BOT"
        if human_score >= config.HUMAN_SCORE_THRESHOLD:
            return "HUMAN"
        return "UNKNOWN"

    def get_tempo(self) -> str:
        """Return 'SLOW', 'NORMAL', or 'FAST' based on commands-per-minute."""
        cpm = self._commands_per_minute()
        if cpm >= config.FAST_TEMPO_CPM:
            return "FAST"
        if cpm <= config.SLOW_TEMPO_CPM:
            return "SLOW"
        return "NORMAL"


# ---------------------------------------------------------------------------
# State Builder
# ---------------------------------------------------------------------------

class StateBuilder:
    """Builds RL state tuples from a rolling window of command categories."""

    WINDOW_SIZE = 3

    def __init__(self) -> None:
        # Pre-pad with NULL so the first commands always see a full window
        self._window: deque = deque(
            ["NULL"] * self.WINDOW_SIZE, maxlen=self.WINDOW_SIZE
        )

    def update(self, category: str) -> None:
        """Add a new category to the rolling window."""
        self._window.append(category)

    def get_state(self, classifier: BehaviorClassifier) -> Tuple[tuple, str, str]:
        """Return a state tuple: (window_tuple, tempo, behavior_class)."""
        window_tuple = tuple(self._window)
        tempo = classifier.get_tempo()
        behavior_class = classifier.classify()
        return (window_tuple, tempo, behavior_class)


# ---------------------------------------------------------------------------
# Q-Learning Agent
# ---------------------------------------------------------------------------

def _state_to_key(state: Tuple) -> str:
    """Serialize a state tuple to a JSON-safe string key."""
    window, tempo, bclass = state
    return f"{','.join(window)}|{tempo}|{bclass}"


class QLearningAgent:
    """Tabular Q-learning agent for adapting honeypot response strategies.

    The Q-table persists to JSON between runs so learning accumulates
    across many demo sessions.
    """

    NUM_ACTIONS = len(config.ACTION_NAMES)

    def __init__(self, q_table_path: str = config.Q_TABLE_PATH) -> None:
        self._path = q_table_path
        self.epsilon: float = config.EPSILON_START
        # Q-table: state_key -> {action_str -> q_value}
        self._q_table: Dict[str, Dict[str, float]] = {}
        self._lock = threading.Lock()
        self.load_q_table()

    def load_q_table(self) -> None:
        """Load Q-table from JSON; start fresh if file is absent or corrupt."""
        try:
            with open(self._path, "r") as fh:
                data = json.load(fh)
            self.epsilon = float(data.get("_epsilon", config.EPSILON_START))
            self._q_table = {k: v for k, v in data.items() if not k.startswith("_")}
        except FileNotFoundError:
            pass  # First run — empty Q-table is expected
        except (json.JSONDecodeError, KeyError, ValueError):
            self._q_table = {}  # Corrupted file — start fresh

    def save_q_table(self) -> None:
        """Persist Q-table and current epsilon to JSON."""
        with self._lock:
            data = dict(self._q_table)
            data["_epsilon"] = self.epsilon
            try:
                with open(self._path, "w") as fh:
                    json.dump(data, fh, indent=2)
            except OSError as exc:
                print(f"[QLearningAgent] Could not save Q-table: {exc}")

    def _ensure_state(self, state_key: str) -> None:
        """Initialise Q-values to 0.0 for any state not yet seen."""
        if state_key not in self._q_table:
            self._q_table[state_key] = {str(a): 0.0 for a in range(self.NUM_ACTIONS)}

    def get_q_values(self, state: Tuple) -> Dict[str, float]:
        """Return a copy of Q-values for all actions in the given state."""
        key = _state_to_key(state)
        with self._lock:
            self._ensure_state(key)
            return dict(self._q_table[key])

    def select_action(self, state: Tuple) -> int:
        """Choose an action via ε-greedy policy.

        Explores (random action) with probability epsilon, otherwise
        exploits the action with the highest Q-value, breaking ties
        randomly to avoid systematic strategy bias.
        """
        if random.random() < self.epsilon:
            return random.randint(0, self.NUM_ACTIONS - 1)

        q_vals = self.get_q_values(state)
        best_val = max(q_vals.values())
        # Collect all actions tied at best_val to break ties fairly
        best_actions = [int(a) for a, v in q_vals.items() if v == best_val]
        return random.choice(best_actions)

    def update(
        self,
        state: Tuple,
        action: int,
        reward: float,
        next_state: Tuple,
    ) -> None:
        """Apply the Bellman Q-learning update.

        Q(s,a) ← Q(s,a) + α * (r + γ * max_a'Q(s',a') - Q(s,a))
        """
        state_key = _state_to_key(state)
        next_key = _state_to_key(next_state)

        with self._lock:
            self._ensure_state(state_key)
            self._ensure_state(next_key)

            current_q = self._q_table[state_key][str(action)]
            max_next_q = max(self._q_table[next_key].values())

            td_error = reward + config.GAMMA * max_next_q - current_q
            self._q_table[state_key][str(action)] += config.ALPHA * td_error

    def decay_epsilon(self) -> None:
        """Multiply epsilon by the decay rate, clamping to EPSILON_MIN."""
        self.epsilon = max(
            config.EPSILON_MIN,
            self.epsilon * config.EPSILON_DECAY,
        )

    @property
    def total_states(self) -> int:
        """Number of unique states recorded in the Q-table."""
        return len(self._q_table)


# ---------------------------------------------------------------------------
# Reward Calculator
# ---------------------------------------------------------------------------

class RewardCalculator:
    """Computes step-level and session-level reward signals.

    One instance per session. Maintains just enough state to detect
    patterns across consecutive commands (last action, command history).
    """

    def __init__(self) -> None:
        self._last_action: Optional[int] = None
        self._category_history: list = []

    def step_reward(
        self,
        category: str,
        behavior_class: str,
        action_id: int,
        continued: bool,
        new_category: bool,
    ) -> float:
        """Compute the reward signal for one command step.

        Args:
            category:       Command category of the current command.
            behavior_class: Attacker classification at this moment.
            action_id:      The action the agent chose for this step.
            continued:      True if the attacker sent another command.
            new_category:   True if this category is new in this session.

        Returns:
            Scalar reward (positive = desirable, negative = undesirable).
        """
        reward = 0.0

        # Engagement continuation: attacker stayed and sent another command
        if continued:
            reward += config.W_ENGAGE

        # Diversity: first time this category appears in the session
        if new_category:
            reward += config.W_DIVERSITY

        # Lure interaction: attacker sent a FILE command right after DECOY_LURE
        # (action_id 2 = DECOY_LURE; we check the *previous* action)
        if category == "FILE" and self._last_action == 2:
            reward += config.W_LURE

        # Human-behaviour coefficient: amplify reward for human-like attackers
        if behavior_class == "HUMAN":
            reward *= 1.5
        elif behavior_class == "BOT":
            # Bots are less valuable; penalise rather than reward further
            reward -= config.W_BOT

        # Repeated-command penalty: sign of scripted/bot behaviour
        if self._category_history and self._category_history[-1] == category:
            reward -= 0.5

        # Immediate disconnect: attacker left without sending another command
        if not continued:
            reward -= 1.0

        self._last_action = action_id
        self._category_history.append(category)
        return reward

    def engagement_score(
        self,
        duration: float,
        command_count: int,
        behavior_class: str,
    ) -> float:
        """Compute a normalised engagement quality score for the full session.

        Formula: duration * log(command_count + 1) * human_coeff
        human_coeff: HUMAN=1.5, UNKNOWN=1.0, BOT=0.3
        """
        human_coeff = {"HUMAN": 1.5, "UNKNOWN": 1.0, "BOT": 0.3}.get(behavior_class, 1.0)
        return duration * math.log(command_count + 1) * human_coeff

    def session_reward(
        self,
        duration: float,
        unique_categories: int,
        behavior_class: str,
        command_count: int,
    ) -> float:
        """Compute an end-of-session bonus reward.

        Rewards sessions that were long, diverse, and human-like.
        """
        score = self.engagement_score(duration, command_count, behavior_class)
        diversity_bonus = unique_categories * config.W_DIVERSITY

        if behavior_class == "BOT":
            # Heavily discount bot sessions — low intelligence value
            return score * 0.3 + diversity_bonus * 0.3
        if behavior_class == "HUMAN":
            return score * 1.5 + diversity_bonus

        return score + diversity_bonus
