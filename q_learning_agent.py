"""Q-learning agent components for RL-Honeypot.

Provides BehaviorClassifier, StateBuilder, QLearningAgent, and RewardCalculator.

Changes vs original:
  Fix 2 — BehaviorClassifier: erken sınıflandırma (2 komuttan itibaren),
           yeni sinyaller (EXEC/PERSIST=HUMAN, pure-auth=BOT), eşik düzeltmesi.
  Fix 4 — StateBuilder: pencere 3→5 (config.STATE_WINDOW_SIZE), oturum derinliği
           (EARLY/MID/LATE) state'e eklendi → 4-tuple.
  Fix 5 — RewardCalculator: kategori ağırlıkları, TTP ilerleme bonusu,
           EXEC/PERSIST yüksek değer bonusu.
  Fix 1 — QLearningAgent.update(): daha önce hiç görülmemiş state'e
           girince exploration bonusu verilir.
"""

import json
import math
import random
import threading
from collections import deque
from typing import Dict, Optional, Tuple

import config


# ---------------------------------------------------------------------------
# Behaviour Classifier  (Fix 2)
# ---------------------------------------------------------------------------

class BehaviorClassifier:
    """Classifies attacker behaviour as BOT, HUMAN, or UNKNOWN.

    Improvements over original:
    - 2 komuttan itibaren aşırı sinyallerde hızlı sınıflandırma.
    - Yeni BOT sinyali: çok hızlı CPM, pure-AUTH oturumu.
    - Yeni HUMAN sinyali: EXEC/PERSIST kategorisi (bot'lar bu kadar ilerlemez).
    - Eşikler düşürüldü: daha kısa oturumlarda da sınıflandırılabilir.
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
        if len(self._timestamps) < 2:
            return 0.0
        elapsed = self._timestamps[-1] - self._timestamps[0]
        if elapsed <= 0:
            return 0.0
        return (len(self._timestamps) - 1) / elapsed * 60.0

    def _inter_command_delay_std(self) -> float:
        """Std-dev of inter-command gaps.  999 when fewer than 3 commands."""
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
        """Return 'BOT', 'HUMAN', or 'UNKNOWN'.

        Fix 2 improvements:
        - 2 komuttan sonra aşırı sinyallerde erken karar (fast-path).
        - BOT: çok hızlı CPM (1.5x eşik), pure-AUTH, ek puan.
        - HUMAN: EXEC/PERSIST görülürse +2 puan (güçlü insan sinyali),
                 5+ komut & 2+ kategori eşiği (eski: 10/3).
        """
        cpm           = self._commands_per_minute()
        delay_std     = self._inter_command_delay_std()
        total         = len(self._commands)
        unique_cats   = len(set(self._categories))
        auth_fraction = self._categories.count("AUTH") / max(total, 1)
        has_unknown   = "UNKNOWN" in self._categories
        has_exec_persist = any(c in ("EXEC", "PERSIST") for c in self._categories)

        # ── Erken fast-path: 2 komut yeterli, aşırı sinyal varsa karar ver ──
        if total >= 2:
            very_fast = cpm > config.FAST_TEMPO_CPM * 1.5
            very_low_std = delay_std < 0.15
            if very_fast and very_low_std:
                return "BOT"
            if auth_fraction == 1.0 and self._consecutive_same >= 2:
                return "BOT"

        if total < 3:
            return "UNKNOWN"

        bot_score   = 0
        human_score = 0

        # ── BOT sinyalleri ────────────────────────────────────────────────
        if cpm > config.FAST_TEMPO_CPM:
            bot_score += 1
        if cpm > config.FAST_TEMPO_CPM * 1.5:
            bot_score += 1          # çok hızlı: ekstra puan
        if self._consecutive_same >= 3:
            bot_score += 1
        if delay_std < 0.3:
            bot_score += 1
        if auth_fraction > 0.80 and total >= 3:   # eskisi: 0.85 / 5 komut
            bot_score += 1
        if auth_fraction == 1.0 and total >= 3:   # tamamen AUTH
            bot_score += 1

        # ── HUMAN sinyalleri ─────────────────────────────────────────────
        if cpm < config.SLOW_TEMPO_CPM and total >= 2:   # eskisi: total >= 3
            human_score += 1
        if total >= 5 and unique_cats >= 2:               # eskisi: 10 / 3
            human_score += 1
        if total >= 10 and unique_cats >= 3:
            human_score += 1        # ekstra çeşitlilik bonusu
        if has_unknown:
            human_score += 1
        if delay_std > 1.5:
            human_score += 1
        if has_exec_persist:
            human_score += 2        # EXEC/PERSIST: çok güçlü HUMAN sinyali

        if bot_score >= config.BOT_SCORE_THRESHOLD:
            return "BOT"
        if human_score >= config.HUMAN_SCORE_THRESHOLD:
            return "HUMAN"
        return "UNKNOWN"

    def get_tempo(self) -> str:
        """Return 'SLOW', 'NORMAL', or 'FAST'."""
        cpm = self._commands_per_minute()
        if cpm >= config.FAST_TEMPO_CPM:
            return "FAST"
        if cpm <= config.SLOW_TEMPO_CPM:
            return "SLOW"
        return "NORMAL"


# ---------------------------------------------------------------------------
# State Builder  (Fix 4)
# ---------------------------------------------------------------------------

class StateBuilder:
    """Builds RL state tuples from a rolling window of command categories.

    Fix 4 improvements:
    - Pencere boyutu config.STATE_WINDOW_SIZE'dan okunur (varsayılan 5, eskisi 3).
    - Oturum derinliği (EARLY/MID/LATE) state'in 4. boyutu olarak eklendi.
    State format: (window_tuple, tempo, behavior_class, depth)
    Key format  : "c1,c2,c3,c4,c5|TEMPO|BEHAVIOR|DEPTH"
    """

    WINDOW_SIZE: int = config.STATE_WINDOW_SIZE   # 5 (eskisi sabit 3)

    def __init__(self) -> None:
        self._window: deque = deque(
            ["NULL"] * self.WINDOW_SIZE, maxlen=self.WINDOW_SIZE
        )
        self._command_count: int = 0

    def update(self, category: str) -> None:
        """Add a new category to the rolling window."""
        self._window.append(category)
        self._command_count += 1

    def _depth(self) -> str:
        """Bucket session depth: EARLY / MID / LATE."""
        if self._command_count <= config.DEPTH_EARLY_MAX:
            return "EARLY"
        if self._command_count <= config.DEPTH_MID_MAX:
            return "MID"
        return "LATE"

    def get_state(
        self, classifier: BehaviorClassifier
    ) -> Tuple[tuple, str, str, str]:
        """Return (window_tuple, tempo, behavior_class, depth)."""
        return (
            tuple(self._window),
            classifier.get_tempo(),
            classifier.classify(),
            self._depth(),
        )


# ---------------------------------------------------------------------------
# Q-Learning Agent  (Fix 1 — exploration bonus)
# ---------------------------------------------------------------------------

def _state_to_key(state: Tuple) -> str:
    """Serialize a 4-element state tuple to a JSON-safe string key."""
    window, tempo, bclass, depth = state
    return f"{','.join(window)}|{tempo}|{bclass}|{depth}"


class QLearningAgent:
    """Tabular Q-learning agent.

    Fix 1: update() fonksiyonu hiç görülmemiş state'lere exploration bonusu
    verir; bu, eğitim boyunca daha geniş bir state uzayını örtmeyi teşvik eder.
    """

    NUM_ACTIONS = len(config.ACTION_NAMES)

    def __init__(self, q_table_path: str = config.Q_TABLE_PATH) -> None:
        self._path = q_table_path
        self.epsilon: float = config.EPSILON_START
        self._q_table: Dict[str, Dict[str, float]] = {}
        self._lock = threading.Lock()
        self.load_q_table()

    def load_q_table(self) -> None:
        """Load Q-table from JSON; start fresh if absent or corrupt."""
        try:
            with open(self._path, "r") as fh:
                data = json.load(fh)
            self.epsilon = float(data.get("_epsilon", config.EPSILON_START))
            self._q_table = {k: v for k, v in data.items() if not k.startswith("_")}
        except FileNotFoundError:
            pass
        except (json.JSONDecodeError, KeyError, ValueError):
            self._q_table = {}

    def save_q_table(self) -> None:
        """Persist Q-table and epsilon to JSON."""
        with self._lock:
            data = dict(self._q_table)
            data["_epsilon"] = self.epsilon
            try:
                with open(self._path, "w") as fh:
                    json.dump(data, fh, indent=2)
            except OSError as exc:
                print(f"[QLearningAgent] Could not save Q-table: {exc}")

    # Optimistic initialization değeri: her aksiyon keşfedilmeden önce
    # "umut verici" görünmeli.  W_LURE / 2 ≈ 1.5 makul bir başlangıç.
    _OPTIMISTIC_INIT: float = 1.5

    def _ensure_state(self, state_key: str) -> bool:
        """Initialise Q-values for unseen state.  Returns True if it was new.

        Optimistic initialization: 0 yerine _OPTIMISTIC_INIT ile başla.
        Bu, ajanı her state'te tüm aksiyonları denemek zorunda bırakır;
        Q-table az veriyle bile daha tutarlı bir politikaya yakınsar.
        """
        if state_key not in self._q_table:
            self._q_table[state_key] = {
                str(a): self._OPTIMISTIC_INIT for a in range(self.NUM_ACTIONS)
            }
            return True
        return False

    def get_q_values(self, state: Tuple) -> Dict[str, float]:
        key = _state_to_key(state)
        with self._lock:
            self._ensure_state(key)
            return dict(self._q_table[key])

    def select_action(self, state: Tuple) -> int:
        """ε-greedy action selection with random tie-breaking."""
        if random.random() < self.epsilon:
            return random.randint(0, self.NUM_ACTIONS - 1)
        q_vals = self.get_q_values(state)
        best_val = max(q_vals.values())
        best_actions = [int(a) for a, v in q_vals.items() if v == best_val]
        return random.choice(best_actions)

    def update(
        self,
        state: Tuple,
        action: int,
        reward: float,
        next_state: Tuple,
    ) -> None:
        """Bellman update with exploration bonus for newly discovered states.

        Fix 1: Eğer state daha önce hiç görülmemişse reward'a
        config.EXPLORATION_BONUS eklenir — yeni state'leri keşfetmek teşvik edilir.
        """
        state_key = _state_to_key(state)
        next_key  = _state_to_key(next_state)

        with self._lock:
            is_new = self._ensure_state(state_key)
            self._ensure_state(next_key)

            # Fix 1: yeni state → küçük keşif bonusu
            if is_new:
                reward += config.EXPLORATION_BONUS

            current_q  = self._q_table[state_key][str(action)]
            max_next_q = max(self._q_table[next_key].values())

            td_error = reward + config.GAMMA * max_next_q - current_q
            self._q_table[state_key][str(action)] += config.ALPHA * td_error

    def decay_epsilon(self) -> None:
        self.epsilon = max(config.EPSILON_MIN, self.epsilon * config.EPSILON_DECAY)

    @property
    def total_states(self) -> int:
        return len(self._q_table)


# ---------------------------------------------------------------------------
# Reward Calculator  (Fix 5)
# ---------------------------------------------------------------------------

class RewardCalculator:
    """Computes step-level and session-level reward signals.

    Fix 5 improvements:
    - Kategori ağırlıkları (config.CATEGORY_WEIGHTS): derin kill-chain
      kategorileri daha yüksek reward verir.
    - TTP ilerleme bonusu: AUTH→RECON→FILE→EXEC→PERSIST zincirine ilerlemek
      config.TTP_PROGRESSION_BONUS ekler.
    - EXEC/PERSIST kategorisi config.EXEC_PERSIST_BONUS ek bonus alır.
    """

    _TTP_ORDER = ["AUTH", "RECON", "FILE", "EXEC", "PERSIST"]

    def __init__(self) -> None:
        self._last_action: Optional[int] = None
        self._category_history: list = []

    def _ttp_index(self, category: str) -> int:
        """Kill-chain indeksi; tanınmayan kategoriler için -1 döner."""
        try:
            return self._TTP_ORDER.index(category)
        except ValueError:
            return -1

    def step_reward(
        self,
        category: str,
        behavior_class: str,
        action_id: int,
        continued: bool,
        new_category: bool,
    ) -> float:
        """Online step reward with TTP weights and progression bonus."""
        reward = 0.0
        cat_weight = config.CATEGORY_WEIGHTS.get(category, 1.0)

        # Engagement: saldırgan devam etti, kategori ağırlığıyla
        if continued:
            reward += config.W_ENGAGE * cat_weight

        # Çeşitlilik: ilk kez bu kategori
        if new_category:
            reward += config.W_DIVERSITY
            # TTP ilerleme bonusu: önceki kategoriden daha derin mi?
            if self._category_history:
                prev_idx = self._ttp_index(self._category_history[-1])
                curr_idx = self._ttp_index(category)
                if curr_idx > prev_idx >= 0:
                    reward += config.TTP_PROGRESSION_BONUS

        # Lure etkisi: DECOY_LURE sonrası FILE komutu
        if category == "FILE" and self._last_action == 2:
            reward += config.W_LURE

        # EXEC / PERSIST yüksek değer bonusu
        if category in ("EXEC", "PERSIST"):
            reward += config.EXEC_PERSIST_BONUS

        # Davranış katsayısı
        if behavior_class == "HUMAN":
            reward *= 1.5
        elif behavior_class == "BOT":
            reward -= config.W_BOT

        # Tekrar cezası
        if self._category_history and self._category_history[-1] == category:
            reward -= 0.5

        # Bağlantı kopması cezası
        if not continued:
            reward -= 1.0

        self._last_action = action_id
        self._category_history.append(category)
        return reward

    def transition_reward(
        self,
        observed_category: str,
        behavior_class: str,
        action_id: int,
        continued: bool,
        new_category: bool,
        previous_category: Optional[str] = None,
    ) -> float:
        """Offline (trainer) reward — same logic as step_reward, stateless form."""
        reward = 0.0
        cat_weight = config.CATEGORY_WEIGHTS.get(observed_category, 1.0)

        if continued:
            reward += config.W_ENGAGE * cat_weight

        if new_category:
            reward += config.W_DIVERSITY
            if previous_category is not None:
                prev_idx = self._ttp_index(previous_category)
                curr_idx = self._ttp_index(observed_category)
                if curr_idx > prev_idx >= 0:
                    reward += config.TTP_PROGRESSION_BONUS

        if observed_category == "FILE" and action_id == 2:
            reward += config.W_LURE

        if observed_category in ("EXEC", "PERSIST"):
            reward += config.EXEC_PERSIST_BONUS

        if behavior_class == "HUMAN":
            reward *= 1.5
        elif behavior_class == "BOT":
            reward -= config.W_BOT

        if previous_category is not None and previous_category == observed_category:
            reward -= 0.5

        if not continued:
            reward -= 1.0

        return reward

    def engagement_score(
        self,
        duration: float,
        command_count: int,
        behavior_class: str,
    ) -> float:
        """Normalised engagement quality score for a full session."""
        human_coeff = {"HUMAN": 1.5, "UNKNOWN": 1.0, "BOT": 0.3}.get(behavior_class, 1.0)
        return duration * math.log(command_count + 1) * human_coeff

    def session_reward(
        self,
        duration: float,
        unique_categories: int,
        behavior_class: str,
        command_count: int,
    ) -> float:
        """End-of-session bonus reward."""
        score = self.engagement_score(duration, command_count, behavior_class)
        diversity_bonus = unique_categories * config.W_DIVERSITY

        if behavior_class == "BOT":
            return score * 0.3 + diversity_bonus * 0.3
        if behavior_class == "HUMAN":
            return score * 1.5 + diversity_bonus
        return score + diversity_bonus
