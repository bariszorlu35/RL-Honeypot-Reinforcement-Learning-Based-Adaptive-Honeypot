"""Fast offline trainer for the RL-Honeypot Q-learning agent.

The live honeypot learns online from socket sessions. That is useful for demos,
but slow because it waits for realistic attacker timing and SLOW_RESPONSE
delays. This trainer uses the same QLearningAgent, StateBuilder,
BehaviorClassifier, RewardCalculator, and command categorizer, while simulating
virtual time and action-dependent attacker reactions.
"""

import argparse
import json
import random
import statistics
from collections import Counter, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional

import config
from q_learning_agent import (
    BehaviorClassifier,
    QLearningAgent,
    RewardCalculator,
    StateBuilder,
)
from response_strategies import categorize_command
from simulate_attacker import PROFILES


PROFILE_MIX = ["bot"] * 4 + ["script_kiddie"] * 3 + ["operator"] * 3
NO_BOT_PROFILE_MIX = ["script_kiddie"] * 4 + ["operator"] * 6

BASE_CONTINUE_PROB = {
    "bot": 0.78,
    "script_kiddie": 0.90,
    "operator": 0.94,
}

ACTION_CONTINUE_DELTA = {
    "bot": {
        0: -0.18,  # SILENT_ERROR
        1: 0.04,   # FAKE_SUCCESS
        2: 0.02,   # DECOY_LURE
        3: -0.22,  # SLOW_RESPONSE
        4: 0.00,   # HONEYTRAP_OFFER
    },
    "script_kiddie": {
        0: -0.08,
        1: 0.04,
        2: 0.08,
        3: -0.10,
        4: 0.05,
    },
    "operator": {
        0: -0.05,
        1: 0.04,
        2: 0.12,
        3: -0.04,
        4: 0.10,
    },
}

LURE_FOLLOW_PROB = {
    "bot": 0.04,
    "script_kiddie": 0.35,
    "operator": 0.55,
}

HONEYTRAP_FOLLOW_PROB = {
    "bot": 0.03,
    "script_kiddie": 0.25,
    "operator": 0.45,
}

POLICY_SEED_OFFSETS = {
    "random": 101,
    "always_fake_success": 211,
    "always_decoy_lure": 307,
    "always_honeytrap": 401,
    "always_silent_error": 503,
    "always_slow_response": 601,
}


@dataclass
class Observation:
    command: str
    category: str
    state: tuple
    new_category: bool


@dataclass
class SessionStats:
    profile: str
    commands: int
    reward: float
    behavior_class: str
    unique_categories: int


def _build_command_index() -> Dict[str, List[str]]:
    by_category: Dict[str, List[str]] = {}
    all_commands = {
        command
        for profile in PROFILES.values()
        for command in profile["command_pool"]
    }

    for command in sorted(all_commands):
        category = categorize_command(command)
        by_category.setdefault(category, []).append(command)

    return by_category


COMMANDS_BY_CATEGORY = _build_command_index()


def _weighted_profile(
    rng: random.Random,
    forced_profile: str,
    include_bot: bool,
) -> str:
    if forced_profile:
        return forced_profile
    profile_mix = PROFILE_MIX if include_bot else NO_BOT_PROFILE_MIX
    return rng.choice(profile_mix)


def _clamp_probability(value: float) -> float:
    return max(0.05, min(0.99, value))


def _should_continue(profile_name: str, action_id: int, rng: random.Random) -> bool:
    base = BASE_CONTINUE_PROB[profile_name]
    delta = ACTION_CONTINUE_DELTA[profile_name].get(action_id, 0.0)
    return rng.random() < _clamp_probability(base + delta)


def _commands_for_categories(categories: Iterable[str]) -> List[str]:
    commands: List[str] = []
    for category in categories:
        commands.extend(COMMANDS_BY_CATEGORY.get(category, []))
    return commands


def _choose_command(
    profile_name: str,
    rng: random.Random,
    last_command: str = "",
    previous_action: Optional[int] = None,
) -> str:
    profile = PROFILES[profile_name]

    if previous_action == 2 and rng.random() < LURE_FOLLOW_PROB[profile_name]:
        lure_commands = _commands_for_categories(["FILE"])
        if lure_commands:
            return rng.choice(lure_commands)

    if previous_action == 4 and rng.random() < HONEYTRAP_FOLLOW_PROB[profile_name]:
        trap_commands = _commands_for_categories(["FILE", "EXEC", "PERSIST"])
        if trap_commands:
            return rng.choice(trap_commands)

    if last_command and rng.random() < profile["repeat_probability"]:
        return last_command

    return rng.choice(profile["command_pool"])


def _observe(
    command: str,
    profile_name: str,
    rng: random.Random,
    classifier: BehaviorClassifier,
    state_builder: StateBuilder,
    categories_seen: set,
    timestamp: float,
) -> tuple[Observation, float]:
    delay_min, delay_max = PROFILES[profile_name]["inter_command_delay"]
    timestamp += rng.uniform(delay_min, delay_max)

    category = categorize_command(command)
    new_category = category not in categories_seen
    categories_seen.add(category)

    classifier.update(command, category, timestamp)
    state_builder.update(category)

    return (
        Observation(
            command=command,
            category=category,
            state=state_builder.get_state(classifier),
            new_category=new_category,
        ),
        timestamp,
    )


def _train_one_session(
    agent: QLearningAgent,
    profile_name: str,
    rng: random.Random,
) -> tuple[SessionStats, Counter]:
    profile = PROFILES[profile_name]
    target_length = rng.randint(*profile["session_length"])

    classifier = BehaviorClassifier()
    state_builder = StateBuilder()
    reward_calc = RewardCalculator()
    categories_seen: set = set()
    action_counts: Counter = Counter()

    timestamp = 0.0
    total_reward = 0.0
    commands_seen = 0

    command = _choose_command(profile_name, rng)
    obs, timestamp = _observe(
        command,
        profile_name,
        rng,
        classifier,
        state_builder,
        categories_seen,
        timestamp,
    )
    commands_seen += 1

    while True:
        action_id = agent.select_action(obs.state)
        action_counts[config.ACTION_NAMES[action_id]] += 1

        reached_length = commands_seen >= target_length
        if reached_length or not _should_continue(profile_name, action_id, rng):
            behavior_class = classifier.classify()
            terminal_step_reward = reward_calc.transition_reward(
                observed_category=obs.category,
                behavior_class=behavior_class,
                action_id=action_id,
                continued=False,
                new_category=False,
                previous_category=None,
            )
            session_bonus = reward_calc.session_reward(
                duration=timestamp,
                unique_categories=len(categories_seen),
                behavior_class=behavior_class,
                command_count=commands_seen,
            )
            # CREDIT ASSIGNMENT FIX:
            # session_bonus (100-200 puan) son aksiyona atanıyordu — yanlış.
            # Q-güncelleme SADECE terminal_step_reward ile yapılır.
            # session_bonus izleme/raporlama için ayrıca kaydedilir.
            agent.update(
                obs.state,
                action_id,
                terminal_step_reward,
                obs.state,
                terminal=True,
            )
            total_reward += terminal_step_reward + session_bonus
            break

        next_command = _choose_command(
            profile_name,
            rng,
            last_command=obs.command,
            previous_action=action_id,
        )
        next_obs, timestamp = _observe(
            next_command,
            profile_name,
            rng,
            classifier,
            state_builder,
            categories_seen,
            timestamp,
        )
        commands_seen += 1

        behavior_class = classifier.classify()
        reward = reward_calc.transition_reward(
            observed_category=next_obs.category,
            behavior_class=behavior_class,
            action_id=action_id,
            continued=True,
            new_category=next_obs.new_category,
            previous_category=obs.category,
        )
        agent.update(obs.state, action_id, reward, next_obs.state)
        total_reward += reward
        obs = next_obs

    agent.decay_epsilon()

    return (
        SessionStats(
            profile=profile_name,
            commands=commands_seen,
            reward=total_reward,
            behavior_class=classifier.classify(),
            unique_categories=len(categories_seen),
        ),
        action_counts,
    )


# ---------------------------------------------------------------------------
# Fix 3: Baseline policies
# ---------------------------------------------------------------------------

def _run_baseline_session(
    action_fn,
    profile_name: str,
    rng: random.Random,
) -> SessionStats:
    """Run one session with a fixed (non-learning) policy and return stats."""
    profile = PROFILES[profile_name]
    target_length = rng.randint(*profile["session_length"])

    classifier    = BehaviorClassifier()
    state_builder = StateBuilder()
    reward_calc   = RewardCalculator()
    categories_seen: set = set()

    timestamp    = 0.0
    total_reward = 0.0
    commands_seen = 0

    command = _choose_command(profile_name, rng)
    obs, timestamp = _observe(
        command, profile_name, rng, classifier, state_builder, categories_seen, timestamp
    )
    commands_seen += 1

    while True:
        action_id     = action_fn(obs.state)
        reached_length = commands_seen >= target_length

        if reached_length or not _should_continue(profile_name, action_id, rng):
            behavior_class = classifier.classify()
            terminal_r = reward_calc.transition_reward(
                observed_category=obs.category,
                behavior_class=behavior_class,
                action_id=action_id,
                continued=False,
                new_category=False,
                previous_category=None,
            )
            bonus = reward_calc.session_reward(
                duration=timestamp,
                unique_categories=len(categories_seen),
                behavior_class=behavior_class,
                command_count=commands_seen,
            )
            total_reward += terminal_r + bonus
            break

        next_command = _choose_command(
            profile_name, rng, last_command=obs.command, previous_action=action_id
        )
        next_obs, timestamp = _observe(
            next_command, profile_name, rng, classifier, state_builder, categories_seen, timestamp
        )
        commands_seen += 1

        behavior_class = classifier.classify()
        r = reward_calc.transition_reward(
            observed_category=next_obs.category,
            behavior_class=behavior_class,
            action_id=action_id,
            continued=True,
            new_category=next_obs.new_category,
            previous_category=obs.category,
        )
        total_reward += r
        obs = next_obs

    return SessionStats(
        profile=profile_name,
        commands=commands_seen,
        reward=total_reward,
        behavior_class=classifier.classify(),
        unique_categories=len(categories_seen),
    )


def run_baselines(
    sessions: int,
    include_bot: bool,
    seed: int,
    verbose: bool = True,
) -> dict:
    """Her sabit policy için N oturum çalıştır, ortalama reward'ı karşılaştır.

    Policies:
      random              — uniform rastgele aksiyon
      always_fake_success — her zaman aksiyon 1
      always_decoy_lure   — her zaman aksiyon 2
      always_honeytrap    — her zaman aksiyon 4
      always_silent_error — her zaman aksiyon 0
      always_slow_response — her zaman aksiyon 3
    """
    policies: dict = {
        "random":              None,            # özel durum — aşağıda ele alınır
        "always_fake_success": lambda s: 1,
        "always_decoy_lure":   lambda s: 2,
        "always_honeytrap":    lambda s: 4,
        "always_silent_error": lambda s: 0,
        "always_slow_response": lambda s: 3,
    }

    results: dict = {}
    for policy_name, action_fn in policies.items():
        rng_p = random.Random(seed + POLICY_SEED_OFFSETS[policy_name])

        if action_fn is None:
            # random policy: farklı bir rng kullanarak her çağrıda rastgele
            def _random_fn(state, r=rng_p):
                return r.randint(0, len(config.ACTION_NAMES) - 1)
            action_fn = _random_fn

        total_reward   = 0.0
        total_commands = 0
        beh_counts: Counter = Counter()

        for _ in range(sessions):
            profile_name = _weighted_profile(rng_p, "", include_bot)
            stats = _run_baseline_session(action_fn, profile_name, rng_p)
            total_reward   += stats.reward
            total_commands += stats.commands
            beh_counts[stats.behavior_class] += 1

        avg_r = round(total_reward   / max(sessions, 1), 3)
        avg_c = round(total_commands / max(sessions, 1), 3)
        results[policy_name] = {
            "avg_reward":   avg_r,
            "avg_commands": avg_c,
            "behaviors":    dict(beh_counts),
        }
        if verbose:
            print(f"  [Baseline] {policy_name:25s}  avg_reward={avg_r:8.2f}  avg_cmds={avg_c:.1f}")

    return results


def _series_summary(values: List[float], digits: int = 3) -> dict:
    """Return mean/std/min/max for a numeric series."""
    if not values:
        return {"mean": 0.0, "std": 0.0, "min": 0.0, "max": 0.0}
    return {
        "mean": round(statistics.mean(values), digits),
        "std": round(statistics.stdev(values), digits) if len(values) > 1 else 0.0,
        "min": round(min(values), digits),
        "max": round(max(values), digits),
    }


def evaluate_learned_policy(
    agent: QLearningAgent,
    sessions: int,
    include_bot: bool,
    seed: int,
) -> dict:
    """Evaluate the learned policy with exploration disabled and no Q updates."""
    original_epsilon = agent.epsilon
    agent.epsilon = 0.0

    rng = random.Random(seed)
    random.seed(seed)
    total_reward = 0.0
    total_commands = 0
    profile_counts: Counter = Counter()
    behavior_counts: Counter = Counter()
    action_counts: Counter = Counter()

    def _learned_action(state):
        action_id = agent.select_action(state)
        action_counts[config.ACTION_NAMES[action_id]] += 1
        return action_id

    try:
        for _ in range(sessions):
            profile_name = _weighted_profile(rng, "", include_bot)
            stats = _run_baseline_session(_learned_action, profile_name, rng)
            total_reward += stats.reward
            total_commands += stats.commands
            profile_counts[stats.profile] += 1
            behavior_counts[stats.behavior_class] += 1
    finally:
        agent.epsilon = original_epsilon

    return {
        "sessions": sessions,
        "epsilon": 0.0,
        "avg_reward": round(total_reward / max(sessions, 1), 3),
        "avg_commands": round(total_commands / max(sessions, 1), 3),
        "profiles": dict(profile_counts),
        "behaviors": dict(behavior_counts),
        "actions": dict(action_counts),
    }


def run_multi_seed_benchmark(
    agent: QLearningAgent,
    seed: int,
    seed_count: int,
    seed_stride: int,
    evaluation_sessions: int,
    baseline_sessions: int,
    include_bot: bool,
) -> dict:
    """Evaluate RL and fixed baselines over multiple deterministic seeds."""
    seeds = [seed + index * seed_stride for index in range(seed_count)]
    rl_rewards: List[float] = []
    rl_commands: List[float] = []
    fixed_rewards: Dict[str, List[float]] = {}
    random_rewards: List[float] = []

    for eval_seed in seeds:
        eval_result = evaluate_learned_policy(
            agent=agent,
            sessions=evaluation_sessions,
            include_bot=include_bot,
            seed=eval_seed,
        )
        rl_rewards.append(eval_result["avg_reward"])
        rl_commands.append(eval_result["avg_commands"])

        baseline_results = run_baselines(
            sessions=baseline_sessions,
            include_bot=include_bot,
            seed=eval_seed - 1,
            verbose=False,
        )
        for policy_name, result in baseline_results.items():
            fixed_rewards.setdefault(policy_name, []).append(result["avg_reward"])
        random_rewards.append(baseline_results["random"]["avg_reward"])

    fixed_summaries = {
        policy_name: _series_summary(values)
        for policy_name, values in fixed_rewards.items()
    }
    best_fixed_policy = max(
        fixed_summaries,
        key=lambda policy_name: fixed_summaries[policy_name]["mean"],
    )
    rl_reward_summary = _series_summary(rl_rewards)
    best_fixed_summary = fixed_summaries[best_fixed_policy]
    random_summary = _series_summary(random_rewards)

    rl_mean = rl_reward_summary["mean"]
    best_mean = best_fixed_summary["mean"]
    random_mean = random_summary["mean"]
    per_seed_success = [
        rl_reward / max(fixed_reward, 1e-9) * 100.0
        for rl_reward, fixed_reward in zip(
            rl_rewards,
            fixed_rewards[best_fixed_policy],
        )
    ]

    return {
        "seed_count": seed_count,
        "seeds": seeds,
        "evaluation_sessions_per_seed": evaluation_sessions,
        "baseline_sessions_per_policy_per_seed": baseline_sessions,
        "rl_reward": rl_reward_summary,
        "rl_commands": _series_summary(rl_commands),
        "random_reward": random_summary,
        "best_fixed_policy": best_fixed_policy,
        "best_fixed_reward": best_fixed_summary,
        "fixed_policy_rewards": fixed_summaries,
        "success_vs_best_fixed_pct": round(rl_mean / max(best_mean, 1e-9) * 100, 2),
        "rl_vs_best_fixed_pct": round((rl_mean - best_mean) / max(best_mean, 1e-9) * 100, 2),
        "rl_vs_random_pct": round((rl_mean - random_mean) / max(random_mean, 1e-9) * 100, 2),
        "per_seed_success_vs_best_fixed_pct": _series_summary(per_seed_success, digits=2),
        "rl_reward_values": [round(value, 3) for value in rl_rewards],
        "best_fixed_reward_values": [
            round(value, 3) for value in fixed_rewards[best_fixed_policy]
        ],
    }


def train(
    sessions: int,
    q_table_path: str,
    forced_profile: str,
    include_bot: bool,
    seed: int,
    reset: bool,
    progress_every: int,
    compare_baselines: bool = False,
    baseline_sessions: int = 2000,
    evaluation_sessions: int = 5000,
    evaluation_seed_count: int = 1,
    evaluation_seed_stride: int = 17,
) -> dict:
    if reset:
        Path(q_table_path).unlink(missing_ok=True)

    rng = random.Random(seed)
    agent = QLearningAgent(q_table_path=q_table_path)

    profile_counts: Counter = Counter()
    behavior_counts: Counter = Counter()
    action_counts: Counter = Counter()
    reward_window: deque = deque(maxlen=250)
    total_commands = 0
    total_reward = 0.0

    for index in range(1, sessions + 1):
        profile_name = _weighted_profile(rng, forced_profile, include_bot)
        stats, actions = _train_one_session(agent, profile_name, rng)

        profile_counts[stats.profile] += 1
        behavior_counts[stats.behavior_class] += 1
        action_counts.update(actions)
        reward_window.append(stats.reward)
        total_commands += stats.commands
        total_reward += stats.reward

        if progress_every and index % progress_every == 0:
            avg_recent = sum(reward_window) / max(len(reward_window), 1)
            print(
                "[Trainer] "
                f"{index}/{sessions} sessions | "
                f"states={agent.total_states} | "
                f"epsilon={agent.epsilon:.3f} | "
                f"avg_recent_reward={avg_recent:.2f}"
            )

    agent.save_q_table()

    rl_avg = total_reward / max(sessions, 1)

    summary = {
        "sessions": sessions,
        "seed": seed,
        "q_table_path": q_table_path,
        "forced_profile": forced_profile,
        "include_bot": include_bot,
        "states": agent.total_states,
        "epsilon": agent.epsilon,
        "total_commands": total_commands,
        "avg_commands_per_session": total_commands / max(sessions, 1),
        "avg_reward_per_session": rl_avg,
        "avg_recent_reward": sum(reward_window) / max(len(reward_window), 1),
        "profiles": dict(profile_counts),
        "behaviors": dict(behavior_counts),
        "actions": dict(action_counts),
    }

    # Fix 3: baseline karşılaştırması
    if compare_baselines:
        print(f"\n[Trainer] Öğrenilmiş policy test ediliyor ({evaluation_sessions} oturum, epsilon=0.00)...")
        eval_result = evaluate_learned_policy(
            agent=agent,
            sessions=evaluation_sessions,
            include_bot=include_bot,
            seed=seed + 2,
        )

        print(f"\n[Trainer] Baseline politikalar çalıştırılıyor ({baseline_sessions} oturum / policy)...")
        bl_results = run_baselines(baseline_sessions, include_bot, seed + 1)

        best_name = max(bl_results, key=lambda k: bl_results[k]["avg_reward"])
        best_avg  = bl_results[best_name]["avg_reward"]
        rand_avg  = bl_results["random"]["avg_reward"]
        rl_eval_avg = eval_result["avg_reward"]

        def _pct(a: float, b: float) -> float:
            return round((a - b) / max(abs(b), 1e-9) * 100, 2)

        summary["baseline_comparison"] = {
            "rl_avg_reward":         round(rl_eval_avg, 3),
            "rl_training_avg_reward": round(rl_avg, 3),
            "rl_evaluation":         eval_result,
            "random_avg_reward":     round(rand_avg, 3),
            "best_fixed_policy":     best_name,
            "best_fixed_avg_reward": round(best_avg, 3),
            "rl_success_vs_best_fixed_pct": round(
                rl_eval_avg / max(abs(best_avg), 1e-9) * 100,
                2,
            ),
            "rl_vs_random_pct":      _pct(rl_eval_avg, rand_avg),
            "rl_vs_best_fixed_pct":  _pct(rl_eval_avg, best_avg),
            "baselines":             bl_results,
        }
        print(
            f"\n[Trainer] Karşılaştırma özeti:"
            f"\n  RL train avg    : {rl_avg:.2f}"
            f"\n  RL eval ε=0     : {rl_eval_avg:.2f}"
            f"\n  Random policy   : {rand_avg:.2f}"
            f"\n  Best fixed ({best_name}): {best_avg:.2f}"
            f"\n  Success vs best : {summary['baseline_comparison']['rl_success_vs_best_fixed_pct']:.1f}%"
            f"\n  RL vs random    : {summary['baseline_comparison']['rl_vs_random_pct']:+.1f}%"
            f"\n  RL vs best fixed: {summary['baseline_comparison']['rl_vs_best_fixed_pct']:+.1f}%"
        )

        if evaluation_seed_count > 1:
            print(
                f"\n[Trainer] Multi-seed benchmark çalıştırılıyor "
                f"({evaluation_seed_count} seed × {evaluation_sessions} RL eval oturumu)..."
            )
            multi_seed = run_multi_seed_benchmark(
                agent=agent,
                seed=seed + 2,
                seed_count=evaluation_seed_count,
                seed_stride=evaluation_seed_stride,
                evaluation_sessions=evaluation_sessions,
                baseline_sessions=baseline_sessions,
                include_bot=include_bot,
            )
            summary["multi_seed_evaluation"] = multi_seed
            print(
                f"\n[Trainer] Multi-seed özeti:"
                f"\n  RL mean reward       : {multi_seed['rl_reward']['mean']:.2f}"
                f"\n  Best fixed policy    : {multi_seed['best_fixed_policy']}"
                f"\n  Best fixed mean      : {multi_seed['best_fixed_reward']['mean']:.2f}"
                f"\n  Success vs best      : {multi_seed['success_vs_best_fixed_pct']:.2f}%"
                f"\n  RL vs best fixed     : {multi_seed['rl_vs_best_fixed_pct']:+.2f}%"
                f"\n  RL vs random         : {multi_seed['rl_vs_random_pct']:+.2f}%"
                f"\n  Per-seed success min : "
                f"{multi_seed['per_seed_success_vs_best_fixed_pct']['min']:.2f}%"
            )

    return summary


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fast offline Q-table trainer for RL-Honeypot"
    )
    parser.add_argument(
        "--sessions",
        type=int,
        default=5000,
        help="Number of simulated sessions to train on",
    )
    parser.add_argument(
        "--profile",
        choices=list(PROFILES.keys()),
        default="",
        help="Train only one profile; default is the project 40/30/30 mix",
    )
    parser.add_argument(
        "--no-bot",
        action="store_true",
        help="Exclude the bot profile from the default mixed training schedule",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=20260603,
        help="Deterministic random seed",
    )
    parser.add_argument(
        "--q-table",
        default=config.Q_TABLE_PATH,
        help="Q-table JSON path to write",
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Start from an empty Q-table instead of resuming",
    )
    parser.add_argument(
        "--progress-every",
        type=int,
        default=500,
        help="Print progress every N sessions; set 0 to disable",
    )
    parser.add_argument(
        "--summary",
        default="training_summary.json",
        help="Path for the JSON training summary",
    )
    # Fix 3: baseline karşılaştırması
    parser.add_argument(
        "--compare-baselines",
        action="store_true",
        help="Eğitim sonrası sabit politikalarla karşılaştır (random, always-FAKE_SUCCESS, vb.)",
    )
    parser.add_argument(
        "--baseline-sessions",
        type=int,
        default=2000,
        help="--compare-baselines için her politikada kaç oturum (varsayılan: 2000)",
    )
    parser.add_argument(
        "--eval-sessions",
        type=int,
        default=5000,
        help="--compare-baselines için epsilon=0 learned-policy test oturumu",
    )
    parser.add_argument(
        "--eval-seed-count",
        type=int,
        default=1,
        help="Kaç farklı seed ile evaluation yapılacağı (varsayılan: 1)",
    )
    parser.add_argument(
        "--eval-seed-stride",
        type=int,
        default=17,
        help="Multi-seed evaluation için seed artış değeri",
    )

    args = parser.parse_args()
    if args.no_bot and args.profile == "bot":
        parser.error("--no-bot cannot be combined with --profile bot")

    summary = train(
        sessions=args.sessions,
        q_table_path=args.q_table,
        forced_profile=args.profile,
        include_bot=not args.no_bot,
        seed=args.seed,
        reset=args.reset,
        progress_every=args.progress_every,
        compare_baselines=args.compare_baselines,
        baseline_sessions=args.baseline_sessions,
        evaluation_sessions=args.eval_sessions,
        evaluation_seed_count=max(args.eval_seed_count, 1),
        evaluation_seed_stride=max(args.eval_seed_stride, 1),
    )

    with open(args.summary, "w") as fh:
        json.dump(summary, fh, indent=2)

    print("\n[Trainer] Done")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
