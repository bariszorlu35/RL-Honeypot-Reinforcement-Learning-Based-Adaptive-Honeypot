"""RL-adaptive honeypot for RL-Honeypot.

Listens on 127.0.0.1:2324. Shares one QLearningAgent across all sessions.
Each session gets its own BehaviorClassifier, StateBuilder, and RewardCalculator.

Run with: python honeypot_rl.py
"""

import socket
import threading
import time
import uuid

import config
import database
from q_learning_agent import (
    BehaviorClassifier,
    QLearningAgent,
    RewardCalculator,
    StateBuilder,
)
from response_strategies import categorize_command, get_response

# One shared agent that learns across all sessions; lock protects Q-table access
_agent = QLearningAgent(q_table_path=config.Q_TABLE_PATH)
_agent_lock = threading.Lock()


def _handle_client(conn: socket.socket, addr: tuple) -> None:
    """Handle one attacker connection; apply ε-greedy RL policy per command."""
    session_id = uuid.uuid4().hex[:8]
    start_time = time.time()
    command_count = 0
    total_reward = 0.0
    categories_seen: set = set()
    attacker_profile = "unknown"

    # Per-session RL components — fresh state for each new attacker
    classifier = BehaviorClassifier()
    state_builder = StateBuilder()
    reward_calc = RewardCalculator()

    prev_state = None
    prev_action = None

    print(f"[RL Honeypot] New connection {addr[0]}:{addr[1]} → session {session_id}")

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

            # Allow simulator to communicate the attacker profile
            if raw.startswith("#PROFILE:"):
                attacker_profile = raw.split(":", 1)[1].strip()
                continue

            command_count += 1
            timestamp = time.time()
            category = categorize_command(raw)
            new_category = category not in categories_seen
            categories_seen.add(category)

            # Update per-session classifiers with this command
            classifier.update(raw, category, timestamp)
            state_builder.update(category)
            current_state = state_builder.get_state(classifier)

            # Select action under agent lock to prevent concurrent Q-table corruption
            with _agent_lock:
                action_id = _agent.select_action(current_state)

            action_name = config.ACTION_NAMES[action_id]

            # Apply any strategy-specific delay, then send response
            delay, response_text = get_response(action_id, raw)
            if delay > 0:
                time.sleep(delay)
            try:
                conn.sendall((response_text + "\r\n$ ").encode())
            except OSError:
                break

            # Step reward — continued=True because the loop is still running
            behavior_class = classifier.classify()
            step_r = reward_calc.step_reward(
                category=category,
                behavior_class=behavior_class,
                action_id=action_id,
                continued=True,
                new_category=new_category,
            )
            total_reward += step_r

            # Update Q-table for the *previous* step now that we have the next state
            if prev_state is not None and prev_action is not None:
                with _agent_lock:
                    _agent.update(prev_state, prev_action, step_r, current_state)

            database.log_command(
                session_id=session_id,
                command=raw,
                category=category,
                action_taken=action_name,
                reward=step_r,
                timestamp=timestamp,
            )

            print(
                f"[RL Honeypot] Session {session_id}: "
                f"cmd={raw!r} action={action_name} "
                f"reward={step_r:.2f} epsilon={_agent.epsilon:.3f}"
            )

            prev_state = current_state
            prev_action = action_id

    except Exception as exc:
        print(f"[RL Honeypot] Session {session_id} error: {exc}")
    finally:
        duration = time.time() - start_time
        behavior_class = classifier.classify()
        engagement = reward_calc.engagement_score(duration, command_count, behavior_class)

        # End-of-session reward and final Q-table update
        if prev_state is not None and prev_action is not None:
            end_reward = reward_calc.session_reward(
                duration=duration,
                unique_categories=len(categories_seen),
                behavior_class=behavior_class,
                command_count=command_count,
            )
            total_reward += end_reward

            terminal_state = state_builder.get_state(classifier)
            with _agent_lock:
                _agent.update(prev_state, prev_action, end_reward, terminal_state)
                _agent.decay_epsilon()
                _agent.save_q_table()

        database.log_session(
            mode="rl",
            session_id=session_id,
            attacker_profile=attacker_profile,
            start_time=start_time,
            duration=duration,
            command_count=command_count,
            unique_categories=len(categories_seen),
            behavior_class=behavior_class,
            engagement_score=engagement,
            total_reward=total_reward,
        )
        conn.close()
        print(
            f"[RL Honeypot] Session {session_id} ended: "
            f"duration={duration:.1f}s cmds={command_count} "
            f"total_reward={total_reward:.2f} behavior={behavior_class} "
            f"profile={attacker_profile}"
        )


def run() -> None:
    """Start the RL honeypot server and accept connections until Ctrl+C."""
    database.init_db()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((config.HOST, config.RL_PORT))
    server.listen(10)
    server.settimeout(1.0)

    print(f"[RL Honeypot] Listening on {config.HOST}:{config.RL_PORT}")
    print(f"[RL Honeypot] Q-table path: {config.Q_TABLE_PATH}")
    print(f"[RL Honeypot] Starting epsilon: {_agent.epsilon:.3f}")
    print("[RL Honeypot] Press Ctrl+C to stop.")

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
        print("\n[RL Honeypot] Shutting down gracefully.")
    finally:
        server.close()


if __name__ == "__main__":
    run()
