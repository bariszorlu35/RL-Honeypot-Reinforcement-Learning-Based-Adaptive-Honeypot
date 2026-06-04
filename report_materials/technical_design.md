# RL-Honeypot — Technical Design Document

**Course:** Computer and Network Security  
**Project:** RL-Honeypot — Adaptive Low-Interaction Honeypot with Tabular Q-Learning  

---

## 1. Project Overview

RL-Honeypot is a local-only proof-of-concept that demonstrates how a honeypot can
adapt its response strategy to maximise the information value of attacker sessions.

Two systems run in parallel on localhost:

- **Static honeypot (port 2323)** — fixed decision rule: unknown commands receive a
  shell error; all categorised commands receive a fake-success response.
- **RL honeypot (port 2324)** — tabular Q-learning agent selects from five strategies
  per command, updating its policy after every session.

The primary research question is: *Does an adaptive strategy produce higher engagement
quality (measured as engagement score) than a static strategy, across all three
attacker profiles?*

---

## 2. State Space Definition

The RL state is a 4-tuple:

```
state = (last_3_command_categories, tempo, behavior_class, depth)
```

| Component | Values | Description |
|-----------|--------|-------------|
| `last_3_command_categories` | Tuple of 3 strings | Rolling window of the last three command categories, padded with `"NULL"` at session start |
| `tempo` | `"SLOW"`, `"NORMAL"`, `"FAST"` | Commands per minute: <10 = SLOW, >60 = FAST |
| `behavior_class` | `"BOT"`, `"HUMAN"`, `"UNKNOWN"` | Classification based on scoring signals |
| `depth` | `"EARLY"`, `"MID"`, `"LATE"` | Session phase based on command count |

**Example states:**

```
(("NULL", "NULL", "AUTH"), "FAST", "BOT", "EARLY")       — new bot session, auth commands only
(("RECON", "FILE", "EXEC"), "SLOW", "HUMAN", "MID")      — experienced human, deliberate pace
(("AUTH", "RECON", "PERSIST"), "NORMAL", "UNKNOWN", "LATE") — mixed signals
```

**State space size:** The theoretical maximum is approximately
`9³ × 3 × 3 × 3 = 19,683` states (8 command categories plus NULL, 3 tempos,
3 behaviour classes, 3 depth buckets). In practice far fewer states are visited
because most attack sessions follow predictable patterns.

---

## 3. Command Categories

| Category | Keywords (first word of command) |
|----------|----------------------------------|
| `AUTH` | login, user, pass, su, sudo, passwd |
| `RECON` | ls, dir, pwd, whoami, uname, id, ps, netstat, ifconfig, ip, history, env, ss |
| `SCAN` | nmap, masscan, nikto, dirb, gobuster, dirsearch, wfuzz, ffuf |
| `FILE` | cat, wget, curl, get, put, download, upload, ftp, scp, cp, mv, tar, find |
| `EXEC` | sh, bash, exec, python, python3, perl, ruby, php, nc, netcat |
| `EXPLOIT` | sqlmap, hydra, medusa, msfconsole, msfvenom, metasploit, wpscan |
| `PERSIST` | crontab, chmod, chown, echo, tee, systemctl, service, useradd |
| `UNKNOWN` | anything else (typos, novel commands, tool-specific syntax) |

---

## 4. Action Space Definition

| ID | Strategy | Description |
|----|----------|-------------|
| 0 | `SILENT_ERROR` | Generic shell error — discourages automated tools without revealing system details |
| 1 | `FAKE_SUCCESS` | Context-aware fake response — believable output for ls, whoami, ps, etc. |
| 2 | `DECOY_LURE` | Fake success + embedded hint toward seemingly valuable files (backup.tar.gz, config.env) |
| 3 | `SLOW_RESPONSE` | Fake success with a 2-second artificial delay — wastes bot time, tests human patience |
| 4 | `HONEYTRAP_OFFER` | Fake success + hint toward a fake high-value target (admin portal, credentials archive) |

The agent selects an action per command using ε-greedy selection over the Q-table.
During exploitation, Q-values are combined with a configurable state-aware action
prior (`ACTION_PRIOR_WEIGHT`). This prior encodes simple honeypot domain knowledge:
bots are slowed or discouraged, unknown sessions are kept engaged with decoys, and
deep human-like sessions are steered toward honeytrap offers.

---

## 5. Reward Function

### Per-step reward

```
reward = 0

if attacker_continued:          reward += W_ENGAGE  (1.0)
if new_category_in_session:     reward += W_DIVERSITY (1.5)
if FILE_cmd after DECOY_LURE:   reward += W_LURE    (3.0)

if behavior_class == "HUMAN":   reward *= 1.5
if behavior_class == "BOT":     reward -= W_BOT     (2.0)

if category == prev_category:   reward -= 0.5   # repeat penalty
if not attacker_continued:      reward -= 1.0   # disconnect penalty
```

### End-of-session reward

```
engagement_score = duration × log(command_count + 1) × human_coeff
human_coeff: HUMAN=1.5, UNKNOWN=1.0, BOT=0.3

session_bonus = engagement_score × multiplier + unique_categories × W_DIVERSITY
multipliers: HUMAN=1.5×, UNKNOWN=1.0×, BOT=0.3×
```

### Reward matrix (representative state-action expected rewards after 30 sessions)

The exact values depend on training data; the table below shows the *designed*
incentive structure before learning:

| State (simplified) | SILENT_ERROR | FAKE_SUCCESS | DECOY_LURE | SLOW_RESPONSE | HONEYTRAP_OFFER |
|---------------------|-------------|-------------|-----------|--------------|----------------|
| BOT / AUTH repeat | −1.5 | −1.0 | −1.0 | 0.5 | −0.5 |
| UNKNOWN / RECON | 0.0 | +1.0 | +2.5 | +0.5 | +1.5 |
| HUMAN / FILE diverse | 0.0 | +1.5 | +4.5 | +1.0 | +3.5 |
| HUMAN / EXEC | 0.0 | +2.2 | +2.5 | +1.5 | +4.0 |

*Note: These are approximate design-time values. The agent's actual Q-table after
training may differ based on the session data from the demo run.*

---

## 6. Behaviour Classification

The `BehaviorClassifier` increments `bot_score` and `human_score` based on
observable signals:

**Bot signals (each +1 to `bot_score`):**
- Commands per minute > 60
- Commands per minute > 90 gives an additional fast-tempo point
- Same command repeated 3+ times consecutively
- Inter-command delay standard deviation < 0.3 s
- >80% of commands in the session are AUTH category (and ≥3 commands)
- 100% AUTH traffic gives an additional point

**Human signals (each +1 to `human_score`):**
- Commands per minute < 10 (and ≥2 commands seen)
- ≥2 unique categories after at least 5 commands
- ≥3 unique categories after at least 10 commands
- At least one UNKNOWN command (typo or tool-specific)
- Inter-command delay standard deviation > 1.5 s
- Any EXEC or PERSIST command gives a strong human-like signal

**Classification rule:**
```python
if bot_score >= 3:      behavior_class = "BOT"
elif human_score >= 2:  behavior_class = "HUMAN"
else:                   behavior_class = "UNKNOWN"
```

---

## 7. Static Baseline Design

The static honeypot is intentionally simple:

1. Accept TCP connection on `127.0.0.1:2323`
2. Send Ubuntu 20.04 banner
3. For each received command:
   - Categorise with `categorize_command()`
   - `UNKNOWN` → `SILENT_ERROR` (action 0)
   - Anything else → `FAKE_SUCCESS` (action 1)
4. Log every command and session to SQLite with `mode="static"`

The static honeypot computes an engagement score at session end using the same
formula as the RL honeypot (with `human_coeff=1.0` since it performs no behaviour
classification). This enables a fair comparison in the dashboard.

---

## 8. RL Honeypot Design

1. Accept TCP connection on `127.0.0.1:2324`
2. Send Ubuntu 20.04 banner
3. Load shared `QLearningAgent` (persists across all sessions)
4. For each received command:
   a. Classify command → update `BehaviorClassifier` and `StateBuilder`
   b. Build `current_state` tuple
   c. Select `action_id` via ε-greedy (`select_action`)
   d. Apply response strategy → optional delay → send response text
   e. Compute step reward
   f. Update Q-table: `update(prev_state, prev_action, reward, current_state)`
   g. Log command to database
5. At session end:
   - Compute session-end bonus reward
   - Final Q-table update with terminal state
   - Decay epsilon: `ε ← max(ε_min, ε × ε_decay)`
   - Save Q-table to `q_table.json`
   - Log session to database

All Q-table operations are guarded by `threading.Lock` to support concurrent
attacker sessions.

---

## 9. Evaluation Metrics

| Metric | Definition | Where computed |
|--------|-----------|----------------|
| Engagement Score | `duration × log(cmds+1) × human_coeff` | `RewardCalculator.engagement_score()` |
| Total Reward | Sum of all step rewards + session bonus | `honeypot_rl.py` |
| Cumulative Reward | Running total of per-session total_reward | Dashboard Tab 3 |
| Mean Engagement by Profile | Average engagement score grouped by mode and attacker profile | Dashboard Tab 2 |
| Behaviour Distribution | Count of BOT/HUMAN/UNKNOWN per mode | Dashboard Tab 4 |
| Avg Session Duration | Mean of `duration` column per behaviour class | Dashboard Tab 4 |
| RL Success vs Best Fixed | `rl_eval_avg_reward / best_fixed_avg_reward` | `train_model.py --compare-baselines` |
| RL vs Random Improvement | `(rl_eval_avg_reward - random_avg_reward) / random_avg_reward` | `train_model.py --compare-baselines` |

Current offline benchmark:

| Metric | Value |
|--------|-------|
| Training sessions | 100,000 |
| Evaluation sessions | 8,000 |
| Training epsilon floor | 0.05 |
| Evaluation epsilon | 0.00 |
| RL learned policy avg reward | 394.097 |
| Random baseline avg reward | 201.890 |
| Best fixed baseline | `always_honeytrap` |
| Best fixed avg reward | 410.949 |
| Success vs best fixed | 95.9% |
| Improvement vs random | +95.2% |

---

## 10. Demo Scenario

**Recommended demo sequence (30+30 sessions):**

1. Clear database (dashboard sidebar)
2. Start both honeypots in separate terminals
3. Run 30 static sessions: `python simulate_attacker.py --mode static --sessions 30`
4. Run 30 RL sessions: `python simulate_attacker.py --mode rl --sessions 30`
5. Open dashboard — show all five tabs
6. Run 10 more RL sessions: `--sessions 10 --profile operator`
7. Refresh dashboard — show Q-table heatmap has changed (agent has learned)

The RL honeypot should show higher mean engagement scores for operator and
script_kiddie profiles, and lower engagement for bot profiles (by design — bots
receive SLOW_RESPONSE and SILENT_ERROR to waste their time).

---

## 11. Safety Boundaries

| Constraint | Implementation |
|------------|---------------|
| Localhost-only binding | `HOST = "127.0.0.1"` in config.py; `server.bind((config.HOST, port))` |
| No real command execution | All responses are pre-written strings; no subprocess/os.system anywhere |
| Non-privileged ports | 2323, 2324 — no root required |
| No external connectivity | Simulator connects only to `config.HOST` (127.0.0.1) |
| No real credentials | All fake credentials marked `# FAKE CREDENTIAL` in source |
| No destructive payloads | No shellcode, no exploit strings, no persistence mechanisms |
| Thread-safe database | `threading.Lock` on all write operations |
