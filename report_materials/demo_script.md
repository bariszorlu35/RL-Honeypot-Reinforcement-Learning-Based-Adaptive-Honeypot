# RL-Honeypot — 10-Minute Live Demo Script

**Audience:** Course instructor / security seminar  
**Setup required before demo:** `pip install -r requirements.txt` completed; four
terminal windows open, all in the `rl-honeypot/` directory.

---

## Setup (1 min before demo starts)

In **Terminal 1** start the static honeypot:
```bash
python honeypot_static.py
```
Expected output:
```
[Static Honeypot] Listening on 127.0.0.1:2323
[Static Honeypot] Press Ctrl+C to stop.
```

In **Terminal 2** start the RL honeypot:
```bash
python honeypot_rl.py
```
Expected output:
```
[RL Honeypot] Listening on 127.0.0.1:2324
[RL Honeypot] Q-table path: q_table.json
[RL Honeypot] Starting epsilon: 1.000
[RL Honeypot] Press Ctrl+C to stop.
```

In **Terminal 4** start the dashboard:
```bash
streamlit run dashboard.py
```
Open the browser URL (usually `http://localhost:8501`).

---

## Minute 0–1: Introduction

> *"Today I'm demonstrating RL-Honeypot — a comparison between a static honeypot and
> one that learns its response strategy using Q-learning. Both run locally on
> 127.0.0.1. The RL agent adapts which of five strategies to use based on how the
> attacker is behaving: are they a fast scripted bot, or a slow, deliberate human?
> The agent's goal is to maximise what I'm calling engagement quality — keeping
> high-value attackers engaged longer while wasting bots' time."*

Point to the dashboard — show the empty Session Overview tab.

> *"The dashboard is live against a local SQLite database. Right now it's empty —
> we'll populate it in the next few minutes."*

---

## Minute 1–3: Run Static Baseline (Terminal 3)

```bash
python simulate_attacker.py --mode static --sessions 30
```

Expected terminal output (repeating):
```
[Simulator] Session 1/30 | profile=bot | commands=8 | duration=1.4s
[Simulator] Session 2/30 | profile=operator | commands=22 | duration=53.1s
...
[Simulator] Done. Total: 30 sessions | Avg duration: 18.2s | Avg commands: 11.4
Profile breakdown: bot=12  operator=9  script_kiddie=9
```

While sessions run, switch to the Static Honeypot terminal and show a few log lines:
```
[Static Honeypot] Session a3f2c1: cmd='ls' category=RECON action=FAKE_SUCCESS
[Static Honeypot] Session a3f2c1: cmd='whoami' category=RECON action=FAKE_SUCCESS
[Static Honeypot] Session b7e912: cmd='user admin' category=AUTH action=FAKE_SUCCESS
```

> *"Notice the static honeypot uses the same two actions regardless of who's
> attacking. A bot hammering credential commands gets the same response as a human
> operator doing reconnaissance."*

---

## Minute 3–5: Run RL Training (Terminal 3)

```bash
python simulate_attacker.py --mode rl --sessions 30
```

Switch to the RL Honeypot terminal and highlight the changing values:
```
[RL Honeypot] Session c4d2a1: cmd='ls' action=DECOY_LURE reward=4.00 epsilon=0.98
[RL Honeypot] Session c4d2a1: cmd='cat config.env' action=HONEYTRAP_OFFER reward=7.50 epsilon=0.98
[RL Honeypot] Session d1f3b2: cmd='user admin' action=SLOW_RESPONSE reward=-1.00 epsilon=0.97
```

> *"See the `action=` field changing. Early sessions are mostly random — epsilon is
> near 1.0 so the agent is exploring. Notice the high reward when a DECOY_LURE was
> followed by the attacker requesting a FILE — that's the lure interaction bonus.
> And the bot session gets SLOW_RESPONSE — wasting its time — which is penalised
> in reward terms but correctly discourages the agent from serving bots efficiently."*

> *"Epsilon is decaying: `0.995^n`. After 30 sessions it will be around 0.86 —
> still exploring but starting to exploit learned preferences."*

---

## Minute 5–7: Dashboard Tour

Click **Refresh Data** in the sidebar.

### Tab 1 — Session Overview
> *"Green rows are HUMAN-classified sessions — long, diverse, high thinking time.
> Red rows are BOT sessions. Notice the engagement_score column: operator sessions
> score much higher than bot sessions in both modes, but the RL mode should already
> show slightly higher scores for human-like profiles."*

### Tab 2 — Engagement Comparison
> *"This grouped bar chart compares mean engagement score for each profile. The
> percentages shown are calculated live from the database — I haven't hardcoded
> any numbers. After only 30 sessions of training the RL agent may not dominate
> significantly yet, which is realistic — we need more data."*

### Tab 3 — Reward Curve
> *"The dashed green line is a rolling average over 5 sessions. You'd expect it to
> rise over time as the agent moves from random exploration to learned strategies."*

### Tab 4 — Behaviour Classification
> *"The static honeypot doesn't classify behaviour — everything is UNKNOWN. The RL
> honeypot correctly labels the bot profile as BOT and the operator profile as HUMAN.
> The bar chart shows that HUMAN sessions last much longer on average."*

---

## Minute 7–9: More Training + Q-Table

Run 20 more RL sessions focused on operator profile:
```bash
python simulate_attacker.py --mode rl --sessions 20 --profile operator
```

Refresh the dashboard and go to **Tab 5 — Q-Table View**.

> *"This heatmap shows the top 20 most-valued states the agent has encountered.
> Green cells mean the agent has learned this action is rewarding in this state.
> For HUMAN states with diverse recent commands, you should see DECOY_LURE and
> HONEYTRAP_OFFER lighting up green — the agent has learned to lure methodical
> human-like attackers toward fake sensitive files."*

> *"The current epsilon value shows how much the agent is still exploring. By the
> end of a full demo with 100+ sessions it will be under 0.1 — mostly exploiting
> its learned policy."*

---

## Minute 9–10: Summary

> *"In summary: the static honeypot gives every attacker the same experience.
> The RL honeypot learns that patient, curious attackers are worth engaging deeply
> with DECOY_LURE and HONEYTRAP_OFFER, while rapid scripted bots get slowed down
> or given errors — yielding less intelligence for them and less wasted effort for
> the defender. The Q-table encodes this policy and persists between runs, so the
> agent gets smarter every time the demo is run."*

> *"The entire project runs on localhost with standard library networking. No real
> commands are executed anywhere — all responses are pre-written text."*

---

## Likely Instructor Questions

**Q1: Why tabular Q-learning instead of a neural network (DQN)?**

> The state space for this scenario is small — at most a few thousand states — so
> a neural network would be massive overkill and would make the reward function hard
> to inspect. Tabular Q-learning is O(1) lookup, fully transparent (the Q-table
> is a readable JSON file), and converges reliably on small, well-defined state
> spaces. A DQN would make sense if we added natural language processing of raw
> command strings, which is out of scope here.

**Q2: How does the engagement score avoid just rewarding session duration?**

> The formula is `duration × log(command_count+1) × human_coeff`. The logarithm
> prevents a single long idle session from inflating the score — a session with
> 1 command and a long timeout scores poorly. The `human_coeff` (1.5 for HUMAN,
> 0.3 for BOT) means a bot session must be 5× longer than a human session to reach
> the same score, which matches the threat model: human operator sessions contain
> more intelligence value. The step-level reward also includes diversity bonuses
> and lure-interaction bonuses, so the agent is rewarded for *quality* of
> engagement, not just duration.

**Q3: What stops the simulator from connecting to external IPs?**

> The simulator hard-codes `host = config.HOST` which is the string `"127.0.0.1"`.
> There is no hostname resolution, no domain lookup, and no user-supplied URL
> in the connection code. The `socket.connect((host, port))` call will fail with
> `ConnectionRefusedError` if the honeypot is not running locally — the code
> handles this gracefully and prints an error rather than retrying or changing targets.

**Q4: How would you extend this to a real deployment?**

> Several changes would be needed for production use: (1) Replace the telnet-style
> protocol with an SSH server using a library like Paramiko, which would attract real
> SSH scan traffic. (2) Bind to a real network interface and configure firewall rules
> to restrict traffic. (3) Add IP-level session tracking and geolocation logging.
> (4) Replace the tabular agent with a DQN or contextual bandit if the raw command
> text is used as input. (5) Add alerting integration for when HUMAN-classified
> sessions exhibit high-value command patterns. Each of these is architecturally
> separated from the current code — the database layer, response strategies, and
> agent are all independently replaceable.

**Q5: Is the behaviour classifier accurate? What are its failure modes?**

> The classifier is intentionally conservative — it requires at least 3 bot signals
> to label a session BOT, and 2 human signals for HUMAN. Failure modes include:
> (1) *False HUMAN*: a well-crafted bot that injects random delays and typos will
> score human signals. (2) *Slow convergence*: with very short sessions (<5 commands)
> there isn't enough data, so everything is UNKNOWN — which is the safe default.
> (3) *Tempo conflation*: a human on a fast connection could be flagged as FAST.
> In a real deployment you would want to combine this with network-layer signals
> (TTL, TCP fingerprinting) for more reliable classification.

**Q6: Why use five strategies and not more?**

> Five is a deliberate balance. Too few actions (2–3) makes the learned policy
> trivially simple and limits the research question. Too many actions (10+) makes
> the Q-table sparse for a short demo — the agent needs to visit `states × actions`
> combinations to have meaningful Q-values. Five strategies cover the four
> archetypal honeypot responses described in the academic literature (error,
> success, lure, delay) plus a compound honeytrap that combines lure and success.
> Increasing to 7–10 strategies would require proportionally more training sessions
> to see meaningful learning.
