"""Professional Streamlit dashboard for RL-Honeypot.

Redesigned with:
- Professional header with live system status
- 6 analysis tabs: Live Traffic, Threat Intelligence, Session Analysis,
  RL Learning, Q-Table Inspector, System Status
- Threat intelligence view (top commands, category × behaviour heatmap)
- RL learning analytics (state coverage, action distribution, training summary)
- Better chart colours and layout
- Export to CSV functionality
- Fixed deprecated Streamlit APIs (use_container_width instead of width="stretch")
- Native auto-refresh (no JS injection)

Run with: streamlit run dashboard.py
"""

import json
import os
import time
from collections import Counter
from datetime import datetime
from typing import Optional

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

import config
import database

# ─────────────────────────────────────────────────────────────────────────────
# Page config
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="RL-Honeypot Dashboard",
    layout="wide",
    page_icon="🍯",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────────────────────────────────────
# Custom CSS — minimal, works in both light and dark modes
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
[data-testid="stMetric"] {
    background: rgba(128,128,128,0.07);
    border: 1px solid rgba(128,128,128,0.18);
    border-radius: 8px;
    padding: 12px 16px 10px 16px;
}
[data-testid="stMetricLabel"] {
    font-size: 0.72rem !important;
    letter-spacing: 0.07em;
    text-transform: uppercase;
    opacity: 0.65;
}
[data-testid="stMetricValue"] { font-size: 1.55rem !important; font-weight: 700; }
.hp-title {
    font-size: 1.65rem;
    font-weight: 800;
    letter-spacing: -0.02em;
    display: inline;
}
.hp-badge {
    background: #e63946;
    color: #fff;
    border-radius: 5px;
    padding: 3px 10px;
    font-size: 0.68rem;
    font-weight: 700;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    vertical-align: middle;
    margin-right: 10px;
}
.status-pill {
    display: inline-block;
    border-radius: 999px;
    padding: 2px 10px;
    font-size: 0.75rem;
    font-weight: 600;
}
.status-active { background: rgba(45,198,83,0.18); color: #2dc653; }
.status-idle   { background: rgba(252,163,17,0.18); color: #fca311; }
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# Colour palette
# ─────────────────────────────────────────────────────────────────────────────
_BEHAVIOR_COLORS = {"HUMAN": "#2dc653", "BOT": "#e63946", "UNKNOWN": "#fca311"}
_MODE_COLORS     = {"rl": "#e63946", "static": "#457b9d"}
_ACTION_COLORS   = {
    "FAKE_SUCCESS":    "#2dc653",
    "DECOY_LURE":      "#fca311",
    "HONEYTRAP_OFFER": "#e63946",
    "SLOW_RESPONSE":   "#457b9d",
    "SILENT_ERROR":    "#6c757d",
}


# ─────────────────────────────────────────────────────────────────────────────
# Data helpers
# ─────────────────────────────────────────────────────────────────────────────

def _load_sessions() -> pd.DataFrame:
    rows = database.get_all_sessions()
    if not rows:
        return pd.DataFrame()
    df = pd.DataFrame(rows)
    if "start_time" in df.columns:
        df["datetime"] = pd.to_datetime(df["start_time"], unit="s", errors="coerce")
    return df


def _load_recent_commands(limit: int = 500) -> pd.DataFrame:
    rows = database.get_recent_commands(limit=limit)
    if not rows:
        return pd.DataFrame()
    df = pd.DataFrame(rows)
    if "timestamp" in df.columns:
        df["datetime"] = pd.to_datetime(df["timestamp"], unit="s", errors="coerce")
        df["time_str"] = df["datetime"].dt.strftime("%H:%M:%S")
    return df


def _load_q_table() -> dict:
    if not os.path.exists(config.Q_TABLE_PATH):
        return {}
    try:
        with open(config.Q_TABLE_PATH) as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError):
        return {}


def _q_summary(raw: dict) -> dict:
    states = [k for k in raw if not k.startswith("_")]
    behavior_counts = Counter()
    profile_hint_counts = Counter()
    for state_key in states:
        parts = state_key.split("|")
        if len(parts) > 2:
            behavior_counts[parts[2]] += 1
        if len(parts) > 4:
            profile_hint_counts[parts[4]] += 1

    return {
        "states":         len(states),
        "epsilon":        raw.get("_epsilon"),
        "bot_states":     behavior_counts["BOT"],
        "human_states":   behavior_counts["HUMAN"],
        "unknown_states": behavior_counts["UNKNOWN"],
        "profile_hints":  dict(profile_hint_counts),
    }


def _load_training_summary() -> dict:
    path = "training_summary.json"
    if not os.path.exists(path):
        return {}
    try:
        with open(path) as fh:
            return json.load(fh)
    except (json.JSONDecodeError, OSError):
        return {}


def _behavior_style(series: pd.Series) -> list:
    _map = {
        "HUMAN":   "background-color:#1a3d2b; color:#2dc653",
        "BOT":     "background-color:#3d1a1a; color:#e63946",
        "UNKNOWN": "background-color:#3d2f0a; color:#fca311",
    }
    return [_map.get(str(v), "") for v in series]


# ─────────────────────────────────────────────────────────────────────────────
# Sidebar
# ─────────────────────────────────────────────────────────────────────────────

def render_sidebar() -> tuple:
    with st.sidebar:
        st.markdown("## 🍯 RL-Honeypot")
        st.caption("Adaptive Q-Learning Honeypot — local-only academic demo")
        st.divider()

        if st.button("🔄 Refresh Data", use_container_width=True):
            st.rerun()

        st.caption(f"🕐 {datetime.now().strftime('%H:%M:%S')}  —  son yükleme")

        auto_refresh = st.checkbox("Auto-refresh", value=False)
        refresh_secs = st.slider(
            "Refresh interval (s)", 2, 30, 5, disabled=not auto_refresh
        )

        st.divider()
        st.markdown("**Ports**")
        st.code(
            f"Static : {config.HOST}:{config.STATIC_PORT}\n"
            f"RL     : {config.HOST}:{config.RL_PORT}",
            language="text",
        )

        st.divider()
        st.markdown("**Quick Commands**")
        st.code(
            "# Start honeypots\n"
            "python honeypot_static.py\n"
            "python honeypot_rl.py\n\n"
            "# Simulate traffic\n"
            "python simulate_attacker.py --mode rl --sessions 20\n\n"
            "# Retrain model\n"
            "python train_model.py --sessions 10000 --reset",
            language="bash",
        )

        st.divider()
        st.markdown("**⚠️ Danger Zone**")
        confirm = st.checkbox("Confirm: delete all session data")
        if st.button("🗑 Clear Database", disabled=not confirm, use_container_width=True):
            database.clear_db()
            st.success("Database cleared.")
            st.rerun()

    return auto_refresh, refresh_secs


# ─────────────────────────────────────────────────────────────────────────────
# Header + KPI strip
# ─────────────────────────────────────────────────────────────────────────────

def render_header(qs: dict) -> None:
    has_data   = qs["states"] > 0
    pill_cls   = "status-active" if has_data else "status-idle"
    pill_label = "● Policy Loaded" if has_data else "○ No Policy"
    now        = datetime.now().strftime("%d %b %Y  •  %H:%M:%S")
    st.markdown(
        f'<div style="display:flex; align-items:center; gap:10px;">'
        f'  <span class="hp-badge">RL-HONEYPOT</span>'
        f'  <span class="hp-title">Adaptive Q-Learning Honeypot Dashboard</span>'
        f'  <span class="status-pill {pill_cls}" style="margin-left:12px">{pill_label}</span>'
        f'  <span style="margin-left:auto; font-size:0.82rem; opacity:0.55; '
        f'             font-variant-numeric:tabular-nums; letter-spacing:0.03em;">'
        f'    🕐 {now}</span>'
        f'</div>',
        unsafe_allow_html=True,
    )
    st.markdown("")


def render_kpi_strip(
    sess_df: pd.DataFrame,
    cmd_df: pd.DataFrame,
    qs: dict,
) -> None:
    total_sess  = len(sess_df) if not sess_df.empty else 0
    rl_sess     = int((sess_df["mode"] == "rl").sum()) if not sess_df.empty and "mode" in sess_df else 0
    static_sess = int((sess_df["mode"] == "static").sum()) if not sess_df.empty and "mode" in sess_df else 0
    total_cmds  = len(cmd_df) if not cmd_df.empty else 0
    eps         = qs["epsilon"]

    c1, c2, c3, c4, c5, c6 = st.columns(6)
    c1.metric("Total Sessions",  total_sess)
    c2.metric("RL Sessions",     rl_sess)
    c3.metric("Static Sessions", static_sess)
    c4.metric("Commands Logged", total_cmds)
    c5.metric("Q-Table States",  qs["states"])
    c6.metric(
        "Epsilon (ε)",
        f"{eps:.4f}" if isinstance(eps, float) else "—",
        delta="exploiting" if isinstance(eps, float) and eps <= 0.10 else "exploring",
        delta_color="normal",
    )


# ─────────────────────────────────────────────────────────────────────────────
# Tab 1 — Live Traffic
# ─────────────────────────────────────────────────────────────────────────────

def render_live_traffic(cmd_df: pd.DataFrame, sess_df: pd.DataFrame) -> None:
    st.subheader("⚡ Live Traffic Feed")

    if cmd_df.empty:
        st.info(
            "No traffic yet.\n\n"
            "**Start a honeypot:**\n"
            "```bash\npython honeypot_rl.py\n```\n"
            "**Then simulate traffic:**\n"
            "```bash\npython simulate_attacker.py --mode rl --sessions 20\n```"
        )
        return

    col1, col2 = st.columns([3, 2])

    with col1:
        tl = cmd_df.sort_values("timestamp").copy()
        tl["cum_reward"] = tl["reward"].fillna(0).cumsum()
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=tl["datetime"],
            y=tl["cum_reward"],
            mode="lines",
            name="Cumulative Reward",
            line=dict(color="#e63946", width=2),
            fill="tozeroy",
            fillcolor="rgba(230,57,70,0.08)",
        ))
        fig.update_layout(
            title="Cumulative Reward Over Time",
            xaxis_title="Time", yaxis_title="Reward",
            height=280, margin=dict(l=8, r=8, t=44, b=8),
            plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
        )
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        action_counts = (
            cmd_df["action_taken"].fillna("UNKNOWN").value_counts().reset_index()
        )
        action_counts.columns = ["action", "count"]
        fig2 = px.bar(
            action_counts, x="count", y="action", orientation="h",
            title="Actions Used",
            color="action", color_discrete_map=_ACTION_COLORS,
        )
        fig2.update_layout(
            height=280, showlegend=False,
            margin=dict(l=8, r=8, t=44, b=8),
            plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
        )
        st.plotly_chart(fig2, use_container_width=True)

    col3, col4 = st.columns(2)

    with col3:
        cat_counts = cmd_df["category"].fillna("UNKNOWN").value_counts().reset_index()
        cat_counts.columns = ["category", "count"]
        fig3 = px.pie(
            cat_counts, names="category", values="count",
            title="Command Categories",
            color_discrete_sequence=px.colors.qualitative.Set3,
        )
        fig3.update_traces(textposition="inside", textinfo="percent+label")
        fig3.update_layout(height=260, margin=dict(l=8, r=8, t=44, b=8), showlegend=False)
        st.plotly_chart(fig3, use_container_width=True)

    with col4:
        beh_counts = (
            cmd_df["behavior_class"].fillna("UNKNOWN").value_counts().reset_index()
        )
        beh_counts.columns = ["behavior", "count"]
        fig4 = px.pie(
            beh_counts, names="behavior", values="count",
            title="Behaviour Classes",
            color="behavior", color_discrete_map=_BEHAVIOR_COLORS,
        )
        fig4.update_traces(textposition="inside", textinfo="percent+label")
        fig4.update_layout(height=260, margin=dict(l=8, r=8, t=44, b=8), showlegend=False)
        st.plotly_chart(fig4, use_container_width=True)

    st.markdown("**Recent Commands**")
    show_cols = [c for c in [
        "time_str", "session_id", "behavior_class", "command",
        "category", "action_taken", "reward", "mode", "attacker_profile",
    ] if c in cmd_df.columns]
    table = cmd_df[show_cols].head(200).copy()
    styled = table.style
    if "behavior_class" in table.columns:
        styled = styled.apply(_behavior_style, subset=["behavior_class"])
    if "reward" in table.columns:
        styled = styled.format({"reward": "{:.2f}"})
    st.dataframe(styled, use_container_width=True, height=420)

    csv = cmd_df.to_csv(index=False).encode()
    st.download_button("⬇️ Export Commands CSV", csv, "commands_export.csv", "text/csv")


# ─────────────────────────────────────────────────────────────────────────────
# Tab 2 — Threat Intelligence
# ─────────────────────────────────────────────────────────────────────────────

def render_threat_intelligence(
    cmd_df: pd.DataFrame, sess_df: pd.DataFrame
) -> None:
    st.subheader("🎯 Threat Intelligence")

    if cmd_df.empty:
        st.info("No traffic data yet.")
        return

    col1, col2 = st.columns(2)

    with col1:
        top_cmds = (
            cmd_df["command"].fillna("").str.strip()
            .value_counts().head(15).reset_index()
        )
        top_cmds.columns = ["command", "count"]
        fig = px.bar(
            top_cmds, x="count", y="command", orientation="h",
            title="Top 15 Most Seen Commands",
            color="count", color_continuous_scale="Reds",
        )
        fig.update_layout(
            height=420, showlegend=False, coloraxis_showscale=False,
            yaxis=dict(categoryorder="total ascending"),
            margin=dict(l=8, r=8, t=44, b=8),
            plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
        )
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        if "category" in cmd_df.columns and "behavior_class" in cmd_df.columns:
            pivot = (
                cmd_df.groupby(["category", "behavior_class"])
                .size().unstack(fill_value=0)
            )
            fig2 = px.imshow(
                pivot,
                title="Category × Behaviour Heatmap",
                color_continuous_scale="RdYlGn",
                text_auto=True, aspect="auto",
            )
            fig2.update_layout(height=420, margin=dict(l=8, r=8, t=44, b=8))
            st.plotly_chart(fig2, use_container_width=True)

    if not sess_df.empty and "attacker_profile" in sess_df.columns:
        st.divider()
        st.markdown("**Attacker Profile Analysis**")
        col3, col4 = st.columns(2)

        with col3:
            prof = sess_df["attacker_profile"].value_counts().reset_index()
            prof.columns = ["profile", "count"]
            fig3 = px.pie(
                prof, names="profile", values="count",
                title="Sessions by Attacker Profile",
                color_discrete_sequence=px.colors.qualitative.Set2,
            )
            fig3.update_traces(textposition="inside", textinfo="percent+label")
            fig3.update_layout(height=280, margin=dict(l=8, r=8, t=44, b=8), showlegend=False)
            st.plotly_chart(fig3, use_container_width=True)

        with col4:
            if "engagement_score" in sess_df.columns:
                fig4 = px.box(
                    sess_df, x="attacker_profile", y="engagement_score",
                    color="attacker_profile",
                    title="Engagement Score by Attacker Profile",
                    color_discrete_sequence=px.colors.qualitative.Set2,
                )
                fig4.update_layout(
                    height=280, showlegend=False,
                    margin=dict(l=8, r=8, t=44, b=8),
                    plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                )
                st.plotly_chart(fig4, use_container_width=True)

    if all(c in cmd_df.columns for c in ["action_taken", "behavior_class", "reward"]):
        st.divider()
        st.markdown("**Average Reward: Action × Behaviour Class**")
        reward_pivot = (
            cmd_df.groupby(["action_taken", "behavior_class"])["reward"]
            .mean().reset_index()
        )
        fig5 = px.bar(
            reward_pivot, x="action_taken", y="reward", color="behavior_class",
            barmode="group",
            title="Which actions earn the most reward per behaviour type?",
            color_discrete_map=_BEHAVIOR_COLORS,
        )
        fig5.update_layout(
            height=320, margin=dict(l=8, r=8, t=44, b=8),
            plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
        )
        st.plotly_chart(fig5, use_container_width=True)


# ─────────────────────────────────────────────────────────────────────────────
# Tab 3 — Session Analysis
# ─────────────────────────────────────────────────────────────────────────────

def render_session_analysis(df: pd.DataFrame) -> None:
    st.subheader("📊 Session Analysis")

    if df.empty:
        st.info(
            "No sessions recorded yet.\n\n"
            "1. `python honeypot_static.py`\n"
            "2. `python honeypot_rl.py`\n"
            "3. `python simulate_attacker.py --mode rl --sessions 20`\n"
            "4. Click **Refresh Data**."
        )
        return

    static_df = df[df["mode"] == "static"] if "mode" in df.columns else pd.DataFrame()
    rl_df     = df[df["mode"] == "rl"]     if "mode" in df.columns else pd.DataFrame()

    if not static_df.empty and not rl_df.empty:
        col1, col2 = st.columns([3, 1])
        with col1:
            grouped = (
                df.groupby(["mode", "attacker_profile"])["engagement_score"]
                .mean().reset_index()
                .rename(columns={"engagement_score": "mean_engagement"})
            )
            fig = px.bar(
                grouped, x="attacker_profile", y="mean_engagement",
                color="mode", barmode="group",
                title="Mean Engagement Score: RL vs Static",
                color_discrete_map=_MODE_COLORS,
            )
            fig.update_layout(
                height=300, margin=dict(l=8, r=8, t=44, b=8),
                plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
            )
            st.plotly_chart(fig, use_container_width=True)

        with col2:
            s_mean = static_df["engagement_score"].mean()
            r_mean = rl_df["engagement_score"].mean()
            if s_mean > 0:
                pct = (r_mean - s_mean) / s_mean * 100
                direction = "higher" if pct >= 0 else "lower"
                col2.metric("RL vs Static", f"{r_mean:.2f}",
                            delta=f"{pct:+.1f}% {direction}")
            col2.metric("Static Mean", f"{s_mean:.2f}")
            col2.metric("RL Mean",     f"{r_mean:.2f}")
    else:
        st.info("Run both **static** and **RL** honeypots with the simulator to enable side-by-side comparison.")

    st.divider()
    col3, col4 = st.columns(2)

    with col3:
        if "duration" in df.columns:
            fig2 = px.histogram(
                df, x="duration", color="mode",
                title="Session Duration Distribution (s)",
                nbins=30, barmode="overlay",
                color_discrete_map=_MODE_COLORS, opacity=0.75,
            )
            fig2.update_layout(
                height=280, margin=dict(l=8, r=8, t=44, b=8),
                plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
            )
            st.plotly_chart(fig2, use_container_width=True)

    with col4:
        if "command_count" in df.columns:
            fig3 = px.histogram(
                df, x="command_count", color="mode",
                title="Commands per Session",
                nbins=20, barmode="overlay",
                color_discrete_map=_MODE_COLORS, opacity=0.75,
            )
            fig3.update_layout(
                height=280, margin=dict(l=8, r=8, t=44, b=8),
                plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
            )
            st.plotly_chart(fig3, use_container_width=True)

    if "duration" in df.columns and "engagement_score" in df.columns:
        fig4 = px.scatter(
            df, x="duration", y="engagement_score",
            color="behavior_class", symbol="mode",
            title="Engagement Score vs Duration",
            color_discrete_map=_BEHAVIOR_COLORS,
            hover_data=["attacker_profile", "command_count"],
        )
        fig4.update_layout(
            height=340, margin=dict(l=8, r=8, t=44, b=8),
            plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
        )
        st.plotly_chart(fig4, use_container_width=True)

    st.divider()
    st.markdown("**All Sessions**")
    display_cols = [c for c in [
        "id", "mode", "attacker_profile", "duration",
        "command_count", "behavior_class", "engagement_score", "total_reward",
    ] if c in df.columns]
    show = df[display_cols].copy()
    styled = show.style
    if "behavior_class" in show.columns:
        styled = styled.apply(_behavior_style, subset=["behavior_class"])
    fmt: dict = {}
    if "duration"         in show.columns: fmt["duration"]         = "{:.1f}s"
    if "engagement_score" in show.columns: fmt["engagement_score"] = "{:.2f}"
    if "total_reward"     in show.columns: fmt["total_reward"]     = "{:.2f}"
    if fmt:
        styled = styled.format(fmt)
    st.dataframe(styled, use_container_width=True)
    st.caption("Row colours: green = HUMAN · yellow = UNKNOWN · red = BOT")

    csv = df.to_csv(index=False).encode()
    st.download_button("⬇️ Export Sessions CSV", csv, "sessions_export.csv", "text/csv")


# ─────────────────────────────────────────────────────────────────────────────
# Tab 4 — RL Learning Analytics
# ─────────────────────────────────────────────────────────────────────────────

def render_rl_learning(
    df: pd.DataFrame,
    q_raw: dict,
    training_summary: dict,
) -> None:
    st.subheader("📈 RL Learning Analytics")

    qs    = _q_summary(q_raw)
    rl_df = df[df["mode"] == "rl"].copy() if not df.empty and "mode" in df.columns else pd.DataFrame()

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Unique States",   qs["states"])
    c2.metric("HUMAN States",    qs["human_states"])
    c3.metric("BOT States",      qs["bot_states"])
    c4.metric("UNKNOWN States",  qs["unknown_states"])

    st.divider()

    if not rl_df.empty:
        rl_sorted = rl_df.sort_values("start_time").reset_index(drop=True)
        rl_sorted["session_num"] = range(1, len(rl_sorted) + 1)
        rl_sorted["cumulative"]  = rl_sorted["total_reward"].cumsum()
        rl_sorted["rolling_avg"] = (
            rl_sorted["total_reward"].rolling(window=5, min_periods=1).mean()
        )

        fig = go.Figure()
        fig.add_trace(go.Bar(
            x=rl_sorted["session_num"],
            y=rl_sorted["total_reward"],
            name="Per-Session Reward",
            marker_color="rgba(230,57,70,0.35)",
            marker_line_color="#e63946",
            marker_line_width=0.5,
        ))
        fig.add_trace(go.Scatter(
            x=rl_sorted["session_num"],
            y=rl_sorted["rolling_avg"],
            name="Rolling Avg (w=5)",
            mode="lines",
            line=dict(color="#2dc653", width=2.5),
        ))
        fig.add_trace(go.Scatter(
            x=rl_sorted["session_num"],
            y=rl_sorted["cumulative"],
            name="Cumulative Reward",
            mode="lines",
            line=dict(color="#457b9d", width=2, dash="dot"),
            yaxis="y2",
        ))
        fig.update_layout(
            title="RL Agent Reward Progression (Live Sessions)",
            xaxis_title="Session Number",
            yaxis_title="Reward",
            yaxis2=dict(
                title="Cumulative Reward", overlaying="y",
                side="right", showgrid=False,
            ),
            legend=dict(orientation="h", yanchor="bottom", y=1.04),
            height=360, margin=dict(l=8, r=8, t=52, b=8),
            plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
        )
        st.plotly_chart(fig, use_container_width=True)

        lc1, lc2, lc3 = st.columns(3)
        lc1.metric("Live RL Sessions",   len(rl_sorted))
        lc2.metric("Total Reward",       f"{rl_sorted['total_reward'].sum():.2f}")
        lc3.metric("Avg Reward/Session", f"{rl_sorted['total_reward'].mean():.2f}")
    else:
        st.info("No RL sessions yet. `python honeypot_rl.py` then run the simulator.")

    if training_summary:
        st.divider()
        st.markdown("**Offline Training Summary**")
        ts = training_summary

        tc1, tc2, tc3, tc4 = st.columns(4)
        tc1.metric("Training Sessions",  f"{ts.get('sessions', 0):,}")
        tc2.metric("Commands Processed", f"{ts.get('total_commands', 0):,}")
        tc3.metric("Avg Reward/Session", f"{ts.get('avg_reward_per_session', 0):.2f}")
        tc4.metric("States Learned",     ts.get("states", "—"))

        fp   = ts.get("forced_profile", "") or "mixed (default)"
        bot  = ts.get("include_bot", True)
        seed = ts.get("seed", "—")
        st.info(f"Profile: **{fp}** | Bot included: **{bot}** | Seed: `{seed}`")

        pc1, pc2 = st.columns(2)
        profiles = ts.get("profiles", {})
        if profiles:
            p_df = pd.DataFrame(list(profiles.items()), columns=["Profile", "Sessions"])
            fig2 = px.pie(
                p_df, names="Profile", values="Sessions",
                title="Training Profile Mix",
                color_discrete_sequence=px.colors.qualitative.Set2,
            )
            fig2.update_traces(textposition="inside", textinfo="percent+label")
            fig2.update_layout(height=260, margin=dict(l=8, r=8, t=44, b=8), showlegend=False)
            pc1.plotly_chart(fig2, use_container_width=True)

        actions = ts.get("actions", {})
        if actions:
            a_df = pd.DataFrame(list(actions.items()), columns=["Action", "Count"])
            fig3 = px.bar(
                a_df, x="Action", y="Count",
                title="Actions Used During Training",
                color="Action", color_discrete_map=_ACTION_COLORS,
            )
            fig3.update_layout(
                height=260, showlegend=False,
                margin=dict(l=8, r=8, t=44, b=8),
                plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
            )
            pc2.plotly_chart(fig3, use_container_width=True)

    if q_raw:
        st.divider()
        st.markdown("**Q-Table State Coverage Breakdown**")
        states = [k for k in q_raw if not k.startswith("_")]
        beh_count   = {"BOT": 0, "HUMAN": 0, "UNKNOWN": 0}
        tempo_count = {"FAST": 0, "NORMAL": 0, "SLOW": 0}
        for s in states:
            parts = s.split("|")
            b = parts[2] if len(parts) > 2 else ""
            t = parts[1] if len(parts) > 1 else ""
            if b in beh_count:   beh_count[b]   += 1
            if t in tempo_count: tempo_count[t]  += 1

        sc1, sc2 = st.columns(2)
        bdf = pd.DataFrame(list(beh_count.items()), columns=["Class", "States"])
        f_b = px.bar(bdf, x="Class", y="States", title="States by Behaviour Class",
                     color="Class", color_discrete_map=_BEHAVIOR_COLORS)
        f_b.update_layout(height=240, showlegend=False,
                           margin=dict(l=8, r=8, t=44, b=8),
                           plot_bgcolor="rgba(0,0,0,0)")
        sc1.plotly_chart(f_b, use_container_width=True)

        tdf = pd.DataFrame(list(tempo_count.items()), columns=["Tempo", "States"])
        f_t = px.bar(tdf, x="Tempo", y="States", title="States by Attacker Tempo",
                     color="Tempo",
                     color_discrete_sequence=px.colors.qualitative.Pastel)
        f_t.update_layout(height=240, showlegend=False,
                           margin=dict(l=8, r=8, t=44, b=8),
                           plot_bgcolor="rgba(0,0,0,0)")
        sc2.plotly_chart(f_t, use_container_width=True)

    # ── Fix 3: Baseline karşılaştırması ───────────────────────────────────────
    if training_summary and "baseline_comparison" in training_summary:
        st.divider()
        st.markdown("**📊 Baseline Policy Comparison (Fix 3)**")

        bl = training_summary["baseline_comparison"]
        baselines = bl.get("baselines", {})

        # RL'i de karşılaştırma tablosuna ekle
        all_policies = {"rl_agent": {"avg_reward": bl["rl_avg_reward"], "avg_commands": 0}}
        all_policies.update(baselines)

        cmp_df = pd.DataFrame([
            {"Policy": k, "Avg Reward": v["avg_reward"],
             "Avg Commands": v.get("avg_commands", 0)}
            for k, v in all_policies.items()
        ]).sort_values("Avg Reward", ascending=False)

        bc1, bc2 = st.columns(2)
        with bc1:
            _POLICY_COLORS = {
                "rl_agent":            "#e63946",
                "always_decoy_lure":   "#fca311",
                "always_honeytrap":    "#457b9d",
                "always_fake_success": "#2dc653",
                "random":              "#888888",
                "always_silent_error": "#4a4a4a",
            }
            fig_bl = px.bar(
                cmp_df, x="Avg Reward", y="Policy", orientation="h",
                title="RL vs Sabit Politikalar — Ortalama Reward",
                color="Policy", color_discrete_map=_POLICY_COLORS,
            )
            fig_bl.update_layout(
                height=300, showlegend=False,
                yaxis=dict(categoryorder="total ascending"),
                margin=dict(l=8, r=8, t=44, b=8),
                plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
            )
            st.plotly_chart(fig_bl, use_container_width=True)

        with bc2:
            vs_random = bl.get("rl_vs_random_pct", 0)
            vs_best   = bl.get("rl_vs_best_fixed_pct", 0)
            best_name = bl.get("best_fixed_policy", "?")
            st.metric("RL vs Random",            f"{bl['random_avg_reward']:.1f}",
                      delta=f"{vs_random:+.1f}%", delta_color="normal")
            st.metric(f"RL vs {best_name}",      f"{bl['best_fixed_avg_reward']:.1f}",
                      delta=f"{vs_best:+.1f}%",  delta_color="normal")
            st.metric("RL avg reward",            f"{bl['rl_avg_reward']:.1f}")

            if vs_best < 0:
                st.info(
                    f"**{best_name}** RL ajanı {abs(vs_best):.0f}% geride bırakıyor. "
                    "Bu beklenen bir durum: state uzayı büyüdüğü için daha fazla "
                    "eğitim (~100k oturum) gerekiyor. "
                    "`python train_model.py --sessions 100000 --reset`"
                )
            else:
                st.success(f"RL ajanı tüm sabit politikaları geride bırakıyor! ✅")


# ─────────────────────────────────────────────────────────────────────────────
# Tab 5 — Q-Table Inspector
# ─────────────────────────────────────────────────────────────────────────────

def render_q_table_view(q_raw: dict) -> None:
    st.subheader("🔬 Q-Table Inspector")

    if not q_raw:
        st.info(
            f"Q-table not found at `{config.Q_TABLE_PATH}`.\n\n"
            "Train offline: `python train_model.py --sessions 5000`"
        )
        return

    qs  = _q_summary(q_raw)
    eps = qs["epsilon"]

    qc1, qc2, qc3, qc4 = st.columns(4)
    qc1.metric("ε (Epsilon)",   f"{eps:.4f}" if isinstance(eps, float) else "—")
    qc2.metric("Unique States", qs["states"])
    qc3.metric("BOT States",    qs["bot_states"])
    qc4.metric("HUMAN States",  qs["human_states"])

    states = [k for k in q_raw if not k.startswith("_")]
    if not states:
        st.info("Q-table is empty — no states visited yet.")
        return

    action_cols = [config.ACTION_NAMES[i] for i in range(len(config.ACTION_NAMES))]
    records = []
    for sk in states:
        q_vals = q_raw[sk]
        row = {"state": sk}
        for i, name in enumerate(action_cols):
            row[name] = float(q_vals.get(str(i), 0.0))
        records.append(row)

    q_df = pd.DataFrame(records)
    q_df["max_q"]       = q_df[action_cols].max(axis=1)
    q_df["best_action"] = q_df[action_cols].idxmax(axis=1)

    hm_col, pie_col = st.columns([3, 1])

    with hm_col:
        top_n  = min(30, len(q_df))
        top_df = q_df.nlargest(top_n, "max_q").set_index("state")[action_cols]
        fig = px.imshow(
            top_df,
            title=f"Top {top_n} States — Q-Value Heatmap",
            labels=dict(x="Action", y="State", color="Q-Value"),
            color_continuous_scale="RdYlGn",
            aspect="auto", text_auto=".1f",
        )
        fig.update_layout(
            height=max(420, top_n * 18 + 80),
            margin=dict(l=8, r=8, t=52, b=8),
        )
        fig.update_yaxes(tickfont_size=8)
        st.plotly_chart(fig, use_container_width=True)

    with pie_col:
        st.markdown("**Best Action Distribution**")
        best_dist = q_df["best_action"].value_counts().reset_index()
        best_dist.columns = ["action", "states"]
        fig2 = px.pie(
            best_dist, names="action", values="states",
            color="action", color_discrete_map=_ACTION_COLORS,
        )
        fig2.update_layout(height=260, margin=dict(l=4, r=4, t=8, b=8))
        fig2.update_traces(textposition="inside", textinfo="percent+label")
        st.plotly_chart(fig2, use_container_width=True)

        st.markdown("**Top 5 States (by max Q)**")
        top5 = q_df.nlargest(5, "max_q")[["state", "max_q", "best_action"]]
        st.dataframe(
            top5.style.format({"max_q": "{:.2f}"}),
            use_container_width=True, hide_index=True,
        )

    st.caption(
        "State key: `cmd₁,cmd₂,cmd₃|TEMPO|BEHAVIOR`  ·  "
        "Greener = higher Q-value (more rewarding strategy for that state)."
    )
    csv = q_df.to_csv(index=False).encode()
    st.download_button("⬇️ Export Q-Table CSV", csv, "q_table_export.csv", "text/csv")


# ─────────────────────────────────────────────────────────────────────────────
# Tab 6 — System Status
# ─────────────────────────────────────────────────────────────────────────────

def render_system_status(
    sess_df: pd.DataFrame,
    cmd_df: pd.DataFrame,
    training_summary: dict,
) -> None:
    st.subheader("⚙️ System Status")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("**Honeypot Configuration**")
        cfg_data = {
            "Parameter": [
                "Static Port", "RL Port", "Host",
                "Learning Rate (α)", "Discount Factor (γ)",
                "ε Start", "ε Min", "ε Decay",
                "Bot Score Threshold", "Human Score Threshold",
                "Fast Tempo (CPM)", "Slow Tempo (CPM)",
                "Slow Response Delay (s)", "Idle Status Interval (s)",
            ],
            "Value": [
                config.STATIC_PORT, config.RL_PORT, config.HOST,
                config.ALPHA, config.GAMMA,
                config.EPSILON_START, config.EPSILON_MIN, config.EPSILON_DECAY,
                config.BOT_SCORE_THRESHOLD, config.HUMAN_SCORE_THRESHOLD,
                config.FAST_TEMPO_CPM, config.SLOW_TEMPO_CPM,
                config.SLOW_RESPONSE_DELAY, config.IDLE_STATUS_INTERVAL,
            ],
        }
        st.dataframe(pd.DataFrame(cfg_data), use_container_width=True, hide_index=True)

    with col2:
        st.markdown("**Reward Weights**")
        rw_data = {
            "Weight": [
                "W_ENGAGE  (engagement continuation)",
                "W_DIVERSITY  (new command category)",
                "W_BOT  (bot behaviour penalty)",
                "W_LURE  (lure interaction bonus)",
            ],
            "Value": [config.W_ENGAGE, config.W_DIVERSITY, config.W_BOT, config.W_LURE],
        }
        st.dataframe(pd.DataFrame(rw_data), use_container_width=True, hide_index=True)

        st.markdown("**Database Health**")
        n_sess  = len(sess_df) if not sess_df.empty else 0
        n_cmds  = len(cmd_df)  if not cmd_df.empty  else 0
        db_size = os.path.getsize(config.DB_PATH) if os.path.exists(config.DB_PATH) else 0
        dbc1, dbc2, dbc3 = st.columns(3)
        dbc1.metric("Sessions", n_sess)
        dbc2.metric("Commands", n_cmds)
        dbc3.metric("DB Size",  f"{db_size / 1024:.1f} KB")

    if training_summary:
        st.divider()
        st.markdown("**Last Offline Training Run**")
        ts = training_summary

        tc1, tc2, tc3, tc4 = st.columns(4)
        tc1.metric("Sessions Trained",   f"{ts.get('sessions', 0):,}")
        tc2.metric("Commands Processed", f"{ts.get('total_commands', 0):,}")
        tc3.metric("Avg Cmd/Session",    f"{ts.get('avg_commands_per_session', 0):.1f}")
        tc4.metric("Final Epsilon",      f"{ts.get('epsilon', 0):.4f}")

        fp   = ts.get("forced_profile", "") or "mixed (default)"
        bot  = ts.get("include_bot", True)
        seed = ts.get("seed", "—")
        st.info(
            f"Profile: **{fp}** | Bot included: **{bot}** | "
            f"Seed: `{seed}` | States learned: **{ts.get('states', '—')}**"
        )

        profiles  = ts.get("profiles", {})
        behaviors = ts.get("behaviors", {})
        if profiles or behaviors:
            tc5, tc6 = st.columns(2)
            if profiles:
                p_df = pd.DataFrame(list(profiles.items()), columns=["Profile", "Sessions"])
                tc5.markdown("**Profile breakdown**")
                tc5.dataframe(p_df, use_container_width=True, hide_index=True)
            if behaviors:
                b_df = pd.DataFrame(
                    list(behaviors.items()), columns=["Classified As", "Sessions"]
                )
                tc6.markdown("**Behaviour classification results**")
                tc6.dataframe(b_df, use_container_width=True, hide_index=True)

    st.divider()
    st.markdown("**Action Space**")
    action_df = pd.DataFrame(
        [(k, v) for k, v in config.ACTION_NAMES.items()],
        columns=["ID", "Strategy"],
    )
    strategy_desc = {
        "SILENT_ERROR":    "Generic error; reveals no system information",
        "FAKE_SUCCESS":    "Context-aware fake success output",
        "DECOY_LURE":      "Fake success + hint toward seemingly valuable files",
        "SLOW_RESPONSE":   f"Adds {config.SLOW_RESPONSE_DELAY}s artificial delay before responding",
        "HONEYTRAP_OFFER": "Fake success + high-value honeytrap hint",
    }
    action_df["Description"] = action_df["Strategy"].map(strategy_desc)
    st.dataframe(action_df, use_container_width=True, hide_index=True)


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    database.init_db()

    auto_refresh, refresh_secs = render_sidebar()

    q_raw   = _load_q_table()
    qs      = _q_summary(q_raw)
    sess_df = _load_sessions()
    cmd_df  = _load_recent_commands(limit=500)
    ts      = _load_training_summary()

    render_header(qs)
    render_kpi_strip(sess_df, cmd_df, qs)
    st.divider()

    # Policy status banner
    if qs["bot_states"]:
        st.warning(
            f"⚠️ Q-table contains **{qs['bot_states']}** BOT state(s). "
            "Mixed-profile policy active."
        )
    elif qs["states"] > 0:
        eps_str = f", ε = {qs['epsilon']:.4f}" if isinstance(qs["epsilon"], float) else ""
        st.success(f"✅ Policy loaded — **{qs['states']}** unique states{eps_str}.")
    else:
        st.info("No Q-table found. Train with: `python train_model.py --sessions 5000`")

    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        "⚡ Live Traffic",
        "🎯 Threat Intelligence",
        "📊 Session Analysis",
        "📈 RL Learning",
        "🔬 Q-Table Inspector",
        "⚙️ System Status",
    ])

    with tab1: render_live_traffic(cmd_df, sess_df)
    with tab2: render_threat_intelligence(cmd_df, sess_df)
    with tab3: render_session_analysis(sess_df)
    with tab4: render_rl_learning(sess_df, q_raw, ts)
    with tab5: render_q_table_view(q_raw)
    with tab6: render_system_status(sess_df, cmd_df, ts)

    # Native auto-refresh — no JS injection needed
    if auto_refresh:
        time.sleep(refresh_secs)
        st.rerun()


main()
