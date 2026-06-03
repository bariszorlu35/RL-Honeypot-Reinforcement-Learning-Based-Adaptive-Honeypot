"""Streamlit dashboard for RL-Honeypot.

Provides five analysis tabs: session overview, engagement comparison,
reward curve, behaviour classification, and Q-table inspection.

Run with: streamlit run dashboard.py
"""

import json
import os
from typing import Optional

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

import config
import database

st.set_page_config(
    page_title="RL-Honeypot Dashboard",
    layout="wide",
    page_icon="🍯",
)


# ---------------------------------------------------------------------------
# Data helpers
# ---------------------------------------------------------------------------

def _load_sessions() -> pd.DataFrame:
    """Load all sessions from the database and return as a DataFrame."""
    rows = database.get_all_sessions()
    if not rows:
        return pd.DataFrame()
    return pd.DataFrame(rows)


def _behavior_bg(val: str) -> str:
    """Return a CSS background-color string for a behaviour class value."""
    return {
        "HUMAN": "background-color: #d4edda",
        "BOT": "background-color: #f8d7da",
        "UNKNOWN": "background-color: #fff3cd",
    }.get(val, "")


def _style_behavior_col(series: pd.Series) -> list:
    """Styler function: colour every cell in the behavior_class column."""
    return [_behavior_bg(v) for v in series]


# ---------------------------------------------------------------------------
# Tab renderers
# ---------------------------------------------------------------------------

def render_session_overview(df: pd.DataFrame) -> None:
    """Tab 1 — Session table with colour-coded behaviour and summary metrics."""
    st.subheader("All Sessions")

    if df.empty:
        st.info(
            "No sessions recorded yet.\n\n"
            "1. Start a honeypot: `python honeypot_static.py` or `python honeypot_rl.py`\n"
            "2. Run the simulator: `python simulate_attacker.py --mode static --sessions 10`\n"
            "3. Click **Refresh Data**."
        )
        return

    static_df = df[df["mode"] == "static"]
    rl_df = df[df["mode"] == "rl"]

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Static Sessions", len(static_df))
    c2.metric("RL Sessions", len(rl_df))
    c3.metric(
        "Mean Engagement (Static)",
        f"{static_df['engagement_score'].mean():.2f}" if not static_df.empty else "—",
    )
    c4.metric(
        "Mean Engagement (RL)",
        f"{rl_df['engagement_score'].mean():.2f}" if not rl_df.empty else "—",
    )

    st.divider()

    display_cols = [
        "id", "mode", "attacker_profile", "duration",
        "command_count", "behavior_class", "engagement_score", "total_reward",
    ]
    available = [c for c in display_cols if c in df.columns]
    show_df = df[available].copy()

    styled = show_df.style
    if "behavior_class" in show_df.columns:
        styled = styled.apply(_style_behavior_col, subset=["behavior_class"])

    format_map = {}
    if "duration" in show_df.columns:
        format_map["duration"] = "{:.1f}s"
    if "engagement_score" in show_df.columns:
        format_map["engagement_score"] = "{:.2f}"
    if "total_reward" in show_df.columns:
        format_map["total_reward"] = "{:.2f}"
    if format_map:
        styled = styled.format(format_map)

    st.dataframe(styled, use_container_width=True)

    st.caption("Row colours: green = HUMAN, yellow = UNKNOWN, red = BOT")


def render_engagement_comparison(df: pd.DataFrame) -> None:
    """Tab 2 — Grouped bar chart comparing Static vs. RL engagement by profile."""
    st.subheader("Static vs. RL Engagement by Attacker Profile")

    if df.empty:
        st.info("No data available. Run sessions first.")
        return

    needed = {"attacker_profile", "mode", "engagement_score"}
    if not needed.issubset(df.columns):
        st.warning("Missing required columns for this chart.")
        return

    grouped = (
        df.groupby(["mode", "attacker_profile"])["engagement_score"]
        .mean()
        .reset_index()
        .rename(columns={"engagement_score": "mean_engagement"})
    )

    if grouped.empty:
        st.info("Not enough data — run more sessions across both modes.")
        return

    fig = px.bar(
        grouped,
        x="attacker_profile",
        y="mean_engagement",
        color="mode",
        barmode="group",
        title="Mean Engagement Score by Attacker Profile and Honeypot Mode",
        labels={
            "mean_engagement": "Mean Engagement Score",
            "attacker_profile": "Attacker Profile",
            "mode": "Mode",
        },
        color_discrete_map={"static": "#636EFA", "rl": "#EF553B"},
    )
    st.plotly_chart(fig, use_container_width=True)

    # Measured percentage difference — calculated from live data, never hardcoded
    st.subheader("Measured Improvement")
    static_mean = df[df["mode"] == "static"]["engagement_score"].mean()
    rl_mean = df[df["mode"] == "rl"]["engagement_score"].mean()

    if (
        not pd.isna(static_mean)
        and not pd.isna(rl_mean)
        and static_mean > 0
    ):
        pct = (rl_mean - static_mean) / static_mean * 100
        direction = "higher" if pct >= 0 else "lower"
        st.markdown(
            f"RL mean engagement is **{abs(pct):.1f}%** {direction} than the static "
            f"baseline ({rl_mean:.2f} vs {static_mean:.2f})."
        )
    else:
        st.info(
            "Need sessions in both static and RL modes to compute a comparison.\n"
            "Run the simulator for both modes and refresh."
        )


def render_reward_curve(df: pd.DataFrame) -> None:
    """Tab 3 — Cumulative RL reward over sessions with rolling average."""
    st.subheader("RL Agent Reward Over Sessions")

    rl_df = df[df["mode"] == "rl"] if not df.empty else pd.DataFrame()

    if rl_df.empty:
        st.info("No RL sessions recorded yet. Run: `python honeypot_rl.py` then `simulate_attacker.py --mode rl`")
        return

    rl_sorted = rl_df.sort_values("start_time").reset_index(drop=True)
    rl_sorted["session_num"] = range(1, len(rl_sorted) + 1)
    rl_sorted["cumulative_reward"] = rl_sorted["total_reward"].cumsum()
    # Rolling average with min_periods=1 so the line starts from session 1
    rl_sorted["rolling_avg"] = (
        rl_sorted["total_reward"].rolling(window=5, min_periods=1).mean()
    )

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=rl_sorted["session_num"],
        y=rl_sorted["cumulative_reward"],
        name="Cumulative Reward",
        mode="lines+markers",
        line=dict(color="#EF553B"),
        marker=dict(size=5),
    ))
    fig.add_trace(go.Scatter(
        x=rl_sorted["session_num"],
        y=rl_sorted["rolling_avg"],
        name="Per-Session Rolling Avg (w=5)",
        mode="lines",
        line=dict(color="#00CC96", dash="dash", width=2),
    ))
    fig.update_layout(
        title="RL Agent Cumulative Reward and Rolling Average",
        xaxis_title="Session Number",
        yaxis_title="Reward",
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
    )
    st.plotly_chart(fig, use_container_width=True)

    col1, col2, col3 = st.columns(3)
    col1.metric("Total RL Sessions", len(rl_sorted))
    col2.metric("Total Reward", f"{rl_sorted['total_reward'].sum():.2f}")
    col3.metric("Avg Reward / Session", f"{rl_sorted['total_reward'].mean():.2f}")


def render_behavior_classification(df: pd.DataFrame) -> None:
    """Tab 4 — Pie charts and duration bar chart by behaviour class."""
    st.subheader("Behaviour Classification")

    if df.empty:
        st.info("No data available.")
        return

    col1, col2 = st.columns(2)
    for col, mode_name in zip([col1, col2], ["static", "rl"]):
        mode_df = df[df["mode"] == mode_name]
        with col:
            st.markdown(f"**{mode_name.upper()} mode**")
            if mode_df.empty:
                st.info(f"No {mode_name} sessions yet.")
            else:
                counts = mode_df["behavior_class"].value_counts().reset_index()
                counts.columns = ["behavior_class", "count"]
                fig = px.pie(
                    counts,
                    names="behavior_class",
                    values="count",
                    title=f"{mode_name.upper()} Behaviour Distribution",
                    color="behavior_class",
                    color_discrete_map={
                        "HUMAN": "#28a745",
                        "BOT": "#dc3545",
                        "UNKNOWN": "#ffc107",
                    },
                )
                st.plotly_chart(fig, use_container_width=True)

    st.divider()
    st.subheader("Average Session Duration by Behaviour Class")

    if "behavior_class" in df.columns and "duration" in df.columns:
        dur_grp = (
            df.groupby(["mode", "behavior_class"])["duration"]
            .mean()
            .reset_index()
            .rename(columns={"duration": "avg_duration"})
        )
        if not dur_grp.empty:
            fig2 = px.bar(
                dur_grp,
                x="behavior_class",
                y="avg_duration",
                color="mode",
                barmode="group",
                title="Avg Session Duration by Behaviour Class and Mode",
                labels={
                    "avg_duration": "Avg Duration (s)",
                    "behavior_class": "Behaviour Class",
                    "mode": "Mode",
                },
                color_discrete_map={"static": "#636EFA", "rl": "#EF553B"},
            )
            st.plotly_chart(fig2, use_container_width=True)


def render_q_table_view() -> None:
    """Tab 5 — Q-table heatmap for the top 20 highest-value states."""
    st.subheader("Q-Table Inspector")

    if not os.path.exists(config.Q_TABLE_PATH):
        st.info(
            f"Q-table not found at `{config.Q_TABLE_PATH}`.\n\n"
            "Start the RL honeypot and run at least one attacker session."
        )
        return

    try:
        with open(config.Q_TABLE_PATH, "r") as fh:
            raw = json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        st.error(f"Could not load Q-table: {exc}")
        return

    epsilon = raw.pop("_epsilon", None)

    col1, col2 = st.columns(2)
    if epsilon is not None:
        col1.metric("Current ε (Epsilon)", f"{epsilon:.4f}")
    col2.metric("Unique States Visited", len(raw))

    if not raw:
        st.info("Q-table exists but is empty — no states have been visited yet.")
        return

    # Build DataFrame: rows = state keys, columns = action names
    action_cols = [config.ACTION_NAMES[i] for i in range(len(config.ACTION_NAMES))]
    records = []
    for state_key, q_vals in raw.items():
        row = {"state": state_key}
        for i, name in enumerate(action_cols):
            row[name] = float(q_vals.get(str(i), 0.0))
        records.append(row)

    q_df = pd.DataFrame(records)
    q_df["max_q"] = q_df[action_cols].max(axis=1)
    # Show only the top 20 states by maximum Q-value
    top20 = q_df.nlargest(20, "max_q").set_index("state")[action_cols]

    fig = px.imshow(
        top20,
        labels=dict(x="Response Strategy (Action)", y="State", color="Q-Value"),
        title="Top 20 States — Q-Value Heatmap",
        color_continuous_scale="RdYlGn",
        aspect="auto",
        text_auto=".2f",
    )
    fig.update_layout(height=600)
    st.plotly_chart(fig, use_container_width=True)

    st.caption(
        "State key format: `last_cmd_1,last_cmd_2,last_cmd_3|TEMPO|BEHAVIOR`. "
        "Greener = agent has learned this strategy is more rewarding for that state."
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    """Render the full dashboard."""
    st.title("RL-Honeypot Dashboard")
    st.caption(
        "Local-only academic honeypot — adaptive Q-learning vs. static baseline. "
        "All data from `honeypot.db` on localhost."
    )

    # Sidebar controls
    with st.sidebar:
        st.header("Controls")
        if st.button("🔄 Refresh Data", use_container_width=True):
            st.rerun()
        st.divider()
        st.markdown("**Danger Zone**")
        confirm_clear = st.checkbox("Confirm: delete all session data")
        clear_clicked = st.button(
            "🗑 Clear Database",
            disabled=not confirm_clear,
            use_container_width=True,
        )
        if clear_clicked and confirm_clear:
            database.clear_db()
            st.success("Database cleared.")
            st.rerun()
        st.divider()
        st.markdown("**Ports**")
        st.markdown(f"- Static honeypot: `{config.HOST}:{config.STATIC_PORT}`")
        st.markdown(f"- RL honeypot: `{config.HOST}:{config.RL_PORT}`")

    database.init_db()
    df = _load_sessions()

    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "📋 Session Overview",
        "📊 Engagement Comparison",
        "📈 Reward Curve",
        "🧠 Behaviour Classification",
        "🔬 Q-Table View",
    ])

    with tab1:
        render_session_overview(df)
    with tab2:
        render_engagement_comparison(df)
    with tab3:
        render_reward_curve(df)
    with tab4:
        render_behavior_classification(df)
    with tab5:
        render_q_table_view()


main()
