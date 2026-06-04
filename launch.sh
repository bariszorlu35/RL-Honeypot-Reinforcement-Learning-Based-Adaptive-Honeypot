#!/usr/bin/env bash
# launch.sh — Her bileşeni ayrı Terminal penceresinde açar
#
# Kullanım:
#   ./launch.sh                  # Honeypotlar + simülatör + dashboard
#   ./launch.sh --sessions 50    # Simülatör oturum sayısını belirt
#   ./launch.sh --no-sim         # Simülatör açılmasın
#   ./launch.sh --no-static      # Static honeypot açılmasın

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ─── Argümanlar ───────────────────────────────────────────────────────────────
SESSIONS=20
RUN_SIM=true
RUN_STATIC=true

while [[ $# -gt 0 ]]; do
    case "$1" in
        --sessions)  SESSIONS="${2:?'--sessions için sayı gerekli'}"; shift ;;
        --no-sim)    RUN_SIM=false ;;
        --no-static) RUN_STATIC=false ;;
        -h|--help)
            echo "Kullanım: ./launch.sh [--sessions N] [--no-sim] [--no-static]"
            exit 0 ;;
        *) echo "Bilinmeyen argüman: $1"; exit 1 ;;
    esac
    shift
done

# ─── Python komutları (relative — cd ile dizine geçiyoruz, tam yol gereksiz) ──
if [[ -x "$SCRIPT_DIR/.venv/bin/python3" ]]; then
    PY=".venv/bin/python3"
    ST=".venv/bin/streamlit"
elif command -v python3 &>/dev/null; then
    PY="python3"
    ST="streamlit"
else
    echo "❌ Python bulunamadı."
    exit 1
fi

# ─── Yeni Terminal penceresi açıcı ────────────────────────────────────────────
# SCRIPT_DIR'deki boşluklar: cd komutuna tek tırnak ile güvenle aktarılıyor.
# Pencere içindeki komutlar relative path kullanıyor — boşluk sorunu yok.
open_window() {
    local title="$1"
    local cmd="$2"
    # Tek tırnaklar AppleScript string sınırlarına çarpmamak için \ ile escape
    local safe_dir
    safe_dir="${SCRIPT_DIR//\'/\'\\\'\'}"   # içindeki ' → '\''
    osascript \
        -e 'tell application "Terminal"' \
        -e '  activate' \
        -e "  do script \"cd '${safe_dir}' && ${cmd}\"" \
        -e "end tell" \
        >/dev/null
}

# ─── Port kontrolü ────────────────────────────────────────────────────────────
port_in_use() { lsof -i :"$1" &>/dev/null; }

echo "🍯 RL-Honeypot başlatılıyor..."
echo ""

# ─── Static honeypot ──────────────────────────────────────────────────────────
if $RUN_STATIC; then
    if port_in_use 2323; then
        echo "⚠️  Port 2323 meşgul — static honeypot atlandı."
    else
        echo "🟢 Static Honeypot açılıyor  →  port 2323"
        open_window "Static Honeypot 2323" "$PY honeypot_static.py"
        sleep 0.5
    fi
fi

# ─── RL honeypot ──────────────────────────────────────────────────────────────
if port_in_use 2324; then
    echo "⚠️  Port 2324 meşgul — RL honeypot atlandı."
else
    echo "🔴 RL Honeypot açılıyor       →  port 2324"
    open_window "RL Honeypot 2324" "$PY honeypot_rl.py"
    sleep 0.5
fi

# ─── Honeypotların ayağa kalkmasını bekle ─────────────────────────────────────
echo "⏳ Honeypotlar hazırlanıyor (2s)..."
sleep 2

# ─── Simülatör ────────────────────────────────────────────────────────────────
if $RUN_SIM; then
    echo "🤖 Simülatör açılıyor         →  $SESSIONS oturum"
    open_window "Attacker Simulator" \
        "$PY simulate_attacker.py --mode rl --sessions $SESSIONS --delay-scale 0.2"
    sleep 0.3
fi

# ─── Dashboard ────────────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Tüm bileşenler başlatıldı"
echo "  Dashboard: http://localhost:8501"
echo "  Durdurmak için Ctrl+C"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

cd "$SCRIPT_DIR"
"$SCRIPT_DIR/$ST" run "$SCRIPT_DIR/dashboard.py"
