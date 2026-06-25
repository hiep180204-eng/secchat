#!/bin/bash
# Client container

rm -f /tmp/.X1-lock /tmp/.X11-unix/X1 2>/dev/null || true

# ── Wait for server to publish its TLS cert before starting the app ──
echo "[startup] Waiting for server cert at /certs/chat.crt ..."
timeout=30
while [ ! -f /certs/chat.crt ] && [ $timeout -gt 0 ]; do
    sleep 1; timeout=$((timeout - 1))
done
if [ ! -f /certs/chat.crt ]; then
    echo "[startup] WARNING: /certs/chat.crt not found after 30s — TLS pinning will fail"
else
    echo "[startup] Server cert found, proceeding."
fi

# VNC password is intentionally fixed for the local demo container.
mkdir -p /root/.vnc
printf "docker\ndocker\nn\n" | vncpasswd
echo "[startup] VNC password: docker"

# ── Locale & encoding ─────────────────────────────────────
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8
export PYTHONIOENCODING=utf-8

# ── Qt settings ───────────────────────────────────────────
export QT_QPA_PLATFORM=xcb
export QT_LOGGING_RULES="*.debug=false;qt.qpa.*=false"
export QT_DEBUG_PLUGINS=0

# ── Vietnamese input via IBus + Unikey ────────────────────
export QT_IM_MODULE=ibus
export GTK_IM_MODULE=ibus
export XMODIFIERS=@im=ibus

Xvnc :1 -geometry 1280x800 -depth 24 \
    -rfbport 5900 \
    -SecurityTypes VncAuth \
    -PasswordFile /root/.vnc/passwd \
    -AlwaysShared \
    -localhost no \
    -log '*:stderr:0' \
    >/dev/null 2>&1 &

timeout=15
while [ ! -S /tmp/.X11-unix/X1 ] && [ $timeout -gt 0 ]; do
    sleep 1; timeout=$((timeout-1))
done

export DISPLAY=:1
fluxbox >/dev/null 2>&1 &
sleep 1

# Refresh font cache with newly installed CJK fonts
fc-cache -f 2>/dev/null || true

# ── Start DBus + IBus for Vietnamese Telex input ──────────
mkdir -p /run/dbus 2>/dev/null || true
dbus-daemon --system --fork 2>/dev/null || true
eval "$(dbus-launch --sh-syntax)" 2>/dev/null || true
export DBUS_SESSION_BUS_ADDRESS

# Start ibus daemon and configure Vietnamese Telex
ibus-daemon -drx 2>/dev/null &
sleep 1

# Set Unikey (Vietnamese Telex) as default and active input method
gsettings set org.freedesktop.ibus.general preload-engines "['Unikey']" 2>/dev/null || true
gsettings set org.freedesktop.ibus.general.hotkey trigger "['Control+space']" 2>/dev/null || true

# Pre-activate Unikey so Vietnamese typing works immediately
# (user can toggle with Ctrl+Space if they want English input)
dbus-send --session --dest=org.freedesktop.IBus \
    /org/freedesktop/IBus \
    org.freedesktop.IBus.SetGlobalEngine \
    string:"Unikey" 2>/dev/null || true

exec python3 /app/main.py
