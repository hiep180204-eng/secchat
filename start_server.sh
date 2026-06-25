#!/bin/bash
# Server container

rm -f /tmp/.X1-lock /tmp/.X11-unix/X1 2>/dev/null || true

# Generate a fresh TLS cert on every container start.
# Generating at runtime means each deployment gets a unique cert — the private key
# never leaves the container and is not baked into the image layer.
mkdir -p /etc/ssl /certs
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout /etc/ssl/chat.key \
    -out    /etc/ssl/chat.crt \
    -days   365 \
    -subj   "/CN=chat-server" \
    -addext "subjectAltName=DNS:chat-server,DNS:localhost,IP:127.0.0.1" \
    2>/dev/null
chmod 600 /etc/ssl/chat.key
chmod 644 /etc/ssl/chat.crt

# Publish only the PUBLIC cert to the /certs mount so clients can pin it.
# The private key stays inside this container.
cp /etc/ssl/chat.crt /certs/chat.crt
echo "[startup] Fresh TLS cert generated and published to /certs/chat.crt"

# VNC password is intentionally fixed for the local demo container.
mkdir -p /root/.vnc
printf "docker\ndocker\nn\n" | vncpasswd
echo "[startup] VNC password: docker"

export QT_QPA_PLATFORM=xcb
export QT_LOGGING_RULES="*.debug=false;qt.qpa.*=false"
export QT_DEBUG_PLUGINS=0

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

exec python3 /app/server_gui.py
