#!/bin/bash
# Маяк VPN: установка входного сервера (каскада).
SUDO="{{SUDO}}"
TARGET_HOST="{{TARGET_HOST}}"
FORWARDS="{{FORWARDS}}"
OWN_SSH_PORT="{{OWN_SSH_PORT}}"
CHECK_TCP="{{CHECK_TCP}}"

echo "$LANG" | grep -qE '^(en_US.UTF-8|C.UTF-8|C)$' || export LC_ALL=C

if ! command -v iptables >/dev/null 2>&1; then
  echo "Устанавливаю iptables…"
  if command -v apt-get >/dev/null 2>&1; then
    $SUDO env DEBIAN_FRONTEND=noninteractive apt-get -yq update >/dev/null
    $SUDO env DEBIAN_FRONTEND=noninteractive apt-get -yq install iptables >/dev/null
  elif command -v dnf >/dev/null 2>&1; then $SUDO dnf -yq install iptables >/dev/null
  elif command -v yum >/dev/null 2>&1; then $SUDO yum -y -q install iptables >/dev/null
  fi
fi
command -v iptables >/dev/null 2>&1 || { echo "MAYAK_ERROR: не удалось установить iptables"; exit 1; }

# Порты входа должны быть свободны и не совпадать с SSH самого входа
for f in $FORWARDS; do
  IFS=: read -r proto lport rport <<< "$f"
  if [ "$proto" = tcp ] && [ "$lport" = "$OWN_SSH_PORT" ]; then
    echo "MAYAK_ERROR: порт $lport — это SSH самого входного сервера"; exit 1
  fi
  if [ "$proto" = tcp ]; then busy=$($SUDO ss -ltnp 2>/dev/null | grep -E "[:.]$lport\s")
  else busy=$($SUDO ss -lunp 2>/dev/null | grep -E "[:.]$lport\s"); fi
  if [ -n "$busy" ]; then
    echo "MAYAK_ERROR: на входном сервере занят $proto-порт $lport: $busy"; exit 1
  fi
done

if echo "$TARGET_HOST" | grep -qE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'; then
  TARGET="$TARGET_HOST"
else
  TARGET=$(getent ahostsv4 "$TARGET_HOST" | awk 'NR==1{print $1}')
fi
[ -n "$TARGET" ] || { echo "MAYAK_ERROR: входной сервер не может определить IP $TARGET_HOST"; exit 1; }

# Видит ли вход основной сервер (только TCP — UDP так не проверить)
for f in $FORWARDS; do
  IFS=: read -r proto lport rport <<< "$f"
  [ "$proto" = tcp ] && CHECK_TCP="$CHECK_TCP $rport"
done
for rport in $(echo $CHECK_TCP | tr ' ' '\n' | sort -un); do
  if timeout 6 bash -c "</dev/tcp/$TARGET/$rport" 2>/dev/null; then
    echo "MAYAK_REACH: tcp $rport ok"
  else
    echo "MAYAK_REACH: tcp $rport fail"
  fi
done

printf 'TARGET_HOST="%s"\nFORWARDS="%s"\n' "$TARGET_HOST" "$FORWARDS" | $SUDO tee /etc/mayak-relay.conf >/dev/null
$SUDO install -m 755 "{{RELAY_SCRIPT}}" /usr/local/sbin/mayak-relay.sh
echo "net.ipv4.ip_forward=1" | $SUDO tee /etc/sysctl.d/99-mayak-relay.conf >/dev/null

$SUDO tee /etc/systemd/system/mayak-relay.service >/dev/null <<'EOF'
[Unit]
Description=Mayak VPN relay (port forwarding to the main VPN server)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/mayak-relay.sh apply
ExecStop=/usr/local/sbin/mayak-relay.sh remove

[Install]
WantedBy=multi-user.target
EOF
$SUDO systemctl daemon-reload
$SUDO systemctl enable mayak-relay.service >/dev/null 2>&1
$SUDO systemctl restart mayak-relay.service
$SUDO /usr/local/sbin/mayak-relay.sh apply
