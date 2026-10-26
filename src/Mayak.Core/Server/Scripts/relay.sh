#!/bin/bash
# Маяк VPN: входной сервер. Пересылает порты на основной VPN-сервер правилами ядра (DNAT + MASQUERADE).
# Шифрование не снимается: AmneziaWG и Reality идут насквозь до основного сервера.
# Использование: mayak-relay.sh [apply|remove]   (настройки — /etc/mayak-relay.conf)

CONF=/etc/mayak-relay.conf
[ -f "$CONF" ] && . "$CONF"

remove_rules() {
  iptables -t nat -D PREROUTING -j MAYAK_PRE 2>/dev/null
  iptables -t nat -D POSTROUTING -j MAYAK_POST 2>/dev/null
  iptables -D FORWARD -j MAYAK_FWD 2>/dev/null
  iptables -t nat -F MAYAK_PRE 2>/dev/null; iptables -t nat -X MAYAK_PRE 2>/dev/null
  iptables -t nat -F MAYAK_POST 2>/dev/null; iptables -t nat -X MAYAK_POST 2>/dev/null
  iptables -F MAYAK_FWD 2>/dev/null; iptables -X MAYAK_FWD 2>/dev/null
}

if [ "$1" = "remove" ]; then
  remove_rules
  echo "MAYAK_OK: пересылка снята"
  exit 0
fi

if [ -z "$TARGET_HOST" ] || [ -z "$FORWARDS" ]; then
  echo "MAYAK_ERROR: нет настроек в $CONF"
  exit 1
fi

if echo "$TARGET_HOST" | grep -qE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'; then
  TARGET="$TARGET_HOST"
else
  TARGET=$(getent ahostsv4 "$TARGET_HOST" | awk 'NR==1{print $1}')
fi
if [ -z "$TARGET" ]; then
  echo "MAYAK_ERROR: не удалось определить IP основного сервера $TARGET_HOST"
  exit 1
fi

sysctl -w net.ipv4.ip_forward=1 >/dev/null

remove_rules
iptables -t nat -N MAYAK_PRE
iptables -t nat -N MAYAK_POST
iptables -N MAYAK_FWD
iptables -t nat -I PREROUTING 1 -j MAYAK_PRE
iptables -t nat -I POSTROUTING 1 -j MAYAK_POST
iptables -I FORWARD 1 -j MAYAK_FWD

for f in $FORWARDS; do
  IFS=: read -r proto lport rport <<< "$f"
  iptables -t nat -A MAYAK_PRE -p "$proto" --dport "$lport" -j DNAT --to-destination "$TARGET:$rport"
  iptables -t nat -A MAYAK_POST -p "$proto" -d "$TARGET" --dport "$rport" -j MASQUERADE
  iptables -A MAYAK_FWD -p "$proto" -d "$TARGET" --dport "$rport" -j ACCEPT
done
iptables -A MAYAK_FWD -s "$TARGET" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

echo "MAYAK_OK: пересылка на $TARGET ($FORWARDS)"
