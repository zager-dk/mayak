#!/bin/bash
# Маяк VPN: ограничение скорости для каждого устройства.
# Запускается внутри контейнера amnezia-awg2 при старте и после изменений в приложении.
#
# Файл лимитов /opt/amnezia/awg/mayak_limits, строка на устройство:
#   <IP> <скачивание, кбит/с> <отдача, кбит/с> <classid в hex>
# 0 — без ограничения в эту сторону.
#
# Скачивание (сервер -> клиент): HTB-класс на устройство + fq_codel на исходящей очереди awg0.
# Отдача (клиент -> сервер): policer на входящей очереди awg0.

IFACE=awg0
LIMITS=/opt/amnezia/awg/mayak_limits

if ! command -v tc >/dev/null 2>&1; then
  echo "MAYAK_ERROR: tc не найден (нужен пакет iproute2)"
  exit 2
fi

if ! ip link show "$IFACE" >/dev/null 2>&1; then
  echo "MAYAK_WARN: интерфейс $IFACE не поднят, лимиты не применены"
  exit 0
fi

tc qdisc del dev "$IFACE" root >/dev/null 2>&1
tc qdisc del dev "$IFACE" ingress >/dev/null 2>&1

if [ ! -s "$LIMITS" ]; then
  echo "MAYAK_OK: лимитов нет"
  exit 0
fi

ERRORS=0
run() {
  if ! "$@" 2>/tmp/mayak_tc.err; then
    ERRORS=$((ERRORS + 1))
    echo "MAYAK_WARN: $* -> $(cat /tmp/mayak_tc.err)"
  fi
}

# Корень: всё, что не попало под фильтры, идёт в класс 1:2 без ограничения.
run tc qdisc add dev "$IFACE" root handle 1: htb default 2
run tc class add dev "$IFACE" parent 1: classid 1:1 htb rate 10gbit ceil 10gbit quantum 60000
run tc class add dev "$IFACE" parent 1:1 classid 1:2 htb rate 10gbit ceil 10gbit quantum 60000
run tc qdisc add dev "$IFACE" parent 1:2 handle 2: fq_codel
run tc qdisc add dev "$IFACE" handle ffff: ingress

COUNT=0
while read -r IP DOWN UP CLASSID _; do
  case "$IP" in ''|\#*) continue ;; esac
  DOWN=${DOWN:-0}; UP=${UP:-0}

  if [ "$DOWN" -gt 0 ] 2>/dev/null; then
    # burst ~ 10 мс на текущей скорости, но не меньше 32 КБ
    BURST=$(( DOWN * 1000 / 8 / 100 ))
    [ "$BURST" -lt 32000 ] && BURST=32000
    run tc class add dev "$IFACE" parent 1:1 classid "1:$CLASSID" htb rate "${DOWN}kbit" ceil "${DOWN}kbit" burst "$BURST" cburst "$BURST" quantum 60000
    run tc qdisc add dev "$IFACE" parent "1:$CLASSID" handle "$CLASSID:" fq_codel
    run tc filter add dev "$IFACE" parent 1: protocol ip prio 1 u32 match ip dst "$IP/32" flowid "1:$CLASSID"
  fi

  if [ "$UP" -gt 0 ] 2>/dev/null; then
    # burst ~ 100 мс на текущей скорости, но не меньше 64 КБ — policer терпимее к TCP
    BURST=$(( UP * 1000 / 8 / 10 ))
    [ "$BURST" -lt 64000 ] && BURST=64000
    run tc filter add dev "$IFACE" parent ffff: protocol ip prio 1 u32 match ip src "$IP/32" police rate "${UP}kbit" burst "$BURST" drop flowid :1
  fi
  COUNT=$((COUNT + 1))
done < "$LIMITS"

if [ "$ERRORS" -gt 0 ]; then
  echo "MAYAK_WARN: лимиты применены с ошибками ($ERRORS), устройств: $COUNT"
  exit 1
fi
echo "MAYAK_OK: лимиты применены, устройств: $COUNT"
