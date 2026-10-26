#!/bin/bash
# Маяк VPN: подготовка хоста (как prepare_host.sh + setup_host_firewall.sh в AmneziaVPN).
SUDO="{{SUDO}}"
DOCKERFILE_FOLDER="{{DOCKERFILE_FOLDER}}"
CUR_USER=$(whoami 2>/dev/null || echo "$HOME" | sed 's/.*\///')

$SUDO mkdir -p "$DOCKERFILE_FOLDER"
$SUDO chown "$CUR_USER" "$DOCKERFILE_FOLDER"

if ! $SUDO docker network ls | grep -q amnezia-dns-net; then
  $SUDO docker network create \
    --driver bridge \
    --subnet=172.29.172.0/24 \
    --opt com.docker.network.bridge.name=amn0 \
    amnezia-dns-net
fi

# Сеть и пересылка пакетов
$SUDO sysctl -w net.ipv4.ip_forward=1 >/dev/null
$SUDO iptables -C INPUT -p icmp --icmp-type echo-request -j DROP 2>/dev/null || $SUDO iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
$SUDO iptables -C FORWARD -j DOCKER-USER 2>/dev/null || $SUDO iptables -A FORWARD -j DOCKER-USER
$SUDO iptables -C FORWARD -j DOCKER-ISOLATION-STAGE-1 2>/dev/null || $SUDO iptables -A FORWARD -j DOCKER-ISOLATION-STAGE-1
$SUDO iptables -C FORWARD -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || $SUDO iptables -A FORWARD -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
$SUDO iptables -C FORWARD -o docker0 -j DOCKER 2>/dev/null || $SUDO iptables -A FORWARD -o docker0 -j DOCKER
$SUDO iptables -C FORWARD -i docker0 ! -o docker0 -j ACCEPT 2>/dev/null || $SUDO iptables -A FORWARD -i docker0 ! -o docker0 -j ACCEPT
$SUDO iptables -C FORWARD -i docker0 -o docker0 -j ACCEPT 2>/dev/null || $SUDO iptables -A FORWARD -i docker0 -o docker0 -j ACCEPT

# Тюнинг сети под высокие скорости. BBR, если ядро умеет.
for kv in \
  "net.netfilter.nf_conntrack_max=262144" \
  "fs.file-max=51200" \
  "net.core.rmem_max=67108864" \
  "net.core.wmem_max=67108864" \
  "net.core.netdev_max_backlog=250000" \
  "net.core.somaxconn=4096" \
  "net.ipv4.tcp_syncookies=1" \
  "net.ipv4.tcp_tw_reuse=1" \
  "net.ipv4.tcp_fin_timeout=30" \
  "net.ipv4.tcp_keepalive_time=1200" \
  "net.ipv4.ip_local_port_range=10000 65000" \
  "net.ipv4.tcp_max_syn_backlog=8192" \
  "net.ipv4.tcp_max_tw_buckets=5000" \
  "net.ipv4.tcp_fastopen=3" \
  "net.ipv4.tcp_mtu_probing=1"; do
  $SUDO sysctl -w "$kv" >/dev/null 2>&1 || true
done
if $SUDO sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw bbr || $SUDO modprobe tcp_bbr 2>/dev/null; then
  $SUDO sysctl -w net.core.default_qdisc=fq >/dev/null 2>&1 || true
  $SUDO sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null 2>&1 || true
fi

# Сохраняем ip_forward после перезагрузки
if [ -d /etc/sysctl.d ]; then
  echo "net.ipv4.ip_forward=1" | $SUDO tee /etc/sysctl.d/99-mayak-vpn.conf >/dev/null
fi

echo "MAYAK_OK"
