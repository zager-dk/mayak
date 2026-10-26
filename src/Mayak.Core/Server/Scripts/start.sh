#!/bin/bash

# Запускается внутри контейнера при каждом старте (совместим со start.sh AmneziaVPN).

echo "Container startup"

# kill daemons in case of restart
awg-quick down /opt/amnezia/awg/awg0.conf

# start daemons if configured
if [ -f /opt/amnezia/awg/awg0.conf ]; then (awg-quick up /opt/amnezia/awg/awg0.conf); fi

# Allow traffic on the TUN interface.
iptables -A INPUT -i awg0 -j ACCEPT
iptables -A FORWARD -i awg0 -j ACCEPT
iptables -A OUTPUT -o awg0 -j ACCEPT

# Allow forwarding traffic only from the VPN.
iptables -A FORWARD -i awg0 -o eth0 -s {{SUBNET_IP}}/{{SUBNET_CIDR}} -j ACCEPT
iptables -A FORWARD -i awg0 -o eth1 -s {{SUBNET_IP}}/{{SUBNET_CIDR}} -j ACCEPT

iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

iptables -t nat -A POSTROUTING -s {{SUBNET_IP}}/{{SUBNET_CIDR}} -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s {{SUBNET_IP}}/{{SUBNET_CIDR}} -o eth1 -j MASQUERADE

# Mayak VPN: speed limits
if [ -x /opt/amnezia/awg/mayak_tc.sh ]; then /opt/amnezia/awg/mayak_tc.sh; fi

tail -f /dev/null
