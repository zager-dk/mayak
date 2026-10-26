#!/bin/bash
# Маяк VPN: установка Docker и служебных утилит (по мотивам install_docker.sh из AmneziaVPN).
# $SUDO — пусто для root, «sudo -n» для пользователя с sudo без пароля.
SUDO="{{SUDO}}"

if pm=$(command -v apt-get 2>/dev/null); then silent_inst="-yq install --install-recommends"; what_pkg="-s install"; check_pkgs="-yq update"; docker_pkg="docker.io"; dist="debian";
elif pm=$(command -v dnf 2>/dev/null); then silent_inst="-yq install"; what_pkg="--assumeno install --setopt=tsflags=test"; check_pkgs="-yq check-update"; docker_pkg="docker"; dist="fedora";
elif pm=$(command -v yum 2>/dev/null); then silent_inst="-y -q install"; what_pkg="--assumeno install --setopt=tsflags=test"; check_pkgs="-y -q check-update"; docker_pkg="docker"; dist="centos";
elif pm=$(command -v zypper 2>/dev/null); then silent_inst="-nq install"; what_pkg="--dry-run install"; check_pkgs="-nq refresh"; docker_pkg="docker"; dist="suse";
elif pm=$(command -v pacman 2>/dev/null); then silent_inst="-S --noconfirm --noprogressbar --quiet"; what_pkg="-Sp"; check_pkgs="-Sup"; docker_pkg="docker"; dist="archlinux";
else echo "MAYAK_ERROR: неизвестный менеджер пакетов, поддерживаются Debian/Ubuntu/Fedora/CentOS/openSUSE/Arch"; exit 1;
fi

echo "Дистрибутив: $dist, менеджер пакетов: $pm"
echo "$LANG" | grep -qE '^(en_US.UTF-8|C.UTF-8|C)$' || export LC_ALL=C
if [ "$dist" = "debian" ]; then export DEBIAN_FRONTEND=noninteractive; fi

if [ -n "$SUDO" ] && ! command -v sudo >/dev/null 2>&1; then
  echo "MAYAK_ERROR: sudo не установлен. Подключайтесь под root."; exit 1
fi

for tool in which fuser lsof; do
  if ! command -v $tool >/dev/null 2>&1; then
    pkg=$tool; [ "$tool" = "fuser" ] && pkg=psmisc
    $SUDO $pm $check_pkgs >/dev/null 2>&1; $SUDO $pm $silent_inst $pkg >/dev/null 2>&1
  fi
done

if ! command -v docker >/dev/null 2>&1; then
  echo "Устанавливаю Docker..."
  $SUDO $pm $check_pkgs
  if ! $SUDO $pm $what_pkg $docker_pkg 2>/dev/null | grep -qi podman; then
    $SUDO $pm $silent_inst $docker_pkg
    sleep 5; $SUDO systemctl enable --now docker; sleep 5
  else
    echo "MAYAK_ERROR: в репозитории только podman, он не поддерживается"; exit 1
  fi
fi

if [ "$($SUDO cat /sys/module/apparmor/parameters/enabled 2>/dev/null)" = "Y" ]; then
  if ! command -v apparmor_parser >/dev/null 2>&1; then
    $SUDO $pm $check_pkgs; $SUDO $pm $silent_inst apparmor
  fi
fi

if [ "$($SUDO systemctl is-active docker 2>/dev/null)" != "active" ]; then
  sleep 5; $SUDO systemctl start docker; sleep 5
fi
if [ "$($SUDO systemctl is-active docker 2>/dev/null)" != "active" ]; then
  echo "MAYAK_ERROR: служба Docker не запустилась"; exit 1
fi

$SUDO docker --version
uname -sr
echo "MAYAK_OK"
