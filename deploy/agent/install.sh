#!/bin/bash
# Маяк: установка или обновление агента на сервере (выход или вход), под root.
# Команду с токеном выдаёт админка: «Серверы» → «+ Сервер».
#   curl -fsSL https://mayaklight.ru/download/install-agent.sh | bash -s -- --api https://mayaklight.ru --token …
# --dry-run — пробный режим: агент переносит людей в API и показывает, что изменил бы, но VPN не трогает.
# Чтобы включить по-настоящему, выполните ту же команду без --dry-run.
set -euo pipefail
API=""
TOKEN=""
DRY=false
while [ $# -gt 0 ]; do
  case "$1" in
    --api) API="${2%/}"; shift 2 ;;
    --token) TOKEN="$2"; shift 2 ;;
    --dry-run) DRY=true; shift ;;
    *) echo "Неизвестный параметр: $1"; exit 1 ;;
  esac
done
say() { echo -e "\n\033[1;33m▸ $*\033[0m"; }
die() { echo -e "\n\033[1;31m✖ $*\033[0m"; exit 1; }
[ "$(id -u)" = 0 ] || die "Запустите от root"
[ -n "$API" ] && [ -n "$TOKEN" ] || die "Нужны --api и --token (команду выдаёт админка Маяка)"

say "Агент Маяка"
mkdir -p /opt/mayak /etc/mayak /var/lib/mayak-agent
curl -fsSL --retry 3 "$API/download/mayak-agent" -o /opt/mayak/mayak-agent.new || die "Не удалось скачать агента с $API"
chmod 755 /opt/mayak/mayak-agent.new
mv -f /opt/mayak/mayak-agent.new /opt/mayak/mayak-agent
( umask 077; printf '{\n  "api": "%s",\n  "token": "%s",\n  "dryRun": %s\n}\n' "$API" "$TOKEN" "$DRY" > /etc/mayak/agent.json )
if $DRY; then say "Пробный режим: настройки VPN меняться не будут"; fi

cat > /etc/systemd/system/mayak-agent.service <<'UNIT'
[Unit]
Description=Mayak agent (applies settings from the Mayak API)
After=network-online.target docker.service
Wants=network-online.target

[Service]
ExecStart=/opt/mayak/mayak-agent /etc/mayak/agent.json
Restart=always
RestartSec=10
StateDirectory=mayak-agent
Environment=DOTNET_BUNDLE_EXTRACT_BASE_DIR=/var/lib/mayak-agent

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload

say "Проверка связи с API"
if DOTNET_BUNDLE_EXTRACT_BASE_DIR=/var/lib/mayak-agent /opt/mayak/mayak-agent /etc/mayak/agent.json --once; then
  systemctl enable -q mayak-agent
  systemctl restart mayak-agent
  echo -e "\n\033[1;32m✔ Агент работает. Журнал: journalctl -u mayak-agent -f\033[0m"
  if $DRY; then echo -e "\033[1;33m  Пробный режим: посмотрите в админке, что агент изменил бы. Если всё верно — повторите команду без --dry-run.\033[0m"; fi
else
  systemctl enable -q mayak-agent
  systemctl restart mayak-agent
  echo -e "\n\033[1;33m! Первая синхронизация не удалась (см. выше). Агент будет повторять попытки сам: journalctl -u mayak-agent -f\033[0m"
fi
