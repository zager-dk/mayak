#!/bin/bash
# Маяк: установка или обновление API (Ubuntu 22.04/24.04, под root).
#   curl -fsSL https://raw.githubusercontent.com/zager-dk/mayak/main/deploy/api/install.sh | bash -s -- --domain mayaklight.ru
# Повторный запуск обновляет API и агента до свежей версии из репозитория; база и настройки сохраняются.
# Сервер API лучше держать отдельно от входа (каскада): вход пересылает порт 443, а здесь на нём HTTPS.
set -euo pipefail
REPO="https://github.com/zager-dk/mayak.git"
BRANCH="main"
DOMAIN=""
while [ $# -gt 0 ]; do
  case "$1" in
    --domain) DOMAIN="$2"; shift 2 ;;
    --branch) BRANCH="$2"; shift 2 ;;
    --repo) REPO="$2"; shift 2 ;;
    *) echo "Неизвестный параметр: $1"; exit 1 ;;
  esac
done

say() { echo -e "\n\033[1;33m▸ $*\033[0m"; }
die() { echo -e "\n\033[1;31m✖ $*\033[0m"; exit 1; }
[ "$(id -u)" = 0 ] || die "Запустите от root"
. /etc/os-release
[ "$ID" = ubuntu ] || die "Нужна Ubuntu 22.04 или 24.04 (сейчас $PRETTY_NAME)"

CONF=/etc/mayak/api.json
if [ -z "$DOMAIN" ] && [ -f "$CONF" ]; then
  DOMAIN=$(python3 -c "import json;print(json.load(open('$CONF'))['PublicUrl'].split('//',1)[1])")
fi
[ -n "$DOMAIN" ] || read -rp "Домен API (например mayaklight.ru): " DOMAIN </dev/tty
MYIP=$(ip -4 route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}')
DNSIP=$(getent ahostsv4 "$DOMAIN" | awk 'NR==1{print $1}' || true)
if [ "$DNSIP" != "$MYIP" ]; then
  echo "Внимание: $DOMAIN указывает на ${DNSIP:-ничего}, а у этого сервера адрес $MYIP."
  echo "HTTPS-сертификат выпустится, только когда DNS укажет сюда (A-запись в панели домена)."
fi

say "Пакеты: PostgreSQL, .NET 8, Caddy"
export DEBIAN_FRONTEND=noninteractive
# Зеркало хостера (например, mirror.timeweb.ru) бывает недоступно из самой ВМ — тогда берём официальное.
fix_mirrors() {
  local files host
  files=$(ls /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources 2>/dev/null || true)
  for host in $(grep -hoE 'https?://[^/ ]+' $files 2>/dev/null | sed -E 's#https?://##' | sort -u); do
    case "$host" in *ubuntu.com|*debian.org|*cloudsmith.io|*microsoft.com) continue ;; esac
    if ! getent hosts "$host" >/dev/null; then
      echo "Зеркало $host не находится — переключаю на официальные зеркала Ubuntu"
      sed -i -E "s#https?://$host/ubuntu/?#http://archive.ubuntu.com/ubuntu/#g" $files
    fi
  done
}
fix_mirrors
apt-get update -qq || die "apt-get update не прошёл — проверьте интернет и DNS на сервере (cat /etc/resolv.conf)"
apt-get install -y -qq postgresql git curl ca-certificates python3 sudo >/dev/null
if ! command -v dotnet >/dev/null || ! dotnet --list-sdks 2>/dev/null | grep -q '^8\.'; then
  apt-get install -y -qq dotnet-sdk-8.0 >/dev/null || die "Не удалось установить .NET 8"
fi
if ! command -v caddy >/dev/null; then
  if ! apt-get install -y -qq caddy >/dev/null 2>&1; then
    apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https gnupg >/dev/null
    curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/gpg.key | gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt > /etc/apt/sources.list.d/caddy-stable.list
    apt-get update -qq
    apt-get install -y -qq caddy >/dev/null || die "Не удалось установить Caddy"
  fi
fi

say "Исходники"
mkdir -p /opt/mayak
if [ -d /opt/mayak/src/.git ]; then
  git -C /opt/mayak/src fetch -q --depth 1 origin "$BRANCH"
  git -C /opt/mayak/src reset -q --hard FETCH_HEAD
else
  rm -rf /opt/mayak/src
  git clone -q --depth 1 --branch "$BRANCH" "$REPO" /opt/mayak/src
fi
echo "Версия: $(git -C /opt/mayak/src log -1 --format='%h %s')"

say "Сборка API и агента (2–5 минут)"
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 HOME=/root
rm -rf /opt/mayak/api.new /opt/mayak/agent-build
dotnet publish /opt/mayak/src/src/Mayak.Api -c Release -o /opt/mayak/api.new --nologo -v q >/tmp/mayak-build.log 2>&1 || { tail -30 /tmp/mayak-build.log; die "Сборка API не удалась"; }
dotnet publish /opt/mayak/src/src/Mayak.Agent -c Release -r linux-x64 --self-contained -p:PublishSingleFile=true \
  -p:EnableCompressionInSingleFile=true -o /opt/mayak/agent-build --nologo -v q >>/tmp/mayak-build.log 2>&1 || { tail -30 /tmp/mayak-build.log; die "Сборка агента не удалась"; }
mkdir -p /opt/mayak/dist
install -m 755 /opt/mayak/agent-build/mayak-agent /opt/mayak/dist/mayak-agent
install -m 644 /opt/mayak/src/deploy/agent/install.sh /opt/mayak/dist/install-agent.sh

say "База данных и настройки"
id mayak >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin -d /var/lib/mayak mayak
mkdir -p /etc/mayak
if [ ! -f "$CONF" ]; then
  DBPASS=$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 28)
  sudo -u postgres psql -qtAc "SELECT 1 FROM pg_roles WHERE rolname='mayak'" | grep -q 1 || sudo -u postgres psql -qc "CREATE ROLE mayak LOGIN"
  sudo -u postgres psql -qc "ALTER ROLE mayak PASSWORD '$DBPASS'"
  sudo -u postgres psql -qtAc "SELECT 1 FROM pg_database WHERE datname='mayak'" | grep -q 1 || sudo -u postgres psql -qc "CREATE DATABASE mayak OWNER mayak"
  echo
  echo "Токен Telegram-бота от @BotFather (ввод не отображается; Enter — пропустить):"
  read -rs TGTOKEN </dev/tty || TGTOKEN=""
  echo
  python3 - "$CONF" "$DOMAIN" "$DBPASS" "$TGTOKEN" <<'PY'
import json, sys
path, domain, dbpass, tg = sys.argv[1:5]
cfg = {
    "ConnectionStrings": {"Db": f"Host=127.0.0.1;Database=mayak;Username=mayak;Password={dbpass}"},
    "PublicUrl": f"https://{domain}",
    "Telegram": {"Token": tg.strip()},
    "Kestrel": {"Endpoints": {"Http": {"Url": "http://127.0.0.1:5080"}}},
    "Logging": {"LogLevel": {"Default": "Information", "Microsoft.EntityFrameworkCore": "Warning", "Microsoft.AspNetCore": "Warning"}},
}
with open(path, "w") as f:
    json.dump(cfg, f, ensure_ascii=False, indent=2)
PY
else
  echo "Настройки уже есть ($CONF) — оставляю как есть."
fi
chown root:mayak "$CONF"
chmod 640 "$CONF"

say "Служба mayak-api"
rm -rf /opt/mayak/api.old
[ -d /opt/mayak/api ] && mv /opt/mayak/api /opt/mayak/api.old
mv /opt/mayak/api.new /opt/mayak/api
cat > /etc/systemd/system/mayak-api.service <<'UNIT'
[Unit]
Description=Mayak API
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
User=mayak
WorkingDirectory=/opt/mayak/api
ExecStart=/usr/bin/dotnet /opt/mayak/api/mayak-api.dll
Restart=always
RestartSec=5
StateDirectory=mayak
Environment=HOME=/var/lib/mayak
Environment=DOTNET_CLI_TELEMETRY_OPTOUT=1
Environment=MAYAK_DistDir=/opt/mayak/dist

[Install]
WantedBy=multi-user.target
UNIT
cat > /usr/local/bin/mayak-api <<'CLI'
#!/bin/bash
# Команды обслуживания API: mayak-api servers | role @telegram owner | add-server exit "Имя" IP
cd /opt/mayak/api && exec sudo -u mayak HOME=/var/lib/mayak MAYAK_DistDir=/opt/mayak/dist /usr/bin/dotnet mayak-api.dll "$@"
CLI
chmod 755 /usr/local/bin/mayak-api
systemctl daemon-reload
systemctl enable -q mayak-api
systemctl restart mayak-api
for i in $(seq 1 30); do curl -fs http://127.0.0.1:5080/health >/dev/null && break; sleep 2; done
curl -fs http://127.0.0.1:5080/health >/dev/null || { journalctl -u mayak-api -n 30 --no-pager; die "API не запустился"; }

say "HTTPS (Caddy, сертификат Let's Encrypt)"
cat > /etc/caddy/Caddyfile <<CADDY
# Маяк: HTTPS для API. Сертификат выпускается и продлевается сам.
$DOMAIN {
	encode gzip
	reverse_proxy 127.0.0.1:5080
}
CADDY
systemctl enable -q caddy
systemctl restart caddy
ok=""
for i in $(seq 1 30); do curl -fs --max-time 5 "https://$DOMAIN/health" >/dev/null 2>&1 && { ok=1; break; }; sleep 3; done
rm -rf /opt/mayak/api.old

echo
if [ -n "$ok" ]; then
  echo -e "\033[1;32m✔ Маяк API работает: https://$DOMAIN\033[0m"
else
  echo -e "\033[1;33m! API запущен, но https://$DOMAIN пока не открывается — проверьте A-запись домена и порты 80/443.\033[0m"
fi
cat <<DONE

Дальше:
  1. Откройте https://$DOMAIN/admin и войдите через Telegram.
     Первый вошедший станет владельцем — войдите сразу.
  2. «Серверы» → «+ Сервер»: добавьте выход (на нём уже стоит VPN Маяка)
     и выполните на нём показанную команду — агент перенесёт людей в API.

Обслуживание: mayak-api servers · журнал: journalctl -u mayak-api -f
Обновление: запустите эту же команду ещё раз.
DONE
