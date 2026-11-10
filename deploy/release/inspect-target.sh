#!/usr/bin/env bash
# Read-only target preflight for the Timeweb console. No files/services changed.
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly API_DIR=/opt/mayak/api
readonly CONFIG=/etc/mayak/api.json
readonly GATEWAY_KEY=/etc/mayak/gateway.pem
readonly UNIT=mayak-api.service
readonly CADDYFILE=/etc/caddy/Caddyfile
readonly EXPECTED_CADDY_SHA256=4371021453096fa9990acaedc0fb23fb18950e46f7199a70ebfdb553ff4e5353
readonly EXPECTED_GATEWAY_SPKI=06537531B7171787CA75D9F94B3EDC49E55FEB0DBB8FF7DAE5559C23C00C1DA2
readonly HEALTH_URL=http://127.0.0.1:5080/health

refuse() { printf 'INSPECT REFUSED: %s\n' "$1" >&2; exit 2; }
[[ $EUID -eq 0 ]] || refuse 'run from the Timeweb console as root (sudo -i)'

[[ -r /etc/os-release ]] || refuse 'cannot identify Linux distribution'
. /etc/os-release
[[ ${ID:-} == ubuntu && ( ${VERSION_ID:-} == 22.04 || ${VERSION_ID:-} == 24.04 ) ]] || refuse 'unsupported OS; expected Ubuntu 22.04/24.04'

for tool in systemctl dotnet python3 pg_isready curl openssl stat df; do
  command -v "$tool" >/dev/null 2>&1 || refuse "required inspection tool missing: $tool"
done
command -v caddy >/dev/null 2>&1 || refuse 'Caddy executable missing'
systemctl is-active --quiet mayak-api.service || refuse 'Mayak API service is not active'
systemctl is-active --quiet caddy.service || refuse 'Caddy service is not active'
runuser -u postgres -- pg_isready --host=/var/run/postgresql --username=postgres --quiet || refuse 'local PostgreSQL is not accepting connections'

[[ -d "$API_DIR" && ! -L "$API_DIR" && -f "$API_DIR/mayak-api.dll" ]] || refuse 'expected API directory or binary missing/symlinked'
[[ -f "$CONFIG" && ! -L "$CONFIG" && -f "$GATEWAY_KEY" && ! -L "$GATEWAY_KEY" ]] || refuse 'expected config/key path missing or symlinked'
[[ -f "$CADDYFILE" && ! -L "$CADDYFILE" ]] || refuse 'expected Caddyfile missing or symlinked'
# Reject symlinked ancestors as well as final components; all expected paths
# must resolve through ordinary directories.
for p in /opt /opt/mayak /opt/mayak/api /etc /etc/mayak /etc/caddy; do
  [[ ! -L "$p" ]] || refuse 'an expected deployment path has a symlinked ancestor'
done
id mayak >/dev/null 2>&1 || refuse 'expected API account mayak missing'
id caddy >/dev/null 2>&1 || refuse 'expected Caddy account missing'
[[ $(stat -c '%U:%G' "$CONFIG") == root:mayak && $(stat -c '%a' "$CONFIG") =~ ^(600|640)$ ]] || refuse 'API config owner/mode differs from supported secure baseline'
[[ $(stat -c '%U:%G' "$GATEWAY_KEY") == root:mayak && $(stat -c '%a' "$GATEWAY_KEY") =~ ^(600|640)$ ]] || refuse 'gateway private-key owner/mode differs from supported secure baseline'
runuser -u mayak -- test -r "$CONFIG" && runuser -u mayak -- test -r "$GATEWAY_KEY" && runuser -u mayak -- test -r "$API_DIR/mayak-api.dll" || refuse 'API service account cannot read an expected file'

user=$(systemctl show -p User --value "$UNIT")
workdir=$(systemctl show -p WorkingDirectory --value "$UNIT")
fragment=$(systemctl show -p FragmentPath --value "$UNIT")
dropins=$(systemctl show -p DropInPaths --value "$UNIT")
envfiles=$(systemctl show -p EnvironmentFiles --value "$UNIT")
[[ $user == mayak && $workdir == "$API_DIR" ]] || refuse 'API service user or working directory differs from supported layout'
# Capture sensitive effective values inside Python; never forward them in argv
# or print command failures (which may contain effective unit values).
python3 - <<'PY' || refuse 'effective API ExecStart arguments or Environment differ from supported layout'
import re,shlex,subprocess
try:
    def effective(prop):
        return subprocess.check_output(
            ['systemctl','show','-p',prop,'--value','mayak-api.service'],
            stderr=subprocess.DEVNULL,text=True).strip()
    raw=effective('ExecStart')
    env=effective('Environment')
    command=re.fullmatch(r'\{\s*path=([^;{}]+?)\s*;\s*argv\[\]=([^;{}]+?)\s*;\s*ignore_errors=no\s*;[^{}]*\}',raw,re.S)
    if command is None: raise SystemExit(1)
    args=command.group(2).split()
    values=shlex.split(env)
except (OSError,ValueError,subprocess.SubprocessError): raise SystemExit(1)
if args != ['/usr/bin/dotnet','/opt/mayak/api/mayak-api.dll']: raise SystemExit(1)
if command.group(1) != args[0]: raise SystemExit(1)
expected={'HOME=/var/lib/mayak','DOTNET_CLI_TELEMETRY_OPTOUT=1','MAYAK_DistDir=/opt/mayak/dist'}
if len(values)!=len(expected) or set(values)!=expected: raise SystemExit(1)
PY
[[ $fragment == /etc/systemd/system/mayak-api.service && -z $dropins && -z $envfiles ]] || refuse 'API unit source/drop-ins/environment files differ from supported layout'

runtime_count=$(dotnet --list-runtimes 2>/dev/null | awk '$1=="Microsoft.NETCore.App" && $2 ~ /^10\./ {n++} END {print n+0}')
[[ $runtime_count == 1 ]] || refuse '.NET 10 runtime missing or ambiguous'
fingerprint=$(openssl pkey -passin pass: -in "$GATEWAY_KEY" -pubout -outform DER 2>/dev/null | openssl dgst -sha256 -r | awk '{print toupper($1)}') || refuse 'gateway key is not a readable PEM key'
[[ $fingerprint == "$EXPECTED_GATEWAY_SPKI" ]] || refuse 'gateway public-key pin does not match approved release pin'

python3 "$(dirname -- "$0")/release_safety.py" caddy-hash "$CADDYFILE" "$EXPECTED_CADDY_SHA256" || refuse 'Caddyfile differs from the observed preserved overlay snapshot'
caddy validate --config "$CADDYFILE" --adapter caddyfile >/dev/null 2>&1 || refuse 'existing Caddy configuration is invalid'

# Check Caddy's effective unit identity and command without printing its args.
caddy_user=$(systemctl show -p User --value caddy.service)
caddy_group=$(systemctl show -p Group --value caddy.service)
caddy_fragment=$(systemctl show -p FragmentPath --value caddy.service)
caddy_dropins=$(systemctl show -p DropInPaths --value caddy.service)
caddy_envfiles=$(systemctl show -p EnvironmentFiles --value caddy.service)
python3 - <<'PY' || refuse 'effective Caddy ExecStart is not the supported config invocation'
import re,subprocess
try:
    raw=subprocess.check_output(
        ['systemctl','show','-p','ExecStart','--value','caddy.service'],
        stderr=subprocess.DEVNULL,text=True).strip()
except (OSError,ValueError,subprocess.SubprocessError): raise SystemExit(1)
command=re.fullmatch(r'\{\s*path=([^;{}]+?)\s*;\s*argv\[\]=([^;{}]+?)\s*;\s*ignore_errors=no\s*;[^{}]*\}',raw,re.S)
if command is None: raise SystemExit(1)
args=command.group(2).split()
if args != ['/usr/bin/caddy','run','--environ','--config','/etc/caddy/Caddyfile']: raise SystemExit(1)
if command.group(1) != args[0]: raise SystemExit(1)
PY
[[ $caddy_user == caddy && $caddy_group == caddy && $caddy_fragment == /usr/lib/systemd/system/caddy.service && -z $caddy_dropins && -z $caddy_envfiles ]] || refuse 'Caddy unit source/drop-ins/environment files are unsupported'

curl --noproxy '*' --fail --silent --max-time 4 "$HEALTH_URL" >/dev/null || refuse 'local API health check failed'
free_mb=$(df -Pm /opt /var/backups | awk 'NR>1 {if ($4<m || m==0) m=$4} END {print m+0}')
(( free_mb > 1024 )) || refuse 'less than 1 GiB free on API/backup filesystems'
# The on-disk baseline and unit invocation do not prove loaded route binding.
# Leave that fact unverified here; the separate apply gate must verify it.
printf 'TARGET INSPECT: Ubuntu %s; exact API identity/args/env and Caddy unit; API health; .NET 8; PostgreSQL accepts local connections; on-disk Caddy baseline; service-readable protected config/key; gateway pin; %s MiB free.\n' "$VERSION_ID" "$free_mb"
printf 'Read-only result: no config values, keys, credentials, tokens, logs or database rows printed; no files/services changed.\n'
printf 'Caddy loaded route: NOT_VERIFIED (loaded routing not inspected); API database/role reachability: NOT_VERIFIED. This inspector is informational only; it is not an --apply authorization.\n'
