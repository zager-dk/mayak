#!/usr/bin/env bash
# Reviewed pull-release entry point. It is intentionally API-only.
set +x
set -Eeuo pipefail
shopt -s inherit_errexit
IFS=$'\n\t'
umask 077

readonly API_DIR=/opt/mayak/api
readonly CONFIG=/etc/mayak/api.json
readonly GATEWAY_KEY=/etc/mayak/gateway.pem
readonly DIST=/opt/mayak/dist
readonly UNIT=mayak-api.service
readonly CADDYFILE=/etc/caddy/Caddyfile
readonly RELEASES=/opt/mayak/releases
readonly BACKUPS=/var/backups/mayak-release
readonly EXPECTED_GATEWAY_SPKI=06537531B7171787CA75D9F94B3EDC49E55FEB0DBB8FF7DAE5559C23C00C1DA2
readonly EXPECTED_CADDY_SHA256=4371021453096fa9990acaedc0fb23fb18950e46f7199a70ebfdb553ff4e5353
readonly HEALTH_URL=http://127.0.0.1:5080/health
readonly SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
readonly SAFETY="$SCRIPT_DIR/release_safety.py"

usage() {
  cat <<'EOF'
Usage:
  sudo bash release-entry.sh --inspect-target
  sudo bash release-entry.sh --inspect --bundle /path/bundle.tar.gz --sha256 HEX
  sudo bash release-entry.sh --apply --bundle /path/bundle.tar.gz --sha256 HEX --confirm-api-only --confirm-write-window
  sudo bash release-entry.sh --rollback RELEASE_ID

Run --inspect first. Upload the bundle over HTTPS, then independently compare
its SHA-256 with the value supplied by the release owner. Do not use the old
deploy/api/install.sh. This script never changes VPN services or routes.
EOF
}
die() { printf 'REFUSED: %s\n' "$1" >&2; exit 2; }
note() { printf '%s\n' "$1"; }

# BEGIN TRANSACTION HELPERS (executed in isolated failure fixtures)
stop_candidate() {
  local failed=0
  if [[ -n ${candidate_pid:-} ]]; then
    kill -- -"$candidate_pid" >/dev/null 2>&1 || kill "$candidate_pid" >/dev/null 2>&1 || true
    wait "$candidate_pid" 2>/dev/null || true
    candidate_pid=
  fi
  return "$failed"
}

cleanup_fixture() {
  local failed=0
  stop_candidate || failed=1
  if [[ -n ${fixture:-} ]]; then
    if timeout 30 runuser -u postgres -- dropdb --host=/var/run/postgresql --port=5432 --username=postgres --no-password --if-exists "$fixture" >/dev/null 2>&1; then fixture=; else failed=1; fi
  fi
  return "$failed"
}

restore_asset() {
  local source=$1 destination=$2 owner=$3 group=$4 mode=$5
  local temporary="$destination.recover-$release_id"
  [[ ! -L $temporary && ( ! -e $temporary || -f $temporary ) ]] || return 1
  install -o "$owner" -g "$group" -m "$mode" "$source" "$temporary" && mv -f -- "$temporary" "$destination"
}

restore_assets() {
  local failed=0 n recovery=${1:-$recovery}
  restore_asset "$recovery/api.json.previous" "$CONFIG" root mayak 0640 || failed=1
  if ! cmp -s -- "$recovery/Caddyfile.previous" "$CADDYFILE"; then
    restore_asset "$recovery/Caddyfile.previous" "$CADDYFILE" root root 0644 || failed=1
  fi
  for n in windows-x64 android-arm64; do
    if [[ -f "$recovery/$n.json.previous" ]]; then restore_asset "$recovery/$n.json.previous" "$static_root/updates/stable/$n.json" root caddy 0640 || failed=1;
    elif [[ -f "$recovery/$n.json.absent" ]]; then rm -f -- "$static_root/updates/stable/$n.json" || failed=1;
    else failed=1; fi
  done
  if [[ -f "$recovery/agent.previous" ]]; then restore_asset "$recovery/agent.previous" "$DIST/mayak-agent" root mayak 0750 || failed=1;
  elif [[ -f "$recovery/agent.absent" ]]; then rm -f -- "$DIST/mayak-agent" || failed=1;
  else failed=1; fi
  return "$failed"
}

probe_api() {
  local attempt
  for attempt in {1..30}; do
    if curl --noproxy '*' --fail --silent --max-time 2 "$HEALTH_URL" >/dev/null 2>&1; then return 0; fi
    sleep 2
  done
  return 1
}

recover_transaction() {
  local failed=0 caddy_changed=0
  # Each operation is guarded: a failed static/config restore must never skip
  # the final attempt to restart the available API. No database is restored.
  timeout 100 systemctl stop "$UNIT" >/dev/null 2>&1 || failed=1
  if [[ -d "$old_api" && ! -L "$old_api" ]]; then
    if [[ -e "$API_DIR" ]]; then mv -- "$API_DIR" "$failed_api" || failed=1; fi
    if [[ ! -e "$API_DIR" ]]; then mv -- "$old_api" "$API_DIR" || failed=1; else failed=1; fi
  fi
  cmp -s -- "$recovery/Caddyfile.previous" "$CADDYFILE" || caddy_changed=1
  restore_assets || failed=1
  if timeout 30 caddy validate --config "$CADDYFILE" --adapter caddyfile >/dev/null 2>&1; then
    if (( caddy_changed )); then
      if systemctl is-active --quiet caddy.service; then timeout 45 systemctl reload caddy >/dev/null 2>&1 || failed=1;
      else timeout 100 systemctl start caddy.service >/dev/null 2>&1 || failed=1; fi
    fi
    python3 "$SAFETY" caddy-config "$CADDYFILE" >/dev/null 2>&1 || failed=1
  else failed=1; fi
  timeout 100 systemctl start "$UNIT" >/dev/null 2>&1 || failed=1
  probe_api || failed=1
  if (( failed )); then note 'RECOVERY INCOMPLETE: API restart attempted; retained files require console diagnosis. Database was not rewound.' >&2;
  else note 'Previous API/config/static restored and health passed. Database was not rewound.' >&2; fi
  return "$failed"
}

exit_release() {
  local rc=$1
  trap - EXIT INT TERM HUP
  set +e
  if ! cleanup_fixture; then
    note 'Fixture cleanup failed; inspect the retained fixture name before any retry.' >&2
    (( rc != 0 )) || rc=1
  fi
  if (( rc != 0 )) && [[ ${service_stopped:-0} == 1 || ${release_swapped:-0} == 1 ]]; then
    recover_transaction || true
  fi
  exit "$rc"
}

snapshot_assets() {
  local destination=$1 n p
  cp -a "$CONFIG" "$destination/api.json.previous"
  cp -a "$CADDYFILE" "$destination/Caddyfile.previous"
  sha256sum "$destination/Caddyfile.previous" | awk '{print $1}' > "$destination/Caddyfile.previous.sha256"
  for n in windows-x64 android-arm64; do
    p="$static_root/updates/stable/$n.json"
    [[ ! -L $p && ( ! -e $p || -f $p ) ]] || die 'existing feed is not a regular file'
    if [[ -f $p ]]; then cp -a "$p" "$destination/$n.json.previous"; else : > "$destination/$n.json.absent"; fi
  done
  p="$DIST/mayak-agent"
  [[ ! -L $p && ( ! -e $p || -f $p ) ]] || die 'existing agent is not a regular file'
  if [[ -f $p ]]; then cp -a "$p" "$destination/agent.previous"; else : > "$destination/agent.absent"; fi
  chown root:root "$destination"/*
  chmod 0600 "$destination"/*
}
# END TRANSACTION HELPERS

ACTION= BUNDLE= EXPECTED_SHA= CONFIRM=0 QUIET_WINDOW=0 ROLLBACK_ID=
while (($#)); do
  case "$1" in
    --inspect|--inspect-target|--apply) [[ -z "$ACTION" ]] || die 'choose one action'; ACTION=${1#--}; shift ;;
    --bundle) (($# >= 2)) || die '--bundle needs a path'; BUNDLE=$2; shift 2 ;;
    --sha256) (($# >= 2)) || die '--sha256 needs a value'; EXPECTED_SHA=$2; shift 2 ;;
    --confirm-api-only) CONFIRM=1; shift ;;
    --confirm-write-window) QUIET_WINDOW=1; shift ;;
    --rollback) (($# >= 2)) || die '--rollback needs a release id'; ACTION=rollback; ROLLBACK_ID=$2; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die 'unknown argument';;
  esac
done
[[ -n "$ACTION" ]] || { usage >&2; exit 2; }
[[ $EUID -eq 0 ]] || die 'run from the Timeweb console as root (sudo -i), after reading the exact command'
[[ -f "$SAFETY" && ! -L "$SAFETY" ]] || die 'release_safety.py is missing beside the entry script'

check_caddy_unit() {
  local caddy_fragment caddy_dropins caddy_envfiles caddy_user caddy_group
  caddy_user=$(systemctl show -p User --value caddy.service)
  caddy_group=$(systemctl show -p Group --value caddy.service)
  caddy_fragment=$(systemctl show -p FragmentPath --value caddy.service)
  caddy_dropins=$(systemctl show -p DropInPaths --value caddy.service)
  caddy_envfiles=$(systemctl show -p EnvironmentFiles --value caddy.service)
  python3 - <<'PY' || die 'effective Caddy ExecStart differs from supported config invocation'
import re,subprocess
try:
 raw=subprocess.check_output(['systemctl','show','-p','ExecStart','--value','caddy.service'],stderr=subprocess.DEVNULL,text=True).strip()
 m=re.fullmatch(r'\{\s*path=([^;{}]+?)\s*;\s*argv\[\]=([^;{}]+?)\s*;\s*ignore_errors=no\s*;[^{}]*\}',raw,re.S)
 if m is None: raise SystemExit(1)
 args=m.group(2).split()
except (OSError,ValueError,subprocess.SubprocessError): raise SystemExit(1)
if args != ['/usr/bin/caddy','run','--environ','--config','/etc/caddy/Caddyfile']: raise SystemExit(1)
if m.group(1) != args[0]: raise SystemExit(1)
PY
  [[ $caddy_user == caddy && $caddy_group == caddy && $caddy_fragment == /usr/lib/systemd/system/caddy.service && -z $caddy_dropins && -z $caddy_envfiles ]] || die 'Caddy unit source/drop-ins/environment files are unsupported'
}

check_target() {
  [[ -r /etc/os-release ]] || die 'cannot identify Linux distribution'
  # Only known Ubuntu LTS targets are supported in this first procedure.
  . /etc/os-release
  [[ ${ID:-} == ubuntu && ( ${VERSION_ID:-} == 22.04 || ${VERSION_ID:-} == 24.04 ) ]] || die 'unsupported OS; expected Ubuntu 22.04 or 24.04'
  [[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || die 'unsupported runtime platform; expected Linux x86_64'
  command -v systemctl >/dev/null || die 'systemd not found'
  command -v dotnet >/dev/null || die '.NET runtime missing'
  command -v python3 >/dev/null || die 'python3 missing'
  command -v pg_dump >/dev/null && command -v pg_restore >/dev/null && command -v psql >/dev/null && command -v pg_isready >/dev/null && command -v createdb >/dev/null && command -v dropdb >/dev/null || die 'PostgreSQL client tools missing'
  command -v caddy >/dev/null && command -v curl >/dev/null && command -v openssl >/dev/null || die 'Caddy/curl/OpenSSL missing'
  command -v setsid >/dev/null && command -v runuser >/dev/null && command -v timeout >/dev/null || die 'setsid/runuser/timeout missing'
  systemctl is-active --quiet "$UNIT" || die 'mayak-api.service is not active'
  systemctl is-active --quiet caddy.service || die 'Caddy is not active'
  runuser -u postgres -- pg_isready --host=/var/run/postgresql --port=5432 --username=postgres --quiet || die 'local PostgreSQL is not accepting connections'
  for p in /opt /opt/mayak /opt/mayak/api /opt/mayak/releases /etc /etc/mayak /etc/caddy /var /var/backups /var/backups/mayak-release; do [[ ! -L "$p" ]] || die 'an expected target path has a symlinked ancestor'; done
  runuser -u caddy -- test -x /opt/mayak || die 'Caddy cannot traverse /opt/mayak'
  for p in /opt/mayak/static /opt/mayak/static/updates /opt/mayak/static/updates/packages /opt/mayak/static/updates/stable; do
    [[ ! -L "$p" ]] || die 'static update path contains a symlink'
    [[ ! -e "$p" || -d "$p" ]] || die 'static update path contains a non-directory component'
  done
  [[ -d "$API_DIR" && ! -L "$API_DIR" && -f "$API_DIR/mayak-api.dll" && -f "$CONFIG" && ! -L "$CONFIG" && -f "$GATEWAY_KEY" && ! -L "$GATEWAY_KEY" && -d "$DIST" && ! -L "$DIST" ]] || die 'expected Mayak API paths are incomplete or symlinked'
  [[ -f "$CADDYFILE" && ! -L "$CADDYFILE" ]] || die 'Caddyfile not found at supported path or is symlinked'
  [[ $(stat -c '%U:%G:%a' "$CADDYFILE") == root:root:644 ]] || die 'Caddyfile owner/mode differs from observed baseline'
  for p in /opt /opt/mayak "$API_DIR" "$DIST" /etc/mayak /etc/caddy /var/backups; do
    [[ $(stat -c '%u' "$p") == 0 ]] && (( (8#$(stat -c '%a' "$p") & 0022) == 0 )) || die 'a deployment directory is writable by a non-root account'
  done
  local unsafe_api
  unsafe_api=$(find "$API_DIR" \( ! -type d ! -type f -o ! -user root -o -perm /022 \) -print -quit 2>/dev/null) || die 'API tree permissions could not be inspected'
  [[ -z $unsafe_api ]] || die 'existing API tree has unsupported links/types/ownership/write permissions'
  id mayak >/dev/null 2>&1 && id caddy >/dev/null 2>&1 || die 'expected Mayak/Caddy accounts missing'
  local user group workdir fragment dropins envfiles runtimes fingerprint
  user=$(systemctl show -p User --value "$UNIT")
  group=$(systemctl show -p Group --value "$UNIT")
  workdir=$(systemctl show -p WorkingDirectory --value "$UNIT")
  fragment=$(systemctl show -p FragmentPath --value "$UNIT")
  dropins=$(systemctl show -p DropInPaths --value "$UNIT")
  envfiles=$(systemctl show -p EnvironmentFiles --value "$UNIT")
  [[ $user == mayak && -z $group && $workdir == "$API_DIR" ]] || die 'service identity or working directory differs from supported layout'
  python3 - <<'PY' || die 'effective API ExecStart arguments or Environment differ from supported layout'
import re,shlex,subprocess
def effective(prop):
    return subprocess.check_output(['systemctl','show','-p',prop,'--value','mayak-api.service'],stderr=subprocess.DEVNULL,text=True).strip()
try:
    raw=effective('ExecStart')
    env=effective('Environment')
except (OSError,ValueError,subprocess.SubprocessError): raise SystemExit(1)
try:
    cmd=re.fullmatch(r'\{\s*path=([^;{}]+?)\s*;\s*argv\[\]=([^;{}]+?)\s*;\s*ignore_errors=no\s*;[^{}]*\}',raw,re.S)
    if cmd is None: raise SystemExit(1)
    args=cmd.group(2).split()
    values=shlex.split(env)
except (IndexError,ValueError): raise SystemExit(1)
if args != ['/usr/bin/dotnet','/opt/mayak/api/mayak-api.dll']: raise SystemExit(1)
if cmd.group(1) != args[0]: raise SystemExit(1)
expected={'HOME=/var/lib/mayak','DOTNET_CLI_TELEMETRY_OPTOUT=1','MAYAK_DistDir=/opt/mayak/dist'}
if len(values)!=len(expected) or set(values)!=expected: raise SystemExit(1)
PY
  [[ $fragment == /etc/systemd/system/mayak-api.service && -z $dropins && -z $envfiles ]] || die 'unit file source/drop-ins/environment files differ from supported layout'
  check_caddy_unit
  runuser -u caddy -- test -x /opt/mayak || die 'Caddy cannot traverse /opt/mayak'
  for p in /opt/mayak/static /opt/mayak/static/updates /opt/mayak/static/updates/packages /opt/mayak/static/updates/stable; do
    if [[ -e $p ]]; then [[ -d $p && ! -L $p && $(stat -c '%U:%G' "$p") == root:caddy && $(stat -c '%a' "$p") == 750 ]] || die 'existing static-update directory has unsupported owner/mode/type'; fi
  done
  runtimes=$(dotnet --list-runtimes 2>/dev/null | awk '$1=="Microsoft.NETCore.App" && $2 ~ /^10\./ {found=1} END {print found+0}')
  [[ $runtimes == 1 ]] || die '.NET 10 runtime missing'
  [[ -r "$CONFIG" && -r "$GATEWAY_KEY" && -r "$API_DIR/mayak-api.dll" ]] || die 'required file unreadable by root'
  [[ $(stat -c '%U:%G' "$CONFIG") == root:mayak && $(stat -c '%a' "$CONFIG") =~ ^(600|640)$ ]] || die 'API config owner/mode differs from supported secure baseline'
  [[ $(stat -c '%U:%G' "$GATEWAY_KEY") == root:mayak && $(stat -c '%a' "$GATEWAY_KEY") =~ ^(600|640)$ ]] || die 'gateway private-key owner/mode differs from supported secure baseline'
  runuser -u mayak -- test -r "$CONFIG" && runuser -u mayak -- test -r "$GATEWAY_KEY" && runuser -u mayak -- test -r "$API_DIR/mayak-api.dll" || die 'service account cannot read required files'
  fingerprint=$(openssl pkey -passin pass: -in "$GATEWAY_KEY" -pubout -outform DER 2>/dev/null | openssl dgst -sha256 -r | awk '{print toupper($1)}') || die 'gateway public key is not parseable'
  [[ $fingerprint == "$EXPECTED_GATEWAY_SPKI" ]] || die 'gateway public key fingerprint differs from approved pin'
  python3 "$SAFETY" caddy-hash "$CADDYFILE" "$EXPECTED_CADDY_SHA256" || die 'Caddyfile differs from the observed preserved overlay snapshot'
  python3 "$SAFETY" caddy-config "$CADDYFILE" || die 'loaded Caddy config differs from the supported on-disk adaptation or logging policy is unverified'
  curl --noproxy '*' --fail --silent --max-time 4 "$HEALTH_URL" >/dev/null || die 'local API health check failed'
  [[ $(df -Pk /opt /var/backups 2>/dev/null | awk 'NR>1 {s+=$4} END {print s+0}') -gt 1048576 ]] || die 'less than 1 GiB free in release/backup filesystems'
}

# Rollback must work after the new layout has already been installed or the
# API has failed to start; it deliberately does not require the old Caddy
# shape or an active mayak-api process.
check_rollback_target() {
  [[ -r /etc/os-release ]] || die 'rollback OS unknown'
  . /etc/os-release
  [[ ${ID:-} == ubuntu && ( ${VERSION_ID:-} == 22.04 || ${VERSION_ID:-} == 24.04 ) ]] || die 'unsupported rollback OS'
  [[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || die 'unsupported rollback runtime platform'
  for tool in systemctl caddy curl openssl dotnet python3 runuser setsid timeout pg_dump pg_restore psql createdb dropdb; do command -v "$tool" >/dev/null || die 'required rollback tool missing'; done
  check_caddy_unit
  [[ $(dotnet --list-runtimes | awk '$1=="Microsoft.NETCore.App" && $2 ~ /^10\./ {n++} END {print n+0}') == 1 ]] || die 'rollback .NET10 runtime unavailable'
  [[ -d "$RELEASES" && ! -L "$RELEASES" && $(stat -c '%U:%G' "$RELEASES") == root:mayak && $(stat -c '%a' "$RELEASES") == 750 ]] || die 'rollback releases directory owner/mode unknown'
  [[ -d "$BACKUPS" && ! -L "$BACKUPS" && $(stat -c '%U:%G' "$BACKUPS") == root:root && $(stat -c '%a' "$BACKUPS") == 700 ]] || die 'rollback backup directory owner/mode unknown'
  runuser -u mayak -- test -r "$CONFIG" && runuser -u mayak -- test -r "$GATEWAY_KEY" || die 'rollback service account cannot read config/key'
  local pin
  pin=$(openssl pkey -passin pass: -in "$GATEWAY_KEY" -pubout -outform DER 2>/dev/null | openssl dgst -sha256 -r | awk '{print toupper($1)}') || die 'rollback gateway key is unreadable'
  [[ $pin == "$EXPECTED_GATEWAY_SPKI" ]] || die 'rollback gateway pin differs from approved pin' 
  for p in /opt /opt/mayak /opt/mayak/releases /opt/mayak/api /opt/mayak/dist /opt/mayak/static /opt/mayak/static/updates /opt/mayak/static/updates/stable /var /var/backups /var/backups/mayak-release /etc /etc/mayak /etc/caddy; do [[ ! -L "$p" ]] || die 'rollback path has symlinked ancestor'; done
  for p in /opt /opt/mayak "$API_DIR" "$DIST" /etc/mayak /etc/caddy /var/backups; do
    [[ $(stat -c '%u' "$p") == 0 ]] && (( (8#$(stat -c '%a' "$p") & 0022) == 0 )) || die 'rollback deployment directory is writable by a non-root account'
  done
  [[ $(stat -c '%U:%G:%a' "$CONFIG") == root:mayak:640 && $(stat -c '%U:%G:%a' "$GATEWAY_KEY") == root:mayak:640 && $(stat -c '%U:%G:%a' "$CADDYFILE") == root:root:644 ]] || die 'rollback protected config/key/Caddy owner/mode differs from supported baseline'
  [[ -f /etc/systemd/system/mayak-api.service && ( -d "$API_DIR" && ! -L "$API_DIR" ) && -f "$CONFIG" && ! -L "$CONFIG" && -f "$CADDYFILE" && ! -L "$CADDYFILE" ]] || die 'rollback target paths differ from supported layout'
  user=$(systemctl show -p User --value "$UNIT")
  group=$(systemctl show -p Group --value "$UNIT")
  workdir=$(systemctl show -p WorkingDirectory --value "$UNIT")
  fragment=$(systemctl show -p FragmentPath --value "$UNIT")
  dropins=$(systemctl show -p DropInPaths --value "$UNIT")
  envfiles=$(systemctl show -p EnvironmentFiles --value "$UNIT")
  [[ $user == mayak && -z $group && $workdir == "$API_DIR" && $fragment == /etc/systemd/system/mayak-api.service && -z $dropins && -z $envfiles ]] || die 'rollback service identity/config source is unknown'
  python3 - <<'PY' || die 'rollback API ExecStart/Environment differs from supported service'
import re,shlex,subprocess
def get(p): return subprocess.check_output(['systemctl','show','-p',p,'--value','mayak-api.service'],stderr=subprocess.DEVNULL,text=True).strip()
try:
    raw=get('ExecStart'); env=get('Environment')
    m=re.fullmatch(r'\{\s*path=([^;{}]+?)\s*;\s*argv\[\]=([^;{}]+?)\s*;\s*ignore_errors=no\s*;[^{}]*\}',raw,re.S)
    if m is None: raise SystemExit(1)
    args=m.group(2).split(); values=shlex.split(env)
except (OSError,ValueError,subprocess.SubprocessError): raise SystemExit(1)
if args != ['/usr/bin/dotnet','/opt/mayak/api/mayak-api.dll'] or m.group(1)!=args[0]: raise SystemExit(1)
expected={'HOME=/var/lib/mayak','DOTNET_CLI_TELEMETRY_OPTOUT=1','MAYAK_DistDir=/opt/mayak/dist'}
if len(values)!=len(expected) or set(values)!=expected: raise SystemExit(1)
PY
}

verify_and_stage() {
  [[ -f "$BUNDLE" && ! -L "$BUNDLE" ]] || die 'bundle must be a regular non-symlink file'
  [[ $EXPECTED_SHA =~ ^[a-fA-F0-9]{64}$ ]] || die 'exact 64-digit bundle SHA-256 is required'
  local actual
  actual=$(sha256sum -- "$BUNDLE" | awk '{print $1}')
  [[ ${actual,,} == ${EXPECTED_SHA,,} ]] || die 'bundle SHA-256 mismatch'
  local parsed
  [[ -f "$SCRIPT_DIR/verify_bundle.py" && ! -L "$SCRIPT_DIR/verify_bundle.py" ]] || die 'bundle verifier is missing beside the entry script'
  parsed=$(python3 "$SCRIPT_DIR/verify_bundle.py" "$BUNDLE" --expected-sha "$EXPECTED_SHA") || die 'bundle validation failed'
  local release_id
  release_id=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["releaseId"])' "$parsed")
  [[ $release_id =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]{2,63}$ ]] || die 'unsafe release id in bundle manifest'
  STAGE="$RELEASES/$release_id"
  [[ ! -e $STAGE ]] || die 'release staging path already exists; refusing to overwrite'
  mkdir -p "$STAGE"
  chown root:mayak "$STAGE"
  chmod 0750 "$STAGE"
  python3 "$SCRIPT_DIR/verify_bundle.py" "$BUNDLE" --expected-sha "$EXPECTED_SHA" --extract "$STAGE" >/dev/null || die 'safe extraction failed'
  cmp -s -- "$SCRIPT_DIR/release-entry.sh" "$STAGE/control/release-entry.sh" || die 'bootstrap entry script differs from SHA-verified bundle'
  cmp -s -- "$SCRIPT_DIR/inspect-target.sh" "$STAGE/control/inspect-target.sh" || die 'bootstrap inspector differs from SHA-verified bundle'
  cmp -s -- "$SCRIPT_DIR/verify_bundle.py" "$STAGE/control/verify_bundle.py" || die 'bootstrap verifier differs from SHA-verified bundle'
  cmp -s -- "$SAFETY" "$STAGE/control/release_safety.py" || die 'bootstrap safety helper differs from SHA-verified bundle'
  chown -R root:mayak "$STAGE"
  find "$STAGE" -type d -exec chmod 0750 {} +
  find "$STAGE" -type f -exec chmod 0640 {} +
  chmod 0750 "$STAGE/dist/mayak-agent"
  runuser -u mayak -- test -r "$STAGE/api/mayak-api.dll" || die 'service user cannot read staged API'
  printf '%s\n' "$release_id"
}

verify_bootstrap_matches_bundle() {
  python3 - "$BUNDLE" "$SCRIPT_DIR/release-entry.sh" "$SCRIPT_DIR/inspect-target.sh" "$SCRIPT_DIR/verify_bundle.py" "$SAFETY" <<'PY'
import pathlib,sys,tarfile
archive=pathlib.Path(sys.argv[1])
try:
    with tarfile.open(archive,'r:gz') as t:
        for member,path in zip(('control/release-entry.sh','control/inspect-target.sh','control/verify_bundle.py','control/release_safety.py'),sys.argv[2:]):
            with pathlib.Path(path).open('rb') as local:
                packaged=t.extractfile(member)
                if packaged is None or packaged.read()!=local.read(): raise SystemExit(1)
except (OSError,tarfile.TarError): raise SystemExit(1)
PY
}

read_local_database_name() {
  python3 "$SAFETY" database "$CONFIG"
}

verify_database_identity() {
  local metadata
  metadata=$(runuser -u postgres -- psql -X -A -t -v ON_ERROR_STOP=1 --host=/var/run/postgresql --port=5432 --username=postgres --no-password --dbname="$1" -c "SELECT current_setting('port') || ':' || pg_get_userbyid(datdba) FROM pg_database WHERE datname=current_database()" 2>/dev/null) || die 'local database identity/owner check is unavailable'
  [[ $metadata == 5432:mayak ]] || die 'configured database port/owner differs from supported local mayak cluster'
  python3 "$SAFETY" database-identity "$CONFIG" || die 'API PostgreSQL endpoint/auth does not match the inspected local cluster; database snapshot is blocked'
}

check_disk_requirement() {
  local bundle_bytes=$1 db_name=$2 db_bytes api_bytes total_need_kb free_kb
  verify_database_identity "$db_name"
  db_bytes=$(runuser -u postgres -- psql -X -A -t -v ON_ERROR_STOP=1 --host=/var/run/postgresql --port=5432 --username=postgres --no-password --dbname="$db_name" -c 'SELECT pg_database_size(current_database())' 2>/dev/null) || die 'configured PostgreSQL database is not reachable by the local postgres role'
  [[ $db_bytes =~ ^[0-9]+$ ]] || die 'could not determine database size safely'
  api_bytes=$(du -sk -- "$API_DIR" | awk '{print $1*1024}')
  [[ $api_bytes =~ ^[0-9]+$ ]] || die 'could not determine current API snapshot size'
  total_need_kb=$(( 1048576 + (3 * bundle_bytes + 3 * db_bytes + 2 * api_bytes + 1023) / 1024 ))
  free_kb=$(df -Pk /opt /var/backups "$DIST" | awk 'NR>1 {if ($4<m || m==0) m=$4} END {print m+0}')
  (( free_kb >= total_need_kb )) || die 'available disk space is below the conservative staging/snapshot requirement'
}

compare_database_counts() {
  python3 - "$1" "$2" <<'PY'
import csv,subprocess,sys
def psql(db,sql):
    return subprocess.check_output(['runuser','-u','postgres','--','psql','-X','-A','-t','-v','ON_ERROR_STOP=1','--host=/var/run/postgresql','--port=5432','--username=postgres','--no-password','--dbname='+db,'-c',sql],stderr=subprocess.DEVNULL,text=True).strip()
def counts(db):
    rows=psql(db,"SELECT schemaname || chr(9) || tablename FROM pg_tables WHERE schemaname NOT IN ('pg_catalog','information_schema') ORDER BY 1").splitlines()
    out={}
    for line in rows:
        schema,table=line.split('\t',1)
        ident='"'+schema.replace('"','""')+'"."'+table.replace('"','""')+'"'
        out[(schema,table)]=int(psql(db,'SELECT count(*) FROM '+ident))
    return out
try:
    if counts(sys.argv[1]) != counts(sys.argv[2]): raise SystemExit(1)
except (OSError,ValueError,subprocess.SubprocessError): raise SystemExit(1)
PY
}

candidate_check() {
  local candidate_api=$1 snapshot_dump=$2 candidate_url candidate_port endpoint_text fixture_ok old_api_check
  fixture="mayak_restore_check_$(date +%s)_$$"
  [[ $fixture =~ ^[a-zA-Z0-9_]+$ ]] || die 'internal fixture DB name invalid'
  candidate_pid=
runuser -u postgres -- createdb --host=/var/run/postgresql --port=5432 --username=postgres --no-password --template=template0 --owner=mayak "$fixture" || die 'could not create isolated restore fixture; API remains running'
runuser -u postgres -- pg_restore --exit-on-error --host=/var/run/postgresql --port=5432 --username=postgres --no-password --dbname="$fixture" --role=mayak --no-owner --no-acl <"$snapshot_dump" >/dev/null 2>&1 || die 'isolated PostgreSQL restore check failed; API remains running'
compare_database_counts "$db_name" "$fixture" || die 'production snapshot and isolated restore table/row counts differ; API remains running'
fixture_root="/run/mayak-release-$release_id"
mkdir -m 0700 "$fixture_root"
python3 "$SAFETY" fixture-snapshot "$fixture" "$fixture_root/schema-before.json" || die 'restored DB has unknown schema, interrupted jobs, or unsupported migration history; API remains running'
candidate_port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
candidate_url="http://127.0.0.1:$candidate_port"
endpoint_text=$(python3 "$SAFETY" candidate-endpoint "$CONFIG") || die 'unsupported Kestrel endpoint configuration; API remains available'
endpoint_names=()
if [[ -n $endpoint_text ]]; then mapfile -t endpoint_names <<<"$endpoint_text"; fi
candidate_env=("MAYAK_ConnectionStrings__Db=Host=/var/run/postgresql;Port=5432;Database=$fixture;Username=mayak" "MAYAK_Telegram__Polling=false" "MAYAK_DistDir=$DIST" "MAYAK_Gateway__PrivateKeyPath=$fixture_root/no-key-in-fixture" "ASPNETCORE_URLS=$candidate_url" "MAYAK_Urls=$candidate_url")
if ((${#endpoint_names[@]})); then candidate_env+=("MAYAK_Kestrel__Endpoints__${endpoint_names[0]}__Url=$candidate_url"); fi
setsid runuser -u mayak -- env "${candidate_env[@]}" sh -c 'cd "$1" && exec dotnet ./mayak-api.dll --urls "$2"' _ "$candidate_api" "$candidate_url" >"$fixture_root/candidate.log" 2>&1 &
candidate_pid=$!
fixture_ok=0
for _ in {1..30}; do if kill -0 "$candidate_pid" 2>/dev/null && curl --noproxy '*' --fail --silent --max-time 2 "$candidate_url/health" >/dev/null 2>&1; then fixture_ok=1; break; fi; sleep 2; done
  stop_candidate || die 'candidate process teardown failed; API remains available'
[[ $fixture_ok == 1 ]] || die 'candidate API restore-fixture health probe failed; root-only log retained for diagnosis'
python3 "$SAFETY" fixture-verify "$fixture" "$fixture_root/schema-before.json" || die 'candidate migration changed existing fixture data or did not apply the exact additive schema; API remains running'

# Prove rollback compatibility by starting the currently installed API against
# the migrated fixture. It must boot without reversing or changing migrations.
if [[ $(readlink -f -- "$candidate_api") != $(readlink -f -- "$API_DIR") ]]; then
  old_api_check="$API_DIR"
  candidate_port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
  candidate_url="http://127.0.0.1:$candidate_port"
  candidate_env[0]="MAYAK_ConnectionStrings__Db=Host=/var/run/postgresql;Port=5432;Database=$fixture;Username=mayak"
  candidate_env[4]="ASPNETCORE_URLS=$candidate_url"
  candidate_env[5]="MAYAK_Urls=$candidate_url"
  if ((${#endpoint_names[@]})); then candidate_env[6]="MAYAK_Kestrel__Endpoints__${endpoint_names[0]}__Url=$candidate_url"; fi
  setsid runuser -u mayak -- env "${candidate_env[@]}" sh -c 'cd "$1" && exec dotnet ./mayak-api.dll --urls "$2"' _ "$old_api_check" "$candidate_url" >"$fixture_root/rollback-compat.log" 2>&1 &
  candidate_pid=$!
  fixture_ok=0
  for _ in {1..30}; do if kill -0 "$candidate_pid" 2>/dev/null && curl --noproxy '*' --fail --silent --max-time 2 "$candidate_url/health" >/dev/null 2>&1; then fixture_ok=1; break; fi; sleep 2; done
  stop_candidate || die 'rollback compatibility process teardown failed; API remains available'
  [[ $fixture_ok == 1 ]] || die 'currently installed API cannot boot against the migrated fixture; API remains running'
  python3 "$SAFETY" fixture-verify "$fixture" "$fixture_root/schema-before.json" || die 'old API changed migrated schema/data; API remains running'
fi

# Keep the restored clone alive through both API boots and schema checks.
# Cleanup is the final candidate_check phase; the EXIT trap retries it on errors.
cleanup_fixture || die 'candidate fixture cleanup failed; API remains available'

}

if [[ $ACTION == inspect ]]; then
  [[ -n $BUNDLE && -n $EXPECTED_SHA ]] || die '--inspect requires --bundle and --sha256'
  check_target
  [[ $(dotnet --list-runtimes | awk '$1=="Microsoft.NETCore.App" && $2 ~ /^10\./ {n++} END {print n+0}') == 1 ]] || die '.NET10 unavailable'
  actual=$(sha256sum -- "$BUNDLE" | awk '{print $1}')
  [[ ${actual,,} == ${EXPECTED_SHA,,} ]] || die 'bundle SHA-256 mismatch'
  [[ -f "$SCRIPT_DIR/verify_bundle.py" && ! -L "$SCRIPT_DIR/verify_bundle.py" ]] || die 'bundle verifier is missing beside the entry script'
  summary=$(python3 "$SCRIPT_DIR/verify_bundle.py" "$BUNDLE" --expected-sha "$EXPECTED_SHA") || die 'archive allowlist/manifest/hash validation failed'
  verify_bootstrap_matches_bundle || die 'local bootstrap scripts differ from SHA-verified bundle'
  db_name=$(read_local_database_name) || die 'unsupported/unparseable local PostgreSQL settings'
  bundle_bytes=$(python3 -c 'import json,sys; print(int(json.loads(sys.argv[1])["bytes"]))' "$summary")
  check_disk_requirement "$bundle_bytes" "$db_name"
  note "INSPECT OK: Ubuntu LTS, .NET 8, expected API service identity, key pin, supported Caddy baseline, tools and free space. Bundle SHA-256 matches. $summary"
  note 'No production files or services were changed. This verifies local target facts only; database restore fixture and HTTPS canary still run in --apply stage before switch.'
  exit 0
fi

if [[ $ACTION == inspect-target ]]; then
  [[ -f "$SCRIPT_DIR/inspect-target.sh" && ! -L "$SCRIPT_DIR/inspect-target.sh" ]] || die 'standalone read-only target inspector missing'
  exec bash "$SCRIPT_DIR/inspect-target.sh"
fi

if [[ $ACTION == rollback ]]; then
  [[ $ROLLBACK_ID =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]{2,63}$ ]] || die 'unsafe rollback id'
  check_rollback_target
  python3 "$SAFETY" caddy-config "$CADDYFILE" || die 'current loaded Caddy config differs from its on-disk bytes'
  dir="$BACKUPS/$ROLLBACK_ID"
  [[ -d $dir && ! -L $dir && $(stat -c '%U:%G' "$dir") == root:root && $(stat -c '%a' "$dir") == 700 ]] || die 'retained rollback directory owner/mode unknown'
  for p in api.previous.tar.gz api.previous.tar.gz.sha256 api.json.previous Caddyfile.previous Caddyfile.previous.sha256; do
    [[ -f "$dir/$p" && ! -L "$dir/$p" && $(stat -c '%U:%G' "$dir/$p") == root:root && $(stat -c '%a' "$dir/$p") == 600 ]] || die 'rollback snapshot/hash record incomplete; use the exact previous reviewed controller for historical receipts'
  done
  for n in windows-x64 android-arm64 agent; do
    previous="$dir/$n.previous"; absent="$dir/$n.absent"
    if [[ $n != agent ]]; then previous="$dir/$n.json.previous"; absent="$dir/$n.json.absent"; fi
    [[ ! -L $previous && ! -L $absent && ( ( -f $previous && ! -e $absent ) || ( ! -e $previous && -f $absent ) ) ]] || die 'rollback feed/agent snapshot is incomplete'
  done
  # No config compatibility guess: this procedure never changes API config.
  cmp -s "$dir/api.json.previous" "$CONFIG" || die 'rollback API config differs; requires a separately reviewed compatibility procedure'
  saved_caddy_hash=$(cat "$dir/Caddyfile.previous.sha256")
  python3 "$SAFETY" caddy-hash "$dir/Caddyfile.previous" "$saved_caddy_hash" || die 'retained Caddy snapshot hash mismatch; historical snapshots require their previous reviewed controller'
  python3 "$SAFETY" caddy-baseline "$dir/Caddyfile.previous" || die 'retained Caddy config is unsupported'
  caddy validate --config "$dir/Caddyfile.previous" --adapter caddyfile >/dev/null 2>&1 || die 'retained Caddy config is invalid; API remains available'
  saved_api_hash=$(cat "$dir/api.previous.tar.gz.sha256")
  [[ $saved_api_hash =~ ^[a-f0-9]{64}$ && $(sha256sum "$dir/api.previous.tar.gz" | awk '{print $1}') == "$saved_api_hash" ]] || die 'retained API snapshot hash mismatch; historical snapshots require their previous reviewed controller'
  db_name=$(read_local_database_name) || die 'rollback database identity cannot be verified'
  check_disk_requirement 0 "$db_name"
  release_id="rollback-$ROLLBACK_ID-$(date +%s)-$$"
  restore_api="$RELEASES/restore-$release_id"
  recovery="$BACKUPS/$release_id"
  old_api="$RELEASES/current-$release_id"
  failed_api="$RELEASES/failed-$release_id"
  static_root=/opt/mayak/static
  for p in "$restore_api" "$recovery" "$old_api" "$failed_api"; do [[ ! -e $p && ! -L $p ]] || die 'rollback staging path exists'; done
  mkdir -m 0700 "$recovery"
  snapshot_assets "$recovery"
  service_stopped=0; release_swapped=0
  trap 'exit_release "$?"' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM HUP
  [[ $(sha256sum "$dir/api.previous.tar.gz" | awk '{print $1}') == "$saved_api_hash" ]] || die 'retained API snapshot changed after hash recording'
  python3 "$SAFETY" extract-snapshot "$dir/api.previous.tar.gz" "$restore_api" || die 'retained API snapshot is corrupt/unsafe; API was not stopped'
  python3 "$SAFETY" overlay-hashes "$restore_api" || die 'retained API snapshot does not contain the observed preserved HTML overlays'
  chown -R root:mayak "$restore_api"
  find "$restore_api" -type d -exec chmod 0750 {} +
  find "$restore_api" -type f -exec chmod 0640 {} +
  runuser -u mayak -- test -r "$restore_api/mayak-api.dll" || die 'rollback candidate is unreadable; API was not stopped'
  timeout 300 runuser -u postgres -- pg_dump --host=/var/run/postgresql --port=5432 --username=postgres --no-password --format=custom --no-owner --no-acl --dbname="$db_name" >"$recovery/database.initial.dump" 2>/dev/null || die 'rollback smoke snapshot failed; API was not stopped'
  chmod 0600 "$recovery/database.initial.dump"
  candidate_check "$restore_api" "$recovery/database.initial.dump"
  service_stopped=1
  timeout 100 systemctl stop "$UNIT"
  mv -- "$API_DIR" "$old_api"
  mv -- "$restore_api" "$API_DIR"
  release_swapped=1
  # Restore selected assets; on any error the EXIT handler restores recovery.
  caddy_changed=0
  cmp -s -- "$dir/Caddyfile.previous" "$CADDYFILE" || caddy_changed=1
  restore_assets "$dir" || die 'selected rollback assets could not be installed; returning to pre-rollback API'
  python3 "$SAFETY" caddy-hash "$CADDYFILE" "$saved_caddy_hash" || die 'installed rollback Caddy bytes differ from the recorded snapshot hash'
  if (( caddy_changed )); then timeout 45 systemctl reload caddy || die 'rollback Caddy reload failed; returning to pre-rollback API'; fi
  python3 "$SAFETY" caddy-config "$CADDYFILE" || die 'rollback loaded Caddy config could not be verified'
  timeout 100 systemctl start "$UNIT"
  probe_api || die 'rollback health failed; returning to pre-rollback API'
  service_stopped=0; release_swapped=0
  trap - EXIT INT TERM HUP
  note 'API rollback restored and health passed. Database was not rewound; additive schema and later writes remain.'
  exit 0
fi

[[ $ACTION == apply && $CONFIRM == 1 && $QUIET_WINDOW == 1 ]] || die '--apply requires --confirm-api-only and --confirm-write-window'
[[ -n $BUNDLE && -n $EXPECTED_SHA ]] || die '--apply requires --bundle and --sha256'
check_target
[[ -f "$BUNDLE" && ! -L "$BUNDLE" && $EXPECTED_SHA =~ ^[a-fA-F0-9]{64}$ ]] || die 'bundle path/SHA precondition failed'
python3 "$SCRIPT_DIR/verify_bundle.py" "$BUNDLE" --expected-sha "$EXPECTED_SHA" >/dev/null || die 'bundle allowlist/manifest/hash validation failed; no target writes performed'
verify_bootstrap_matches_bundle || die 'local bootstrap scripts differ from SHA-verified bundle; no target writes performed'
bundle_summary=$(python3 "$SCRIPT_DIR/verify_bundle.py" "$BUNDLE" --expected-sha "$EXPECTED_SHA") || die 'bundle manifest cannot be read'
release_id=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["releaseId"])' "$bundle_summary")
bundle_bytes=$(python3 -c 'import json,sys; print(int(json.loads(sys.argv[1])["bytes"]))' "$bundle_summary")
db_name=$(read_local_database_name) || die 'unsupported/unparseable local PostgreSQL settings; no target writes performed'
check_disk_requirement "$bundle_bytes" "$db_name"
[[ $release_id =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]{2,63}$ ]] || die 'unsafe release id in bundle manifest'
STAGE="$RELEASES/$release_id"
backup="$BACKUPS/$release_id"
[[ ! -e "$STAGE" && ! -L "$STAGE" && ! -e "$backup" && ! -L "$backup" ]] || die 'release staging/backup path already exists'
if [[ -e "$RELEASES" ]]; then [[ -d "$RELEASES" && ! -L "$RELEASES" && $(stat -c '%U:%G' "$RELEASES") == root:mayak && $(stat -c '%a' "$RELEASES") == 750 ]] || die 'release staging directory has unsupported owner/mode/type'; fi
if [[ -e "$BACKUPS" ]]; then [[ -d "$BACKUPS" && ! -L "$BACKUPS" && $(stat -c '%U:%G' "$BACKUPS") == root:root && $(stat -c '%a' "$BACKUPS") == 700 ]] || die 'release backup directory has unsupported owner/mode/type'; fi
for n in windows-x64 android-arm64; do p="/opt/mayak/static/updates/stable/$n.json"; [[ ! -L "$p" && ( ! -e "$p" || -f "$p" ) ]] || die 'existing stable feed path is a symlink or non-regular file'; done
[[ ! -L "$DIST/mayak-agent" && ( ! -e "$DIST/mayak-agent" || -f "$DIST/mayak-agent" ) ]] || die 'existing Mayak agent path is a symlink or non-regular file'
if [[ ! -e "$RELEASES" ]]; then install -d -o root -g mayak -m 0750 "$RELEASES";
elif [[ -d "$RELEASES" && $(stat -c '%U:%G' "$RELEASES") == root:mayak && $(stat -c '%a' "$RELEASES") == 750 ]]; then :;
else die 'release staging directory has unsupported owner/mode/type'; fi
if [[ ! -e "$BACKUPS" ]]; then install -d -o root -g root -m 0700 "$BACKUPS";
elif [[ -d "$BACKUPS" && $(stat -c '%U:%G' "$BACKUPS") == root:root && $(stat -c '%a' "$BACKUPS") == 700 ]]; then :;
else die 'release backup directory has unsupported owner/mode/type'; fi
release_id=$(verify_and_stage)
stage="$RELEASES/$release_id"
backup="$BACKUPS/$release_id"
mkdir -m 0700 "$backup"


static_root=/opt/mayak/static
snapshot_assets "$backup"
python3 "$SAFETY" overlay-hashes "$API_DIR" || die 'current API HTML overlay differs from observed preserved snapshot; API remains running'
tar -czf "$backup/api.previous.tar.gz" -C "$API_DIR" .
chmod 0600 "$backup/api.previous.tar.gz"
sha256sum "$backup/api.previous.tar.gz" | awk '{print $1}' > "$backup/api.previous.tar.gz.sha256"
chmod 0600 "$backup/api.previous.tar.gz.sha256"
recovery="$backup"
old_api="$API_DIR.previous-$release_id"
failed_api="$RELEASES/failed-$release_id-api"
service_stopped=0
release_swapped=0
trap 'exit_release "$?"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP

# Snapshot and validate the candidate while the live API remains available.
# pg_dump is MVCC-consistent; a second final dump follows the API stop.
if ! timeout 300 runuser -u postgres -- pg_dump --host=/var/run/postgresql --port=5432 --username=postgres --no-password --format=custom --no-owner --no-acl --dbname="$db_name" 2>/dev/null >"$backup/database.initial.dump"; then rm -f -- "$backup/database.initial.dump"; die 'initial pg_dump failed; API remains running'; fi
chmod 0600 "$backup/database.initial.dump"
candidate_check "$stage/api" "$backup/database.initial.dump"

# Static packages are staged before stopping the API; feeds remain unchanged.
static_root=/opt/mayak/static
id caddy >/dev/null 2>&1 || die 'Caddy service account missing'
for d in "$static_root" "$static_root/updates" "$static_root/updates/packages" "$static_root/updates/stable"; do
  if [[ ! -e $d && ! -L $d ]]; then install -d -o root -g caddy -m 0750 "$d";
  elif [[ -d $d && ! -L $d && $(stat -c '%U:%G' "$d") == root:caddy && $(stat -c '%a' "$d") == 750 ]]; then :;
  else die 'existing static-update directory has an unsupported owner/mode/type'; fi
done
for f in "$stage"/updates/packages/*; do
  dest="$static_root/updates/packages/$(basename "$f")"
  if [[ -e $dest || -L $dest ]]; then [[ -f $dest && ! -L $dest ]] && cmp -s -- "$f" "$dest" || die 'existing update package filename has different contents; refusing overwrite';
  else [[ ! -e "$dest.new-$release_id" && ! -L "$dest.new-$release_id" ]] || die 'package staging path already exists'; install -o root -g caddy -m 0640 "$f" "$dest.new-$release_id"; mv "$dest.new-$release_id" "$dest"; fi
  runuser -u caddy -- test -r "$dest" || die 'Caddy cannot read staged update package'
done

agent_new="$DIST/.mayak-agent-$release_id"
api_next="$API_DIR.next-$release_id"
for p in "$agent_new" "$old_api" "$api_next" "$failed_api"; do [[ ! -e $p && ! -L $p ]] || die 'API/agent swap or recovery staging path already exists'; done
install -o root -g mayak -m 0750 "$stage/dist/mayak-agent" "$agent_new"
cp -a "$stage/api" "$api_next"
chown -R root:mayak "$api_next"
find "$api_next" -type d -exec chmod 0750 {} +
find "$api_next" -type f -exec chmod 0640 {} +
runuser -u mayak -- test -r "$api_next/mayak-api.dll" || die 'prepared API is not readable by service account'

python3 "$SAFETY" caddy-hash "$CADDYFILE" "$EXPECTED_CADDY_SHA256" || die 'Caddy changed since the observed overlay snapshot'
caddy validate --config "$CADDYFILE" --adapter caddyfile >/dev/null 2>&1 || die 'existing Caddy config validation failed; no Caddy bytes changed'

# Prepare both feed files before stopping the API; only mv remains in switch.
for name in windows-x64 android-arm64; do
  [[ ! -e "$static_root/updates/stable/$name.json.new-$release_id" && ! -L "$static_root/updates/stable/$name.json.new-$release_id" ]] || die 'stable-feed staging path already exists'
  install -o root -g caddy -m 0640 "$stage/updates/stable/$name.json" "$static_root/updates/stable/$name.json.new-$release_id"
  runuser -u caddy -- test -r "$static_root/updates/stable/$name.json.new-$release_id" || die 'prepared feed is unreadable'
done

# Only after restore, candidate smoke and static package staging, stop the
# known writer and make the retained final MVCC snapshot immediately before
# switching API/agent files.
service_stopped=1
timeout 100 systemctl stop "$UNIT"
release_swapped=0
if ! timeout 300 runuser -u postgres -- pg_dump --host=/var/run/postgresql --port=5432 --username=postgres --no-password --format=custom --no-owner --no-acl --dbname="$db_name" 2>/dev/null >"$backup/database.dump"; then rm -f -- "$backup/database.dump"; die 'final pg_dump failed; old API will be restarted'; fi
chmod 0600 "$backup/database.dump"

mv -f "$agent_new" "$DIST/mayak-agent"
mv "$API_DIR" "$old_api"
mv "$API_DIR.next-$release_id" "$API_DIR"
release_swapped=1
timeout 100 systemctl start "$UNIT"
api_ok=0
for _ in {1..30}; do if curl --noproxy '*' --fail --silent --max-time 2 "$HEALTH_URL" >/dev/null 2>&1; then api_ok=1; break; fi; sleep 2; done
[[ $api_ok == 1 ]] || die 'new API readiness failed; API-only rollback will restore old files/config'
service_stopped=0

python3 "$SAFETY" caddy-config "$CADDYFILE" || die 'loaded Caddy config differs from the preserved on-disk configuration'

# Atomic signed-feed switch happens only after package installation.
for name in windows-x64 android-arm64; do
  mv -f "$static_root/updates/stable/$name.json.new-$release_id" "$static_root/updates/stable/$name.json"
done
for name in windows-x64 android-arm64; do
  expected=$(sha256sum "$stage/updates/stable/$name.json" | awk '{print $1}')
  delivered=$(curl --noproxy '*' --fail --silent --show-error --max-time 15 --resolve mayaklight.ru:443:127.0.0.1 "https://mayaklight.ru/updates/stable/$name.json" | sha256sum | awk '{print $1}') || die 'same-origin HTTPS feed canary failed'
  [[ $delivered == "$expected" ]] || die 'HTTPS feed bytes differ from signed staged manifest'
done
for package in "$stage"/updates/packages/*; do
  name=$(basename "$package")
  expected=$(sha256sum "$package" | awk '{print $1}')
  delivered=$(curl --noproxy '*' --fail --silent --show-error --max-time 120 --resolve mayaklight.ru:443:127.0.0.1 "https://mayaklight.ru/updates/packages/$name" | sha256sum | awk '{print $1}') || die 'same-origin HTTPS package canary failed'
  [[ $delivered == "$expected" ]] || die 'HTTPS package bytes differ from verified bundle'
done
canary=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')
canary_status=$(printf 'url = "https://mayaklight.ru/sub/%s"\nresolve = "mayaklight.ru:443:127.0.0.1"\nnoproxy = "*"\n' "$canary" | curl --config - --silent --output /dev/null --write-out '%{http_code}' --max-time 10 2>/dev/null) || die 'subscription log canary request could not complete'
[[ $canary_status == 404 ]] || die 'subscription log canary returned an unexpected status'
sleep 2
printf '%s\n' "$canary" | python3 "$SAFETY" journal-canary || die 'subscription canary was logged or journal verification is unavailable'
service_stopped=0
trap - EXIT INT TERM HUP
note "RELEASE APPLIED: $release_id. API health and same-origin HTTPS feed canary passed. Initial PostgreSQL dump restore-tested; final snapshot retained; Caddy bytes unchanged; rollback does not rewind DB."
note 'No VPN services, routes, containers or firewall were changed. No secret or canary token was printed.'
exit 0
