#!/usr/bin/env python3
"""Isolated Mayak HTTPS pilot. Target-only, root, Python stdlib; no DB writes."""
from __future__ import annotations
import argparse
import contextlib
import hashlib
import json
import math
import os
import pathlib
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse
import uuid
import zipfile

ROOT = pathlib.Path('/opt/mayak/https-entry')
CADDY = pathlib.Path('/etc/caddy/Caddyfile')
UNIT = pathlib.Path('/etc/systemd/system/mayak-https-entry.service')
WANTS = pathlib.Path('/etc/systemd/system/multi-user.target.wants/mayak-https-entry.service')
SERVICE = 'mayak-https-entry.service'
USER = 'mayak-entry'
FOREIGN, DOMAIN, PORT = '147.45.41.230', 'mayaklight.ru', 18080
ARCHIVE_SHA = '8a5f3e6a1057e4bd0f8a7c57c9d91204b4be0b74222a6e210d070603101163c2'
PHASE = 'startup'
PATH_RE = re.compile(r'/mayak-connect/[a-f0-9]{36}/')
ENDPOINTS = ('/', '/my/', '/admin/', '/health', '/gw/public-key',
             '/updates/stable/windows-x64.json', '/updates/stable/android-arm64.json')
STATIC_TARGETS = {'/': pathlib.Path('/opt/mayak/api/wwwroot/index.html'),
                  '/my/': pathlib.Path('/opt/mayak/api/wwwroot/my/index.html')}
STATIC_NAMES = {'/': 'index.html', '/my/': 'my.html'}
ADMIN_TARGETS = {'/admin/': pathlib.Path('/opt/mayak/api/wwwroot/admin/index.html')}
ADMIN_NAMES = {'/admin/': 'admin.html'}
UNIT_TEXT = '''[Unit]
Description=Mayak isolated HTTPS entry
After=network-online.target
[Service]
User=mayak-entry
Group=mayak-entry
ExecStart=/opt/mayak/https-entry/xray run -config /opt/mayak/https-entry/config.json
Restart=on-failure
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths=/opt/mayak/https-entry
LimitNOFILE=65536
UMask=0077
StandardOutput=null
StandardError=null
[Install]
WantedBy=multi-user.target
'''


class Refuse(Exception):
    """Only fixed, nonsecret developer-written diagnostics belong here."""


def phase(value):
    global PHASE
    PHASE = value


def require(ok, reason):
    if not ok:
        raise Refuse(reason)


def run(argv, *, timeout=30, input_text=None, binary=False):
    return subprocess.run(argv, input=input_text, text=not binary, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, timeout=timeout, check=True).stdout


def strict_json(text):
    def pairs(items):
        out = {}
        for k, v in items:
            require(k not in out, 'duplicate JSON key')
            out[k] = v
        return out
    return json.loads(text, object_pairs_hook=pairs)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def digest(path):
    return sha(pathlib.Path(path).read_bytes())


def parents_safe(path):
    p = pathlib.Path(os.path.abspath(path))
    for item in (p, *p.parents):
        s = item.lstat()
        require(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022,
                'parent must be a root-owned nonwritable real directory')


def regular(path, private=True):
    path = pathlib.Path(path)
    parents_safe(path.parent)
    s = path.lstat()
    require(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and s.st_nlink == 1,
            'file must be root-owned regular single-link file')
    require(not s.st_mode & (0o077 if private else 0o022), 'unsafe file permissions')
    return s


def private_dir(path):
    parents_safe(path)
    require(not path.lstat().st_mode & 0o077, 'directory must be private')


def put(path, data, mode=0o600):
    """Create without following links or replacing any existing entry."""
    parents_safe(path.parent)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as f:
        os.fchmod(f.fileno(), mode)
        f.write(data.encode() if isinstance(data, str) else data)
        f.flush()
        os.fsync(f.fileno())


def save_json(path, obj):
    data = (json.dumps(obj, sort_keys=True) + '\n').encode()
    if not path.exists():
        put(path, data)
        return
    regular(path)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix='.receipt-')
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        pathlib.Path(tmp).unlink(missing_ok=True)


def atomic_copy(source, destination, expected):
    regular(source)
    s = regular(destination, private=False)
    require(digest(destination) == expected, 'destination drift before atomic replacement')
    fd, tmp = tempfile.mkstemp(dir=destination.parent, prefix='.mayak-entry-')
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(source.read_bytes()); f.flush(); os.fsync(f.fileno())
        os.chown(tmp, s.st_uid, s.st_gid)
        os.chmod(tmp, stat.S_IMODE(s.st_mode))
        require(digest(destination) == expected, 'destination drift during atomic replacement')
        os.replace(tmp, destination)
    finally:
        pathlib.Path(tmp).unlink(missing_ok=True)


@contextlib.contextmanager
def lock():
    import fcntl
    p = pathlib.Path('/run/mayak-https-entry.lock')
    parents_safe(p.parent)
    fd = os.open(p, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        regular(p)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def valid_uuid(s):
    try:
        return str(uuid.UUID(s)) == s.lower()
    except (ValueError, AttributeError, TypeError):
        return False


def endpoint_from_db(meta):
    c = meta.get('Cluster')
    require(isinstance(c, dict) and isinstance(c.get('XrayJson'), str), 'missing upstream metadata')
    return endpoint_config(strict_json(c['XrayJson']))


def endpoint_config(cfg):
    require(isinstance(cfg, dict), 'unsupported upstream endpoint')
    transport, flow = cfg.get('Transport'), cfg.get('Flow')
    require(type(cfg.get('Port')) is int and cfg['Port'] == 443 and
            cfg.get('Security', 'reality') == 'reality' and transport in ('xhttp', 'raw', 'tcp') and
            (flow in (None, '') or (transport in ('raw', 'tcp') and flow == 'xtls-rprx-vision')) and
            cfg.get('Fingerprint') in (None, '', 'chrome') and
            cfg.get('Host', FOREIGN) == FOREIGN, 'incompatible upstream port, transport, flow or fingerprint')
    sni, sid, public = cfg.get('Sni'), cfg.get('ShortId'), cfg.get('PublicKey')
    require(isinstance(sni, str) and re.fullmatch(r'[A-Za-z0-9.-]{1,253}', sni) and
            isinstance(sid, str) and re.fullmatch(r'[0-9a-f]{2,16}', sid) and len(sid) % 2 == 0 and
            isinstance(public, str) and re.fullmatch(r'[A-Za-z0-9_-]{43}', public), 'unsupported upstream Reality metadata')
    if transport in ('raw', 'tcp'):
        require(all(cfg.get(k) in (None, '') for k in ('XhttpPath', 'XhttpHost', 'XhttpMode')),
                'XHTTP metadata on raw upstream')
        return dict(sni=sni, sid=sid, pbk=public, transport='raw', flow=flow or '')
    mode = cfg.get('XhttpMode') or 'auto'
    path, host = cfg.get('XhttpPath') or '/', cfg.get('XhttpHost') or sni
    require(isinstance(path, str) and re.fullmatch(r'/[A-Za-z0-9/_-]{0,200}', path) and
            isinstance(host, str) and re.fullmatch(r'[A-Za-z0-9.-]{1,253}', host) and
            mode in ('auto', 'packet-up', 'stream-up'), 'unsupported upstream XHTTP metadata')
    return dict(sni=sni, sid=sid, pbk=public, path=path, host=host, mode=mode)


def upstream_override(data, device):
    cfg = strict_json(data)
    fields = {'Host', 'Port', 'Security', 'Transport', 'Flow', 'Sni', 'ShortId', 'PublicKey',
              'Fingerprint', 'XhttpPath', 'XhttpHost', 'XhttpMode', 'targetHost', 'selectedClientSha256'}
    required = {'Host', 'Port', 'Security', 'Transport', 'Flow', 'Sni', 'ShortId', 'PublicKey',
                'targetHost', 'selectedClientSha256'}
    require(isinstance(cfg, dict) and required <= set(cfg) <= fields,
            'unsupported public upstream override fields')
    require(cfg['targetHost'] == FOREIGN and cfg['Host'] == FOREIGN and cfg['Security'] == 'reality' and
            isinstance(cfg['Flow'], str) and cfg['selectedClientSha256'] == sha(device.encode()),
            'upstream override target, security or selected credential binding mismatch')
    return endpoint_config(cfg)


def select_device(meta, device_id=None):
    accounts, devices = meta.get('Accounts'), meta.get('Devices')
    require(isinstance(accounts, list) and isinstance(devices, list), 'missing accounts/devices')
    active = set()
    for a in accounts:
        require('PaidUntilEpoch' in a, 'missing account expiration')
        until = a.get('PaidUntilEpoch')
        require(until is None or (type(until) in (int, float) and math.isfinite(until)), 'invalid account expiration')
        if a.get('Enabled') is True and (until is None or until > time.time()):
            active.add(a.get('Id'))
    eligible = [d for d in devices if d.get('Enabled') is True and d.get('AccountId') in active and
                d.get('ServiceProtocol') in (None, '') and valid_uuid(d.get('XrayId'))]
    if device_id:
        eligible = [d for d in eligible if d.get('Id') == device_id]
    elif len(eligible) != 1:
        eligible = [d for d in eligible if d.get('Name') == 'Телефон']
    require(len(eligible) == 1, 'eligible device ambiguous or absent; select device identifier')
    return str(uuid.UUID(eligible[0]['XrayId']))


def build_xray(outbound_id, inbound_id, path, upstream):
    stream = {'network': upstream.get('transport', 'xhttp'), 'security': 'reality',
              'realitySettings': {'serverName': upstream['sni'], 'fingerprint': 'chrome',
                                 'publicKey': upstream['pbk'], 'shortId': upstream['sid']}}
    if stream['network'] == 'xhttp':
        stream['xhttpSettings'] = {k: upstream[k] for k in ('host', 'path', 'mode')}
    config = {'log': {'loglevel': 'none'},
        'inbounds': [{'listen': '127.0.0.1', 'port': PORT, 'protocol': 'vless',
            'settings': {'clients': [{'id': inbound_id}], 'decryption': 'none'},
            'streamSettings': {'network': 'xhttp', 'security': 'none',
                'xhttpSettings': {'path': path, 'mode': 'packet-up'}}}],
        'outbounds': [{'protocol': 'vless', 'settings': {'vnext': [{'address': FOREIGN, 'port': 443,
            'users': [{'id': outbound_id, 'encryption': 'none'}]}]},
            'streamSettings': stream}]}
    if upstream.get('transport') == 'raw':
        outbound = config['outbounds'][0]
        outbound['settings']['vnext'][0]['users'][0]['flow'] = upstream['flow']
    return config


def read_db(db):
    require(re.fullmatch(r'[A-Za-z0-9_]{1,63}', db), 'unsupported database name')
    # XrayJson contains PUBLIC endpoint metadata; never read XrayPrivateKey.
    sql = '''SELECT json_build_object(
      'Cluster',(SELECT json_build_object('XrayJson',"XrayJson") FROM "Cluster" WHERE "Id"=1),
      'Accounts',(SELECT json_agg(json_build_object('Id',"Id",'Enabled',"Enabled",'PaidUntilEpoch',extract(epoch from "PaidUntil"))) FROM "Accounts"),
      'Devices',(SELECT json_agg(json_build_object('Id',"Id",'AccountId',"AccountId",'Enabled',"Enabled",'Name',"Name",'XrayId',"XrayId",'ServiceProtocol',"ServiceProtocol")) FROM "Devices"))::text'''
    return strict_json(run(['runuser', '-u', 'postgres', '--', 'psql', '-X', '-A', '-t',
        '-v', 'ON_ERROR_STOP=1', '--no-password', '--dbname=' + db, '-c', sql]))


def load_meta(path):
    regular(path)
    return strict_json(path.read_text())


def adapt(path):
    source = str(path)
    config = strict_json(run(['caddy', 'adapt', '--config', source, '--adapter', 'caddyfile']))

    def canonical_hide(value):
        if isinstance(value, dict):
            # Caddy 2.6.2 hides its actual adapter input file automatically.
            # Compare staged adaptations as if read from the live Caddyfile;
            # retain every unrelated hide entry and all other config fields.
            if value.get('handler') == 'file_server' and isinstance(value.get('hide'), list):
                value['hide'] = [str(CADDY) if item == source else item for item in value['hide']]
            for child in value.values():
                canonical_hide(child)
        elif isinstance(value, list):
            for child in value:
                canonical_hide(child)

    canonical_hide(config)
    return config


def loaded():
    return strict_json(run(['curl', '--disable', '--noproxy', '*', '--fail', '--silent', '--max-time', '5',
                           'http://127.0.0.1:2019/config/']))


def props(service):
    keys = 'User,Group,FragmentPath,DropInPaths,ExecStart,MainPID,ActiveState,LoadState'
    return dict(line.split('=', 1) for line in run(['systemctl', 'show', service, '--property=' + keys]).splitlines())


def process(pid):
    p = pathlib.Path('/proc') / str(pid)
    # starttime disambiguates PID reuse; executable and uid disambiguate identities.
    fields = (p / 'stat').read_text().rsplit(')', 1)[1].split()
    return {'pid': int(pid), 'start': fields[19], 'exe': os.readlink(p / 'exe'), 'uid': p.stat().st_uid}


def exec_start(value):
    # systemctl serializes accounting alongside the immutable command. daemon-reload
    # can reset accounting without changing the real process or loaded command.
    require(isinstance(value, str) and not re.search(r'[\r\n]', value), 'malformed systemd ExecStart')
    match = re.fullmatch(
        r'\{\s*path=(/[^\s;{}]+)\s*;\s*argv\[\]=([^;{}\r\n]+?)\s*;\s*ignore_errors=(no|yes)\s*;\s*'
        r'start_time=\[[^\]\r\n]*\]\s*;\s*stop_time=\[[^\]\r\n]*\]\s*;\s*pid=[0-9]+\s*;\s*'
        r'code=[^;{}\r\n]+\s*;\s*status=[^;{}\r\n]+\s*\}', value)
    require(match is not None, 'malformed systemd ExecStart')
    argv = match[2].split()
    require(argv and all(re.fullmatch(r'[A-Za-z0-9_./=:@+,-]+', arg) for arg in argv),
            'unsupported systemd ExecStart arguments')
    require(argv[0] == match[1], 'systemd ExecStart executable mismatch')
    return {'path': match[1], 'argv': argv, 'ignore_errors': match[3]}


def same_caddy_identity(actual, expected):
    identities = []
    for item in (actual, expected):
        require(isinstance(item, dict) and set(item) == {'unit_sha', 'binary_sha', 'argv', 'process'},
                'unsupported Caddy identity snapshot')
        identities.append(dict(item, argv=exec_start(item['argv'])))
    return identities[0] == identities[1]


def caddy_identity():
    import pwd
    p = props('caddy.service')
    require(p.get('User') == 'caddy' and p.get('Group') in ('', 'caddy') and not p.get('DropInPaths') and
            p.get('ActiveState') == 'active' and p.get('LoadState') == 'loaded', 'unsupported Caddy unit identity')
    fragment = pathlib.Path(p['FragmentPath'])
    # Distribution /lib may be a symlink; resolve explicitly, then validate the actual file.
    fragment = fragment.resolve(strict=True)
    regular(fragment, private=False)
    require(fragment.name == 'caddy.service' and str(fragment.parent) in
            ('/usr/lib/systemd/system', '/lib/systemd/system'), 'unexpected Caddy unit location')
    command = exec_start(p['ExecStart'])
    require(command['path'] == '/usr/bin/caddy' and command['ignore_errors'] == 'no' and
            command['argv'][1:2] == ['run'] and command['argv'].count('--config') == 1 and
            command['argv'][command['argv'].index('--config') + 1:] == ['/etc/caddy/Caddyfile'],
            'unsupported Caddy command')
    identity = process(int(p['MainPID']))
    require(identity['exe'] == '/usr/bin/caddy' and identity['uid'] == pwd.getpwnam('caddy').pw_uid,
            'unexpected Caddy process identity')
    regular(pathlib.Path('/usr/bin/caddy'), private=False)
    require(listener_owned(identity['pid'], 2019), 'Caddy admin listener identity mismatch')
    return dict(unit_sha=digest(fragment), binary_sha=digest('/usr/bin/caddy'), argv=p['ExecStart'], process=identity)


def response_baseline():
    out = {}
    for endpoint in ENDPOINTS:
        # No -k, no redirects, no compression. Status+body binding is stable and private.
        value = run(['curl', '--disable', '--noproxy', '*', '--silent', '--show-error', '--max-time', '15',
            '--resolve', DOMAIN + ':443:127.0.0.1', '-H', 'Accept-Encoding: identity',
            '--write-out', '\n%{http_code}', 'https://' + DOMAIN + endpoint], timeout=20, binary=True)
        body, code = value.rsplit(b'\n', 1)
        code = code.decode('ascii')
        require(code.isdigit() and code != '000', 'baseline HTTPS request failed')
        if endpoint == '/health':
            require(code == '200' and strict_json(body).get('ok') is True, 'API health baseline failed')
        if endpoint.startswith('/updates/') or endpoint == '/gw/public-key':
            require(code == '200' and len(body) > 0, 'required public endpoint unavailable')
        out[endpoint] = {'status': code, 'sha256': sha(body)}
    return out


def baseline(path=CADDY):
    regular(path, private=False)
    before = path.read_bytes()
    disk = adapt(path)
    require(loaded() == disk and path.read_bytes() == before, 'loaded Caddy differs from disk')
    return {'caddy_sha256': sha(before), 'loaded': disk, 'identity': caddy_identity(),
            'responses': response_baseline()}


def candidate(original, path):
    require(PATH_RE.fullmatch(path), 'invalid staged route')
    canon = re.sub(r'(?m)^\s*#.*$', '', original)
    canon = re.sub(r'\s+', ' ', canon).strip()
    require(re.fullmatch(r'mayaklight\.ru \{ (?:encode gzip )?handle /updates/\* \{ root \* /opt/mayak/static file_server \} reverse_proxy 127\.0\.0\.1:5080 \}', canon),
            'unsupported Caddyfile drift')
    # Exclusive handles: compression is scoped to the original API/static fallback only.
    return f'''mayaklight.ru {{
    handle {path}* {{
        reverse_proxy 127.0.0.1:{PORT}
    }}
    handle {{
        encode gzip
        handle /updates/* {{
            root * /opt/mayak/static
            file_server
        }}
        reverse_proxy 127.0.0.1:5080
    }}
}}
'''


def free_port(port):
    with socket.socket() as s:
        s.bind(('127.0.0.1', port))
        return s.getsockname()[1]


def listener_owned(pid, port):
    expected = '0100007F:' + format(port, '04X')
    matches = [line.split()[9] for line in pathlib.Path('/proc/net/tcp').read_text().splitlines()[1:]
               if line.split()[1] == expected and line.split()[3] == '0A']
    if len(matches) != 1:
        return False
    own = set()
    for p in (pathlib.Path('/proc') / str(pid) / 'fd').iterdir():
        try:
            own.add(os.readlink(p))
        except FileNotFoundError:
            pass
    return 'socket:[' + matches[0] + ']' in own


def curl_socks(port, url):
    value = run(['curl', '--disable', '--noproxy', '', '--proxy', 'socks5h://127.0.0.1:' + str(port),
                '--fail', '--silent', '--max-time', '18', '--write-out', '\n%{http_code}', url], timeout=22)
    body, status = value.rsplit('\n', 1)
    require(status == '200', 'probe HTTPS status is not 200')
    return body


def probe_socks(d, m, outbound=None, negative=False):
    """Every request uses a listener proven to belong to this exact child PID."""
    port = free_port(0)
    if outbound is None:
        outbound = strict_json((d / 'xray.json').read_text())['outbounds'][0]
    cfg = {'log': {'loglevel': 'none'}, 'inbounds': [{'listen': '127.0.0.1', 'port': port,
        'protocol': 'socks', 'settings': {'auth': 'noauth', 'udp': False}}], 'outbounds': [outbound]}
    tmp = d / ('probe-' + secrets.token_hex(10) + '.json')
    put(tmp, json.dumps(cfg))
    p = None
    try:
        p = subprocess.Popen([str(d / 'xray.bin'), 'run', '-config', str(tmp)],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        end = time.monotonic() + 8
        while time.monotonic() < end:
            require(p.poll() is None, 'probe child exited before listener readiness')
            if listener_owned(p.pid, port):
                break
            time.sleep(.1)
        else:
            raise Refuse('probe child did not acquire the private listener')
        for url in ('https://example.com/', 'https://api.ipify.org'):
            require(p.poll() is None and listener_owned(p.pid, port), 'probe listener ownership lost')
            try:
                result = curl_socks(port, url)
            except subprocess.SubprocessError:
                if negative:
                    continue
                raise Refuse('authenticated probe HTTP request failed')
            require(not negative, 'wrong-UUID unexpectedly reached HTTPS destination')
            require(bool(result.strip()), 'probe returned empty response')
            if url.endswith('ipify.org'):
                require(result.strip() == FOREIGN, 'authenticated probe egress mismatch')
        require(p.poll() is None and listener_owned(p.pid, port), 'probe listener ownership lost at completion')
    finally:
        if p is not None:
            if p.poll() is None:
                p.terminate()
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill(); p.wait(timeout=5)
        tmp.unlink(missing_ok=True)


def preflight(args):
    import grp
    phase('preflight.tools')
    for c in ('caddy', 'systemctl', 'curl', 'runuser', 'psql', 'useradd'):
        require(shutil.which(c), 'required target tool missing')
    require(re.match(r'v?2\.6\.2(?:\s|$)', run(['caddy', 'version'])), 'unreviewed Caddy version')
    phase('preflight.baseline')
    b = baseline()
    free_port(PORT)
    require(not ROOT.exists() and not ROOT.is_symlink() and not UNIT.exists() and not UNIT.is_symlink(),
            'entry install paths already occupied')
    require(not WANTS.exists() and not WANTS.is_symlink() and props(SERVICE).get('LoadState') == 'not-found',
            'entry unit or enablement already exists')
    require(subprocess.run(['id', '-u', USER], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0,
            'entry identity already exists')
    try:
        grp.getgrnam(USER)
    except KeyError:
        pass
    else:
        raise Refuse('entry group already exists')
    print('PASS preflight: Caddy loaded/disk identity, HTTPS endpoints and free entry loopback port')
    return b


def prepare(args):
    phase('prepare.archive')
    regular(args.archive, private=False)
    require(digest(args.archive) == ARCHIVE_SHA, 'pinned Xray archive checksum mismatch')
    parents_safe(args.out.parent)
    with zipfile.ZipFile(args.archive) as z:
        items = [i for i in z.infolist() if i.filename == 'xray']
        require(len(items) == 1 and 0 < items[0].file_size < 200_000_000 and not items[0].is_dir(),
                'unsupported archive executable entry')
        data = z.read(items[0])
    require(data[:5] == b'\x7fELF\x02' and data[18:20] == b'\x3e\x00', 'expected Linux amd64 ELF executable')
    put(args.out, data, 0o700)
    put(args.out.with_name(args.out.name + '.sha256'), sha(data) + '\n')
    print('PASS prepare: pinned archive; extracted only xray; private binary checksum file created')


def stage(args):
    b = preflight(args)
    phase('stage.metadata')
    override_path = args.upstream_metadata
    require(not (override_path and args.metadata), 'upstream override requires real database credentials')
    meta = load_meta(args.metadata) if args.metadata else read_db(args.database)
    device = select_device(meta, args.device_id)
    if override_path:
        regular(override_path)
        override_data = override_path.read_bytes()
        upstream = upstream_override(override_data, device)
    else:
        upstream = endpoint_from_db(meta)
    regular(args.xray_bin)
    if args.sha256_file:
        regular(args.sha256_file)
        expected = args.sha256_file.read_text().strip()
    else:
        expected = args.sha256 or ''
    require(re.fullmatch('[a-f0-9]{64}', expected) and digest(args.xray_bin) == expected,
            'Xray binary checksum mismatch')
    phase('stage.create')
    parents_safe(args.out.parent)
    require(not args.out.exists() and not args.out.is_symlink(), 'stage path already occupied')
    args.out.mkdir(mode=0o700)
    d = args.out
    original = CADDY.read_bytes()
    require(sha(original) == b['caddy_sha256'], 'Caddy changed during staging')
    path, inbound_id = '/mayak-connect/' + secrets.token_hex(18) + '/', str(uuid.uuid4())
    put(d / 'Caddyfile.original', original)
    put(d / 'Caddyfile.candidate', candidate(original.decode(), path))
    put(d / 'xray.bin', args.xray_bin.read_bytes(), 0o700)
    put(d / 'xray.json', json.dumps(build_xray(device, inbound_id, path, upstream)))
    put(d / 'baseline.json', json.dumps(b))
    names = ['Caddyfile.original', 'Caddyfile.candidate', 'xray.bin', 'xray.json', 'baseline.json']
    if override_path:
        put(d / 'upstream-metadata.json', override_data)
        names.append('upstream-metadata.json')
    m = dict(path=path, inbound_id=inbound_id, database=args.database, device_id=args.device_id,
             metadata_fixture=bool(args.metadata), upstream_device=device, upstream=upstream,
             upstream_metadata=bool(override_path), files={name: digest(d / name) for name in names})
    put(d / 'manifest.json', json.dumps(m))
    stage_files(d)
    print('PASS stage: private bound baseline/candidate; public routes unchanged')


def stage_files(d):
    private_dir(d)
    # Check every entry, including optional receipts; directories/symlinks are never allowed.
    for p in d.iterdir():
        regular(p)
    m = strict_json((d / 'manifest.json').read_text())
    require(PATH_RE.fullmatch(m.get('path', '')) and valid_uuid(m.get('inbound_id')), 'invalid staged pilot metadata')
    expected_names = {'Caddyfile.original', 'Caddyfile.candidate', 'xray.bin', 'xray.json', 'baseline.json'}
    require(type(m.get('upstream_metadata', False)) is bool, 'invalid upstream override marker')
    if m.get('upstream_metadata', False):
        require(m.get('metadata_fixture') is False, 'upstream override requires real database credentials')
        expected_names.add('upstream-metadata.json')
    require(set(m['files']) == expected_names, 'invalid stage file manifest')
    for name, expected in m['files'].items():
        require(digest(d / name) == expected, 'bound stage artifact changed')
    if m.get('upstream_metadata', False):
        require(upstream_override((d / 'upstream-metadata.json').read_bytes(), m['upstream_device']) == m['upstream'],
                'bound upstream override inconsistent')
    b = strict_json((d / 'baseline.json').read_text())
    require(m['files']['Caddyfile.original'] == b['caddy_sha256'] and
            (d / 'Caddyfile.candidate').read_text() == candidate((d / 'Caddyfile.original').read_text(), m['path']) and
            strict_json((d / 'xray.json').read_text()) == build_xray(m['upstream_device'], m['inbound_id'], m['path'], m['upstream']),
            'stage bindings inconsistent')
    static_revision(d, m)
    admin_revision(d, m)
    return m


def check_drift(d, candidate_live=False, responses=True, static_trial=None, admin_trial=None):
    m = stage_files(d)
    b = strict_json((d / 'baseline.json').read_text())
    regular(CADDY, private=False)
    source = d / ('Caddyfile.candidate' if candidate_live else 'Caddyfile.original')
    require(digest(CADDY) == digest(source) and loaded() == adapt(source), 'Caddy disk/runtime drift')
    require(same_caddy_identity(caddy_identity(), b['identity']), 'Caddy identity drift')
    if responses:
        require(response_baseline() == response_expectations(d, b, static_trial, admin_trial), 'original endpoint response drift')
    return m


def check(args):
    d = args.stage
    phase('check.drift')
    m = check_drift(d)
    free_port(PORT)
    outbound_checks(d, m, 'check')
    check_drift(d)
    save_json(d / 'check.json', {'manifest_sha': digest(d / 'manifest.json'), 'at': time.time(),
                               'outbound_auth': True, 'outbound_wrong_uuid': True})
    print('PASS check: syntax, authenticated example.com + foreign egress, wrong-UUID blocked; routes unchanged')


def outbound_checks(d, m, operation):
    phase(operation + '.xray-syntax')
    run([str(d / 'xray.bin'), 'run', '-test', '-config', str(d / 'xray.json')])
    phase(operation + '.caddy-syntax')
    run(['caddy', 'validate', '--config', str(d / 'Caddyfile.candidate'), '--adapter', 'caddyfile'])
    phase(operation + '.outbound-auth')
    probe_socks(d, m)
    phase(operation + '.outbound-wrong-uuid')
    outbound = strict_json((d / 'xray.json').read_text())['outbounds'][0]
    outbound['settings']['vnext'][0]['users'][0]['id'] = str(uuid.uuid4())
    probe_socks(d, m, outbound, negative=True)


def stamp(path):
    s = regular(path, private=False)
    return dict(sha=digest(path), ino=s.st_ino, dev=s.st_dev, uid=s.st_uid, gid=s.st_gid, mode=stat.S_IMODE(s.st_mode))


def receipt(d):
    regular(d / 'receipt.json')
    r = strict_json((d / 'receipt.json').read_text())
    require(r['manifest_sha'] == digest(d / 'manifest.json'), 'receipt belongs to different stage')
    return r


def owned(d):
    import pwd
    r = receipt(d)
    require(r.get('installed'), 'no completed owned install receipt; recovery requires diagnosis')
    require(set(r['files']) == {str(ROOT / 'xray'), str(ROOT / 'config.json'), str(UNIT)}, 'unexpected install receipt')
    require({p: stamp(pathlib.Path(p)) for p in r['files']} == r['files'], 'installed file ownership/hash drift')
    s = ROOT.lstat()
    require(stat.S_ISDIR(s.st_mode) and s.st_ino == r['root_ino'] and s.st_uid == 0 and s.st_gid == r['gid'] and
            stat.S_IMODE(s.st_mode) == 0o750, 'install directory identity drift')
    p = pwd.getpwnam(USER)
    require(p.pw_uid == r['uid'] and p.pw_gid == r['gid'] and p.pw_shell == '/usr/sbin/nologin', 'service identity drift')
    unit = props(SERVICE)
    require(unit.get('FragmentPath') == str(UNIT) and not unit.get('DropInPaths') and
            unit.get('User') == USER and unit.get('Group') == USER and
            f'{ROOT}/xray run -config {ROOT}/config.json' in unit.get('ExecStart', ''), 'loaded entry unit drift')
    pid = int(unit.get('MainPID', '0'))
    if WANTS.exists() or WANTS.is_symlink():
        parents_safe(WANTS.parent)
        s = WANTS.lstat()
        require(stat.S_ISLNK(s.st_mode) and s.st_uid == 0 and os.readlink(WANTS) == str(UNIT),
                'entry enablement link drift')
    if pid:
        proc = process(pid)
        require(proc['uid'] == r['uid'] and proc['exe'] == str(ROOT / 'xray'), 'entry process drift')
        if r.get('process'):
            require(proc == r['process'], 'entry process replaced since receipt')
    return r, pid


def fresh_credentials(m, d):
    require(not m['metadata_fixture'], 'fixture credentials cannot be installed')
    require(stage_files(d) == m, 'stage metadata drift')
    meta = read_db(m['database'])
    require(select_device(meta, m['device_id']) == m['upstream_device'] and
            (m.get('upstream_metadata', False) or endpoint_from_db(meta) == m['upstream']),
            'selected credential or upstream metadata drift')


def live_entry(d, m):
    r, pid = owned(d)
    require(not r.get('rolled_back') and r.get('process') and pid and r['process']['pid'] == pid,
            'entry is not an active resumable receipt')
    require(r['files'][str(ROOT / 'xray')]['sha'] == m['files']['xray.bin'] and
            r['files'][str(ROOT / 'config.json')]['sha'] == m['files']['xray.json'] and
            r['files'][str(UNIT)]['sha'] == sha(UNIT_TEXT.encode()), 'installed entry differs from stage')
    unit = props(SERVICE)
    require(unit.get('ActiveState') == 'active' and unit.get('LoadState') == 'loaded' and
            int(unit.get('MainPID', '0')) == pid and exec_start(unit.get('ExecStart')) ==
            {'path': str(ROOT / 'xray'), 'argv': [str(ROOT / 'xray'), 'run', '-config', str(ROOT / 'config.json')],
             'ignore_errors': 'no'} and listener_owned(pid, PORT), 'live entry unit/listener drift')


def switch_and_verify(args, m, operation):
    d = args.stage
    phase(operation + '.pre-switch-drift')
    check_drift(d); fresh_credentials(m, d); live_entry(d, m)
    check_drift(d, responses=False)
    phase(operation + '.switch')
    atomic_copy(d / 'Caddyfile.candidate', CADDY, m['files']['Caddyfile.original'])
    require(loaded() == strict_json((d / 'baseline.json').read_text())['loaded'],
            'Caddy runtime changed immediately before reload')
    run(['systemctl', 'reload', 'caddy.service'])
    phase(operation + '.verify')
    verify(args)


def recover_failed(args, operation):
    failed_phase = PHASE
    try:
        rollback(args)
    except BaseException:
        phase(failed_phase)
        raise Refuse(operation + ' failed; RECOVERY INCOMPLETE; inspect private stage without printing secrets') from None
    phase(failed_phase)
    raise Refuse(operation + ' failed; owned route/service recovery completed; private evidence retained') from None


def resume(args):
    d = args.stage
    phase('resume.guard')
    m = stage_files(d)
    require(not m['metadata_fixture'], 'fixture credentials cannot be installed')
    check_drift(d)  # Admission requires the original public route, not a partially switched route.
    live_entry(d, m)
    try:
        phase('resume.credentials')
        fresh_credentials(m, d)
        outbound_checks(d, m, 'resume')
        phase('resume.service-user-syntax')
        run(['runuser', '-u', USER, '--', str(ROOT / 'xray'), 'run', '-test', '-config', str(ROOT / 'config.json')])
        switch_and_verify(args, m, 'resume')
    except BaseException:
        recover_failed(args, 'resume')
    print('PASS resume: owned entry, authenticated TLS/Caddy/entry/Reality/foreign; old endpoints stable')


def apply(args):
    d = args.stage
    phase('apply.check')
    m = stage_files(d)
    require(not (d / 'receipt.json').exists(), 'stage already has install receipt')
    check(args)  # real outbound MUST pass before any public path changes
    phase('apply.identity')
    preflight(args)
    check_drift(d)
    fresh_credentials(m, d)
    parents_safe(ROOT.parent); parents_safe(UNIT.parent)
    # Retain all owned files/identity on recovery; no unsafe deletion or credential loss.
    save_json(d / 'receipt.json', {'manifest_sha': digest(d / 'manifest.json'), 'installed': False})
    try:
        phase('apply.install')
        import pwd
        run(['useradd', '--system', '--user-group', '--no-create-home', '--shell', '/usr/sbin/nologin', USER])
        p = pwd.getpwnam(USER)
        ROOT.mkdir(mode=0o750)
        os.chmod(ROOT, 0o750)
        os.chown(ROOT, 0, p.pw_gid)
        put(ROOT / 'xray', (d / 'xray.bin').read_bytes(), 0o750)
        put(ROOT / 'config.json', (d / 'xray.json').read_bytes(), 0o640)
        for path in (ROOT / 'xray', ROOT / 'config.json'):
            os.chown(path, 0, p.pw_gid)
        put(UNIT, UNIT_TEXT, 0o644)
        r = dict(manifest_sha=digest(d / 'manifest.json'), installed=True, uid=p.pw_uid, gid=p.pw_gid,
                 root_ino=ROOT.stat().st_ino, files={str(path): stamp(path) for path in
                 (ROOT / 'xray', ROOT / 'config.json', UNIT)})
        save_json(d / 'receipt.json', r)
        run(['systemctl', 'daemon-reload'])
        phase('apply.service-user-syntax')
        run(['runuser', '-u', USER, '--', str(ROOT / 'xray'), 'run', '-test', '-config', str(ROOT / 'config.json')])
        run(['systemctl', 'enable', '--now', SERVICE])
        phase('apply.listener')
        end = time.monotonic() + 10
        while time.monotonic() < end:
            r, pid = owned(d)
            if pid and listener_owned(pid, PORT):
                break
            time.sleep(.2)
        else:
            raise Refuse('entry service did not acquire loopback listener')
        r['process'] = process(pid)
        save_json(d / 'receipt.json', r)
        switch_and_verify(args, m, 'apply')
    except BaseException:
        recover_failed(args, 'apply')
    print('PASS apply: authenticated TLS/Caddy/entry/Reality/foreign; old endpoints stable')


def tls_outbound(m, identifier):
    return {'protocol': 'vless', 'settings': {'vnext': [{'address': '127.0.0.1', 'port': 443,
        'users': [{'id': identifier, 'encryption': 'none'}]}]},
        'streamSettings': {'network': 'xhttp', 'security': 'tls', 'tlsSettings': {'serverName': DOMAIN,
            'allowInsecure': False}, 'xhttpSettings': {'host': DOMAIN, 'path': m['path'], 'mode': 'packet-up'}}}


def verify(args, static_trial=None, admin_trial=None):
    d = args.stage
    phase('verify.identity-baseline')
    m = check_drift(d, candidate_live=True, static_trial=static_trial, admin_trial=admin_trial)
    _, pid = owned(d)
    require(pid and listener_owned(pid, PORT), 'owned entry loopback listener absent')
    phase('verify.tls-positive')
    probe_socks(d, m, tls_outbound(m, m['inbound_id']))
    phase('verify.tls-wrong-uuid')
    probe_socks(d, m, tls_outbound(m, str(uuid.uuid4())), negative=True)
    phase('verify.final-drift')
    check_drift(d, candidate_live=True, static_trial=static_trial, admin_trial=admin_trial); owned(d)
    save_json(d / 'verified.json', {'manifest_sha': digest(d / 'manifest.json'),
        'receipt_sha': digest(d / 'receipt.json'), 'at': time.time(), 'tls_auth': True,
        'wrong_uuid': True, 'egress': FOREIGN, 'endpoints_unchanged': True,
        'static_revision_sha256': digest(d / 'static-plan.json') if (d / 'static-plan.json').exists() else None,
        'admin_revision_sha256': digest(d / 'admin-plan.json') if (d / 'admin-plan.json').exists() else None})
    print('PASS verify: server-local TLS certificate/path, full authenticated traversal, wrong UUID and baseline endpoints')


def rollback(args):
    d = args.stage
    phase('rollback.baseline')
    m = stage_files(d)
    b = strict_json((d / 'baseline.json').read_text())
    expected_responses = response_expectations(d, b)
    regular(CADDY, private=False)
    require(same_caddy_identity(caddy_identity(), b['identity']), 'RECOVERY INCOMPLETE: Caddy identity drift')
    current = digest(CADDY)
    require(current in (m['files']['Caddyfile.candidate'], m['files']['Caddyfile.original']),
            'RECOVERY INCOMPLETE: unexpected Caddy disk drift')
    runtime = loaded()
    require(runtime in (adapt(d / 'Caddyfile.candidate'), b['loaded']),
            'RECOVERY INCOMPLETE: unexpected loaded Caddy drift')
    # Restore and verify original Caddy BEFORE touching the entry service.
    phase('rollback.restore-caddy')
    if current != m['files']['Caddyfile.original']:
        atomic_copy(d / 'Caddyfile.original', CADDY, current)
    if loaded() != b['loaded']:
        run(['systemctl', 'reload', 'caddy.service'])
    require(loaded() == b['loaded'] and digest(CADDY) == b['caddy_sha256'], 'RECOVERY INCOMPLETE: original Caddy not restored')
    phase('rollback.owned-service')
    r, _ = owned(d)  # modified/foreign unit is NEVER stopped, disabled or removed
    run(['systemctl', 'disable', '--now', SERVICE])
    require(props(SERVICE).get('ActiveState') == 'inactive', 'RECOVERY INCOMPLETE: owned service still active')
    require(response_baseline() == expected_responses, 'RECOVERY INCOMPLETE: baseline endpoints changed')
    # Retain disabled owned unit, root-owned credentials, binary and dedicated identity.
    r['rolled_back'] = True
    save_json(d / 'receipt.json', r)
    (d / 'verified.json').unlink(missing_ok=True)
    print('PASS rollback: original Caddy active before owned service stopped; private install/evidence retained')


def client_link(args):
    phase('export.verify')
    verify(args)  # no manual bypass; a stale attestation cannot unlock export
    m = stage_files(args.stage)
    private_dir(args.out.parent)
    link = f"vless://{m['inbound_id']}@{DOMAIN}:443?encryption=none&security=tls&sni={DOMAIN}&type=xhttp&host={DOMAIN}&path={urllib.parse.quote(m['path'], safe='')}&mode=packet-up#Mayak%20pilot"
    put(args.out, link + '\n')
    print('PASS export: fresh verification, profile written privately (0600); physical Android NOT VERIFIED')


def static_html(data, m):
    text = data.decode('utf-8')
    lower = text.lower()
    require('\x00' not in text and re.search(r'<html(?:\s|>)', lower) and '</html>' in lower,
            'static bundle must contain UTF8 HTML documents')
    require('vless://' not in lower and 'vless%3a' not in lower and
            all(value.lower() not in lower for value in (m['inbound_id'], m['upstream_device'])),
            'static HTML contains pilot credentials or profile')


def admin_html(data, m):
    """Validate an admin page without rejecting its legitimate profile generator."""
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError:
        raise Refuse('admin HTML must be UTF-8') from None
    decoded = urllib.parse.unquote(text)
    lower = decoded.lower()
    require('\x00' not in text and re.search(r'<html(?:\s|>)', lower) and '</html>' in lower,
            'admin bundle must contain a UTF-8 HTML document')
    # The page may contain code that builds vless:// links for users. Reject only
    # actual credentials from this pilot, including a URI containing either UUID.
    for value in (m['inbound_id'], m['upstream_device']):
        require(value.lower() not in lower, 'admin HTML contains pilot credentials')
    for match in re.finditer(r"vless://([^\s\"'<>`]+)", decoded, re.IGNORECASE):
        require('@' not in match.group(1), 'admin HTML contains a credential-bearing VLESS URI')


def static_bundle(path, expected, m):
    private_dir(path)
    require(set(p.name for p in path.iterdir()) == {'manifest.json', 'index.html', 'my.html'},
            'static bundle must contain exactly manifest and two HTML files')
    for p in path.iterdir():
        regular(p)
    require(isinstance(expected, str) and re.fullmatch(r'[a-f0-9]{64}', expected) and
            digest(path / 'manifest.json') == expected, 'reviewed static bundle manifest hash mismatch')
    manifest = strict_json((path / 'manifest.json').read_bytes())
    require(isinstance(manifest, dict) and set(manifest) == set(STATIC_TARGETS), 'unsupported static bundle endpoints')
    for endpoint, name in STATIC_NAMES.items():
        item = manifest[endpoint]
        require(isinstance(item, dict) and set(item) == {'old_sha256', 'new_sha256'} and
                all(isinstance(v, str) and re.fullmatch(r'[a-f0-9]{64}', v) for v in item.values()),
                'invalid explicit static old/new hashes')
        data = (path / name).read_bytes()
        require(sha(data) == item['new_sha256'], 'static bundle HTML hash mismatch')
        static_html(data, m)
    return manifest


def static_stamp(value, sha256, before=None):
    require(isinstance(value, dict) and set(value) == {'sha', 'ino', 'dev', 'uid', 'gid', 'mode'} and
            value['sha'] == sha256 and all(type(value[k]) is int for k in ('ino', 'dev', 'uid', 'gid', 'mode')) and
            value['ino'] > 0 and value['uid'] == 0 and 0 <= value['mode'] <= 0o777 and not value['mode'] & 0o022,
            'invalid static file identity stamp')
    if before is not None:
        require(all(value[k] == before[k] for k in ('dev', 'uid', 'gid', 'mode')), 'static file metadata drift')


def static_revision(d, m=None):
    if not any(p.name.startswith('static-') for p in d.iterdir()):
        return None
    for name in ('static-plan.json', 'static-state.json'):
        require((d / name).exists(), 'static transaction preparation incomplete; private evidence retained')
        regular(d / name)
    plan = strict_json((d / 'static-plan.json').read_bytes())
    state = strict_json((d / 'static-state.json').read_bytes())
    require(set(plan) == {'version', 'manifest_sha256', 'baseline_sha256', 'history', 'files'} and plan['version'] == 1 and
            set(state) == {'plan_sha256', 'status', 'restores'} and state['plan_sha256'] == digest(d / 'static-plan.json') and
            state['status'] in ('prepared', 'verifying', 'committed', 'recovering', 'rolled_back', 'recovery_incomplete') and
            isinstance(state['restores'], dict) and set(state['restores']) <= set(STATIC_TARGETS), 'invalid static transaction receipt')
    require(plan['manifest_sha256'] == digest(d / 'manifest.json') and
            plan['baseline_sha256'] == digest(d / 'baseline.json'), 'static revision belongs to different stage')
    names = {'static-baseline.json', 'static-manifest.json', 'static-verified.json', 'static-entry-receipt.json', 'static-bundle.json',
             'static-old-index.html', 'static-new-index.html', 'static-old-my.html', 'static-new-my.html'}
    require(set(plan['history']) == names and set(plan['files']) == set(STATIC_TARGETS), 'unsupported static revision history')
    for name, expected in plan['history'].items():
        regular(d / name)
        require(digest(d / name) == expected, 'immutable static history changed')
    require(plan['history']['static-baseline.json'] == plan['baseline_sha256'] and
            plan['history']['static-manifest.json'] == plan['manifest_sha256'], 'static original history mismatch')
    bundle = strict_json((d / 'static-bundle.json').read_bytes())
    require(isinstance(bundle, dict) and set(bundle) == set(STATIC_TARGETS), 'invalid static bundle history')
    m = m if m is not None else strict_json((d / 'manifest.json').read_bytes())
    baseline_responses = strict_json((d / 'baseline.json').read_bytes())['responses']
    for endpoint, name in STATIC_NAMES.items():
        item = plan['files'][endpoint]
        require(set(item) == {'old_sha256', 'new_sha256', 'before', 'after', 'temp'} and
                bundle[endpoint] == {k: item[k] for k in ('old_sha256', 'new_sha256')} and
                baseline_responses[endpoint] == {'status': '200', 'sha256': item['old_sha256']} and
                plan['history']['static-old-' + name] == item['old_sha256'] and
                plan['history']['static-new-' + name] == item['new_sha256'], 'static revision response binding mismatch')
        for kind in ('old_sha256', 'new_sha256'):
            require(isinstance(item[kind], str) and re.fullmatch(r'[a-f0-9]{64}', item[kind]), 'invalid static revision hash')
        static_stamp(item['before'], item['old_sha256'])
        static_stamp(item['after'], item['new_sha256'], item['before'])
        require(re.fullmatch(r'\.mayak-static-[A-Za-z0-9_-]+', item['temp']), 'invalid static temporary filename')
        static_html((d / ('static-new-' + name)).read_bytes(), m)
        if endpoint in state['restores']:
            restored = state['restores'][endpoint]
            require(set(restored) == {'stamp', 'temp'} and re.fullmatch(r'\.mayak-static-[A-Za-z0-9_-]+', restored['temp']),
                    'invalid static recovery receipt')
            static_stamp(restored['stamp'], item['old_sha256'], item['before'])
    return plan, state


def admin_stamp(value, sha256, before=None):
    static_stamp(value, sha256, before)


def admin_revision(d, m=None):
    names = {'admin-plan.json', 'admin-state.json', 'admin-manifest.json', 'admin-baseline.json',
             'admin-entry-receipt.json', 'admin-verified.json', 'admin-bundle-manifest.json',
             'admin-old-admin.html', 'admin-new-admin.html'}
    static_names = {'admin-static-plan.json', 'admin-static-state.json'}
    present = {p.name for p in d.iterdir() if p.name.startswith('admin-')}
    if not present:
        return None
    if m is None:
        regular(d / 'manifest.json')
        m = strict_json((d / 'manifest.json').read_bytes())
    require(present in (names, names | static_names), 'admin transaction preparation incomplete or has unknown files')
    plan_path, state_path = d / 'admin-plan.json', d / 'admin-state.json'
    plan = strict_json(plan_path.read_bytes()); state = strict_json(state_path.read_bytes())
    require(set(plan) == {'version', 'manifest_sha256', 'baseline_sha256', 'files', 'history',
                          'static_plan_sha256', 'static_state_sha256', 'reviewed_bundle_manifest_sha256'} and plan['version'] == 1 and
            set(state) == {'plan_sha256', 'status', 'restores', 'direction'} and
            state['plan_sha256'] == digest(plan_path) and
            state['status'] in ('prepared', 'verifying', 'rollback_verifying', 'committed', 'rolled_back', 'recovering', 'recovery_incomplete') and
            state['direction'] in ('publish', 'rollback') and isinstance(state['restores'], dict) and
            set(state['restores']) <= set(ADMIN_TARGETS), 'invalid admin transaction receipt')
    require(plan['manifest_sha256'] == digest(d / 'manifest.json') and
            plan['baseline_sha256'] == digest(d / 'baseline.json') and
            set(plan['files']) == set(ADMIN_TARGETS), 'admin revision belongs to different stage')
    expected_history = {'admin-manifest.json', 'admin-baseline.json', 'admin-entry-receipt.json',
                        'admin-verified.json', 'admin-bundle-manifest.json',
                        'admin-old-admin.html', 'admin-new-admin.html'}
    if plan['static_plan_sha256'] is not None:
        expected_history |= {'admin-static-plan.json', 'admin-static-state.json'}
    require(set(plan['history']) == expected_history, 'unsupported admin revision history')
    for name, expected in plan['history'].items():
        regular(d / name)
        require(digest(d / name) == expected, 'immutable admin history changed')
    require(plan['history']['admin-manifest.json'] == plan['manifest_sha256'] == digest(d / 'manifest.json') and
            plan['history']['admin-baseline.json'] == plan['baseline_sha256'] == digest(d / 'baseline.json') and
            plan['history']['admin-entry-receipt.json'] == digest(d / 'admin-entry-receipt.json') and
            plan['history']['admin-verified.json'] == digest(d / 'admin-verified.json') and
            plan['history']['admin-bundle-manifest.json'] == plan['reviewed_bundle_manifest_sha256'],
            'admin revision proof binding mismatch')
    reviewed = strict_json((d / 'admin-bundle-manifest.json').read_bytes())
    item = plan['files']['/admin/']
    require(isinstance(reviewed, dict) and set(reviewed) == {'/admin/'} and
            reviewed['/admin/'] == {'old_sha256': item['old_sha256'], 'new_sha256': item['new_sha256']} and
            plan['reviewed_bundle_manifest_sha256'] == sha((d / 'admin-bundle-manifest.json').read_bytes()),
            'reviewed admin bundle binding mismatch')
    original_receipt = strict_json((d / 'admin-entry-receipt.json').read_bytes())
    current_receipt = strict_json((d / 'receipt.json').read_bytes())
    require(original_receipt.get('manifest_sha') == plan['manifest_sha256'] and
            (current_receipt == original_receipt or
             (current_receipt.get('rolled_back') is True and
              {k: v for k, v in current_receipt.items() if k != 'rolled_back'} == original_receipt)),
            'current entry receipt drift')
    prior = strict_json((d / 'admin-verified.json').read_bytes())
    require(prior.get('manifest_sha') == plan['manifest_sha256'] and
            prior.get('receipt_sha') == plan['history']['admin-entry-receipt.json'] and
            prior.get('tls_auth') is True and prior.get('wrong_uuid') is True and
            prior.get('egress') == FOREIGN and prior.get('endpoints_unchanged') is True and
            prior.get('static_revision_sha256') == plan['static_plan_sha256'] and
            prior.get('admin_revision_sha256') in (None, ''),
            'prior admin verification proof invalid')
    require((plan['static_plan_sha256'] is None) == (plan['static_state_sha256'] is None),
            'invalid admin/static revision binding')
    if plan['static_plan_sha256'] is not None:
        require(plan['history']['admin-static-plan.json'] == plan['static_plan_sha256'] and
                plan['history']['admin-static-state.json'] == plan['static_state_sha256'] and
                (d / 'static-plan.json').exists() and (d / 'static-state.json').exists() and
                digest(d / 'static-plan.json') == plan['static_plan_sha256'],
                'admin revision static history drift')
        static_plan, static_state = static_revision(d, m)
        historical_static = strict_json((d / 'admin-static-state.json').read_bytes())
        require(historical_static == {'plan_sha256': plan['static_plan_sha256'],
                                      'status': 'committed', 'restores': {}} and
                static_state['plan_sha256'] == plan['static_plan_sha256'] and
                static_state['status'] in ('committed', 'recovering', 'recovery_incomplete', 'rolled_back'),
                'admin revision requires its accepted static revision')
        if digest(d / 'static-state.json') != plan['static_state_sha256']:
            # Only guarded static rollback may advance the captured committed
            # receipt, and only after admin rollback has completed. Pending
            # recovery remains resumable; ordinary verification rejects it.
            require(state['status'] == 'rolled_back' and state['direction'] == 'rollback' and
                    static_state['status'] in ('recovering', 'recovery_incomplete', 'rolled_back'),
                    'admin revision static state binding mismatch')
            for endpoint, target in STATIC_TARGETS.items():
                restored = static_state['restores'].get(endpoint, {}).get('stamp')
                known = [static_plan['files'][endpoint]['after']]
                if restored is not None:
                    known.append(restored)
                current = stamp(target)
                require(current in known and
                        (static_state['status'] != 'rolled_back' or current == restored),
                        'admin revision static rollback target identity drift')
    baseline = strict_json((d / 'admin-baseline.json').read_bytes())
    require(baseline.get('responses', {}).get('/admin/') ==
            {'status': '200', 'sha256': plan['files']['/admin/']['old_sha256']} and
            digest(d / 'admin-old-admin.html') == plan['files']['/admin/']['old_sha256'] and
            digest(d / 'admin-new-admin.html') == plan['files']['/admin/']['new_sha256'],
            'admin revision file history mismatch')
    item = plan['files']['/admin/']
    require(set(item) == {'old_sha256', 'new_sha256', 'before', 'after', 'temp'} and
            re.fullmatch(r'[a-f0-9]{64}', item['old_sha256']) and re.fullmatch(r'[a-f0-9]{64}', item['new_sha256']) and
            re.fullmatch(r'\.mayak-static-[A-Za-z0-9_-]+', item['temp']), 'invalid admin revision file receipt')
    admin_stamp(item['before'], item['old_sha256'])
    admin_stamp(item['after'], item['new_sha256'], item['before'])
    if '/admin/' in state['restores']:
        restored = state['restores']['/admin/']
        require(set(restored) == {'stamp', 'temp'} and
                re.fullmatch(r'\.mayak-static-[A-Za-z0-9_-]+', restored['temp']), 'invalid admin recovery receipt')
        admin_stamp(restored['stamp'], item['old_sha256'], item['before'])
    admin_html((d / 'admin-new-admin.html').read_bytes(), m)
    return plan, state


def response_expectations(d, b, static_trial=None, admin_trial=None):
    revision = static_revision(d)
    responses = dict(b['responses'])
    if revision is None:
        pass
    else:
        plan, state = revision
        new = state['status'] == 'committed' or (state['status'] == 'verifying' and static_trial == digest(d / 'static-plan.json'))
        require(new or state['status'] == 'rolled_back', 'static transaction pending; run guarded rollback-static')
        for endpoint, target in STATIC_TARGETS.items():
            item = plan['files'][endpoint]
            expected = item['after'] if new else state['restores'].get(endpoint, {}).get('stamp', item['before'])
            require(stamp(target) == expected, 'static target file identity drift')
            responses[endpoint] = {'status': '200', 'sha256': item['new_sha256' if new else 'old_sha256']}
    revision = admin_revision(d)
    if revision is None:
        return responses
    plan, state = revision
    revision_sha = digest(d / 'admin-plan.json')
    publish_trial = admin_trial == revision_sha
    rollback_trial = admin_trial == 'rollback:' + revision_sha
    new = state['status'] == 'committed' or (state['status'] == 'verifying' and publish_trial)
    old = state['status'] in ('prepared', 'rolled_back') or (state['status'] == 'rollback_verifying' and rollback_trial)
    require(new or old, 'admin transaction pending; run guarded rollback-admin')
    item = plan['files']['/admin/']
    target = ADMIN_TARGETS['/admin/']
    expected = item['after'] if new else state['restores'].get('/admin/', {}).get('stamp', item['before'])
    require(stamp(target) == expected, 'admin target file identity drift')
    responses['/admin/'] = {'status': '200', 'sha256': item['new_sha256'] if new else item['old_sha256']}
    return responses


def static_temp(source, target, before):
    regular(source)
    require(stamp(target) == before, 'static target drift before temporary preparation')
    fd, name = tempfile.mkstemp(dir=target.parent, prefix='.mayak-static-')
    path = pathlib.Path(name)
    try:
        with os.fdopen(fd, 'wb') as f:
            os.fchown(f.fileno(), before['uid'], before['gid'])
            os.fchmod(f.fileno(), before['mode'])
            f.write(source.read_bytes()); f.flush(); os.fsync(f.fileno())
        return path, stamp(path)
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def static_sync(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def static_move(source, target, source_stamp, target_stamp):
    require(stamp(source) == source_stamp and stamp(target) == target_stamp, 'static source/target drift before atomic replace')
    os.replace(source, target)
    static_sync(target.parent)
    require(stamp(target) == source_stamp, 'static target drift after atomic replace')


def static_restore(args):
    d = args.stage
    m = check_drift(d, candidate_live=True, responses=False)
    live_entry(d, m)
    revision = static_revision(d, m)
    require(revision is not None, 'no static transaction to recover')
    admin = admin_revision(d, m)
    require(admin is None or admin[1]['status'] == 'rolled_back',
            'admin revision is active or pending; rollback-admin must run first')
    plan, state = revision
    # Check BOTH targets before restoring either. Only recorded inode/hash/metadata
    # identities are owned, including a crash after rename but before receipt update.
    current = {endpoint: stamp(target) for endpoint, target in STATIC_TARGETS.items()}
    for endpoint, item in plan['files'].items():
        known = [item['before'], item['after']]
        if endpoint in state['restores']:
            known.append(state['restores'][endpoint]['stamp'])
        require(current[endpoint] in known, 'RECOVERY INCOMPLETE: unexpected static target drift')
    state['status'] = 'recovering'
    save_json(d / 'static-state.json', state)
    static_sync(d)
    for endpoint, target in STATIC_TARGETS.items():
        item = plan['files'][endpoint]
        if current[endpoint] == item['after']:
            tmp, restored = static_temp(d / ('static-old-' + STATIC_NAMES[endpoint]), target, current[endpoint])
            state['restores'][endpoint] = {'stamp': restored, 'temp': tmp.name}
            save_json(d / 'static-state.json', state)  # durable ownership BEFORE rename
            static_sync(d)
            static_move(tmp, target, restored, current[endpoint])
        tmp = target.parent / item['temp']
        if tmp.exists():
            require(stamp(tmp) == item['after'], 'RECOVERY INCOMPLETE: unexpected static temporary drift')
            tmp.unlink()
    require(response_baseline() == strict_json((d / 'baseline.json').read_bytes())['responses'],
            'RECOVERY INCOMPLETE: restored static HTTP responses differ')
    state['status'] = 'rolled_back'
    save_json(d / 'static-state.json', state)
    static_sync(d)
    verify(args)


def rollback_static(args):
    phase('static.rollback')
    # Refuse an active admin overlay before entering the recovery handler. The
    # handler journals recovery failures; a predictable ordering refusal is not
    # a recovery failure and must leave the prior static receipt untouched.
    m = stage_files(args.stage)
    admin = admin_revision(args.stage, m)
    require(admin is None or admin[1]['status'] == 'rolled_back',
            'admin revision is active or pending; rollback-admin must run first')
    try:
        static_restore(args)
    except BaseException:
        static_incomplete(args.stage)
        raise Refuse('static rollback RECOVERY INCOMPLETE; private history retained') from None
    print('PASS rollback-static: exact owned HTML restored; full VPN/endpoint verification passed')


def static_incomplete(d):
    # Keep the last durable ownership journal even if the diagnostic write fails.
    try:
        _, state = static_revision(d)
        state['status'] = 'recovery_incomplete'
        save_json(d / 'static-state.json', state)
        static_sync(d)
    except BaseException:
        pass


def update_static(args):
    d = args.stage
    phase('static.verify-before')
    verify(args)  # full existing positive+negative VPN and old HTTP verification first
    m = stage_files(d)
    require(static_revision(d, m) is None, 'static revision already exists; repeat publish refused')
    require(admin_revision(d, m) is None, 'admin revision exists; static update refused')
    live_entry(d, m); fresh_credentials(m, d)
    bundle = static_bundle(args.bundle, args.bundle_sha256, m)
    b = strict_json((d / 'baseline.json').read_bytes())
    before = {endpoint: stamp(target) for endpoint, target in STATIC_TARGETS.items()}
    for endpoint, item in bundle.items():
        require((before[endpoint]['uid'], before[endpoint]['gid'], before[endpoint]['mode']) == (0, 986, 0o640),
                'unexpected static target ownership/mode')
        require(before[endpoint]['sha'] == item['old_sha256'] and
                b['responses'][endpoint] == {'status': '200', 'sha256': item['old_sha256']}, 'static target/HTTP old identity mismatch')
    phase('static.prepare-history')
    history = {}
    for source, name in [('baseline.json', 'static-baseline.json'), ('manifest.json', 'static-manifest.json'),
                         ('verified.json', 'static-verified.json'), ('receipt.json', 'static-entry-receipt.json')]:
        regular(d / source)
        put(d / name, (d / source).read_bytes()); history[name] = digest(d / name)
    put(d / 'static-bundle.json', (args.bundle / 'manifest.json').read_bytes())
    history['static-bundle.json'] = digest(d / 'static-bundle.json')
    files = {}
    for endpoint, target in STATIC_TARGETS.items():
        name = STATIC_NAMES[endpoint]
        put(d / ('static-old-' + name), target.read_bytes())
        put(d / ('static-new-' + name), (args.bundle / name).read_bytes())
        for prefix in ('old', 'new'):
            history['static-' + prefix + '-' + name] = digest(d / ('static-' + prefix + '-' + name))
        require(history['static-old-' + name] == bundle[endpoint]['old_sha256'] and
                history['static-new-' + name] == bundle[endpoint]['new_sha256'], 'static files changed during snapshot')
        tmp, after = static_temp(d / ('static-new-' + name), target, before[endpoint])
        files[endpoint] = dict(bundle[endpoint], before=before[endpoint], after=after, temp=tmp.name)
    plan = dict(version=1, manifest_sha256=digest(d / 'manifest.json'), baseline_sha256=digest(d / 'baseline.json'), history=history, files=files)
    put(d / 'static-plan.json', json.dumps(plan, sort_keys=True))
    state = dict(plan_sha256=digest(d / 'static-plan.json'), status='prepared', restores={})
    put(d / 'static-state.json', json.dumps(state, sort_keys=True))
    static_sync(d)
    try:
        phase('static.pre-switch')
        check_drift(d, candidate_live=True, responses=False); live_entry(d, m); fresh_credentials(m, d)
        require(response_baseline() == b['responses'], 'static pre-switch endpoint drift')
        for endpoint, target in STATIC_TARGETS.items():
            require(stamp(target) == before[endpoint], 'static target drift before publish')
        phase('static.publish')
        for endpoint, target in STATIC_TARGETS.items():
            item = files[endpoint]
            static_move(target.parent / item['temp'], target, item['after'], item['before'])
        state['status'] = 'verifying'
        save_json(d / 'static-state.json', state)
        static_sync(d)
        phase('static.verify-new')
        verify(args, static_trial=state['plan_sha256'])
        state['status'] = 'committed'
        save_json(d / 'static-state.json', state)
        static_sync(d)
        check_drift(d, candidate_live=True); live_entry(d, m)
    except BaseException:
        try:
            static_restore(args)
        except BaseException:
            static_incomplete(d)
            raise Refuse('static publish failed; RECOVERY INCOMPLETE; private history retained') from None
        raise Refuse('static publish failed; owned HTML restored and fully verified') from None
    print('PASS update-static: exact two HTML responses accepted; original baseline/history and full VPN verification retained')


def admin_bundle(path, expected, m):
    private_dir(path)
    require(set(p.name for p in path.iterdir()) == {'manifest.json', 'admin.html'},
            'admin bundle must contain exactly manifest and admin.html')
    for p in path.iterdir(): regular(p)
    manifest_data = (path / 'manifest.json').read_bytes()
    require(isinstance(expected, str) and re.fullmatch(r'[a-f0-9]{64}', expected) and
            sha(manifest_data) == expected, 'reviewed admin manifest hash mismatch')
    manifest = strict_json(manifest_data)
    require(isinstance(manifest, dict) and set(manifest) == set(ADMIN_TARGETS), 'unsupported admin bundle endpoints')
    item = manifest['/admin/']
    require(isinstance(item, dict) and set(item) == {'old_sha256', 'new_sha256'} and
            all(isinstance(v, str) and re.fullmatch(r'[a-f0-9]{64}', v) for v in item.values()),
            'invalid explicit admin old/new hashes')
    data = (path / 'admin.html').read_bytes()
    require(sha(data) == item['new_sha256'], 'admin bundle HTML hash mismatch')
    admin_html(data, m)
    return manifest


def admin_incomplete(d):
    try:
        _, state = admin_revision(d)
        state['status'] = 'recovery_incomplete'
        save_json(d / 'admin-state.json', state)
        static_sync(d)
    except BaseException:
        pass


def admin_restore(args):
    d = args.stage
    m = stage_files(d)
    revision = admin_revision(d, m)
    require(revision is not None, 'no admin transaction to recover')
    # Validate the live entry and Caddy identity before writing the recovery
    # journal or touching the public file, including interrupted transactions.
    check_drift(d, candidate_live=True, responses=False)
    live_entry(d, m)
    plan, state = revision
    target = ADMIN_TARGETS['/admin/']
    item = plan['files']['/admin/']
    current = stamp(target)
    known = [item['before'], item['after']]
    if '/admin/' in state['restores']:
        known.append(state['restores']['/admin/']['stamp'])
    require(current in known, 'RECOVERY INCOMPLETE: unexpected admin target drift')
    state['direction'] = 'rollback'
    state['status'] = 'recovering'
    save_json(d / 'admin-state.json', state)
    static_sync(d)
    if current == item['after']:
        tmp, restored = static_temp(d / 'admin-old-admin.html', target, current)
        state['restores']['/admin/'] = {'stamp': restored, 'temp': tmp.name}
        save_json(d / 'admin-state.json', state)
        static_sync(d)
        static_move(tmp, target, restored, current)
    tmp = target.parent / item['temp']
    if tmp.exists():
        require(stamp(tmp) == item['after'], 'RECOVERY INCOMPLETE: unexpected admin temporary drift')
        tmp.unlink()
    state['status'] = 'rollback_verifying'
    save_json(d / 'admin-state.json', state)
    static_sync(d)
    verify(args, admin_trial='rollback:' + digest(d / 'admin-plan.json'))
    state['status'] = 'rolled_back'
    save_json(d / 'admin-state.json', state)
    static_sync(d)
    check_drift(d, candidate_live=True); live_entry(d, m)


def rollback_admin(args):
    d = args.stage
    phase('admin.rollback')
    m = stage_files(d)
    revision = admin_revision(d, m)
    require(revision is not None, 'no admin transaction to recover')
    require(revision[1]['status'] != 'rolled_back', 'admin revision is already rolled back')
    if revision[1]['status'] == 'committed':
        verify(args)
    else:
        check_drift(d, candidate_live=True, responses=False)
        live_entry(d, m)
    try:
        admin_restore(args)
    except BaseException:
        admin_incomplete(d)
        raise Refuse('admin rollback RECOVERY INCOMPLETE; private history retained') from None
    print('PASS rollback-admin: exact prior admin HTML restored; full VPN and protected endpoint verification passed')


def update_admin(args):
    d = args.stage
    phase('admin.verify-before')
    verify(args)
    m = stage_files(d)
    require(admin_revision(d, m) is None, 'admin revision already exists; repeat publish refused')
    live_entry(d, m); fresh_credentials(m, d)
    bundle = admin_bundle(args.bundle, args.bundle_sha256, m)
    b = strict_json((d / 'baseline.json').read_bytes())
    target = ADMIN_TARGETS['/admin/']
    before = stamp(target)
    require((before['uid'], before['gid'], before['mode']) == (0, 986, 0o640),
            'unexpected admin target ownership/mode')
    require(before['sha'] == bundle['/admin/']['old_sha256'] and
            b['responses']['/admin/'] == {'status': '200', 'sha256': before['sha']},
            'admin target/HTTP old identity mismatch')
    phase('admin.prepare-history')
    regular(args.bundle / 'manifest.json')
    manifest_data = (args.bundle / 'manifest.json').read_bytes()
    require(sha(manifest_data) == args.bundle_sha256, 'reviewed admin manifest hash mismatch')
    history = {}
    sources = [('baseline.json', 'admin-baseline.json'), ('manifest.json', 'admin-manifest.json'),
               ('receipt.json', 'admin-entry-receipt.json'), ('verified.json', 'admin-verified.json')]
    if (d / 'static-plan.json').exists() or (d / 'static-state.json').exists():
        require((d / 'static-plan.json').exists() and (d / 'static-state.json').exists(),
                'incomplete static revision; admin publish refused')
        _, static_state = static_revision(d, m)
        require(static_state['status'] == 'committed', 'admin publish requires committed static UI')
        sources += [('static-plan.json', 'admin-static-plan.json'), ('static-state.json', 'admin-static-state.json')]
    for source, name in sources:
        regular(d / source); put(d / name, (d / source).read_bytes()); history[name] = digest(d / name)
    put(d / 'admin-bundle-manifest.json', manifest_data)
    history['admin-bundle-manifest.json'] = digest(d / 'admin-bundle-manifest.json')
    put(d / 'admin-old-admin.html', target.read_bytes())
    put(d / 'admin-new-admin.html', (args.bundle / 'admin.html').read_bytes())
    for name in ('admin-old-admin.html', 'admin-new-admin.html'):
        history[name] = digest(d / name)
    require(history['admin-old-admin.html'] == bundle['/admin/']['old_sha256'] and
            history['admin-new-admin.html'] == bundle['/admin/']['new_sha256'],
            'admin files changed during snapshot')
    tmp, after = static_temp(d / 'admin-new-admin.html', target, before)
    files = {'/admin/': dict(bundle['/admin/'], before=before, after=after, temp=tmp.name)}
    static_sha = digest(d / 'static-plan.json') if (d / 'static-plan.json').exists() else None
    static_state_sha = digest(d / 'static-state.json') if static_sha is not None else None
    plan = dict(version=1, manifest_sha256=digest(d / 'manifest.json'), baseline_sha256=digest(d / 'baseline.json'),
                files=files, history=history, static_plan_sha256=static_sha, static_state_sha256=static_state_sha,
                reviewed_bundle_manifest_sha256=history['admin-bundle-manifest.json'])
    put(d / 'admin-plan.json', json.dumps(plan, sort_keys=True))
    state = dict(plan_sha256=digest(d / 'admin-plan.json'), status='prepared', restores={}, direction='publish')
    put(d / 'admin-state.json', json.dumps(state, sort_keys=True))
    static_sync(d); static_sync(target.parent)
    try:
        phase('admin.pre-switch')
        check_drift(d, candidate_live=True, responses=False); live_entry(d, m); fresh_credentials(m, d)
        require(response_baseline() == response_expectations(d, b), 'admin pre-switch endpoint drift')
        require(stamp(target) == before, 'admin target drift before publish')
        phase('admin.publish')
        static_move(target.parent / tmp.name, target, after, before)
        state['status'] = 'verifying'
        save_json(d / 'admin-state.json', state); static_sync(d)
        phase('admin.verify-new')
        verify(args, admin_trial=state['plan_sha256'])
        state['status'] = 'committed'
        save_json(d / 'admin-state.json', state); static_sync(d)
        check_drift(d, candidate_live=True); live_entry(d, m)
    except BaseException:
        try:
            admin_restore(args)
        except BaseException:
            admin_incomplete(d)
            raise Refuse('admin publish failed; RECOVERY INCOMPLETE; private history retained') from None
        raise Refuse('admin publish failed; owned HTML restored and fully verified') from None
    print('PASS update-admin: exact /admin/ response accepted; original baseline/static history and full VPN verification retained')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='cmd', required=True)
    q = sub.add_parser('preflight'); q.set_defaults(fn=preflight)
    q = sub.add_parser('prepare'); q.add_argument('--archive', type=pathlib.Path, required=True); q.add_argument('--out', type=pathlib.Path, required=True); q.set_defaults(fn=prepare)
    q = sub.add_parser('stage'); q.add_argument('--metadata', type=pathlib.Path); q.add_argument('--upstream-metadata', type=pathlib.Path); q.add_argument('--database', default='mayak'); q.add_argument('--device-id'); q.add_argument('--xray-bin', type=pathlib.Path, required=True)
    g = q.add_mutually_exclusive_group(required=True); g.add_argument('--sha256'); g.add_argument('--sha256-file', type=pathlib.Path)
    q.add_argument('--out', type=pathlib.Path, required=True); q.set_defaults(fn=stage)
    for name, fn in [('check', check), ('apply', apply), ('resume', resume), ('rollback', rollback), ('verify', verify), ('client-link', client_link)]:
        q = sub.add_parser(name); q.add_argument('--stage', type=pathlib.Path, required=True); q.set_defaults(fn=fn)
        if name == 'client-link': q.add_argument('--out', type=pathlib.Path, required=True)
    for name, fn in [('update-static', update_static), ('rollback-static', rollback_static),
                     ('update-admin', update_admin), ('rollback-admin', rollback_admin)]:
        q = sub.add_parser(name); q.add_argument('--stage', type=pathlib.Path, required=True); q.set_defaults(fn=fn)
        if name == 'update-static':
            q.add_argument('--bundle', type=pathlib.Path, required=True); q.add_argument('--bundle-sha256', required=True)
        if name == 'update-admin':
            q.add_argument('--bundle', type=pathlib.Path, required=True); q.add_argument('--bundle-sha256', required=True)
    args = p.parse_args()
    try:
        require(sys.platform.startswith('linux') and os.geteuid() == 0, 'run as root on target Linux')
        os.umask(0o077)
        with lock():
            args.fn(args)
    except (Refuse, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, zipfile.BadZipFile) as e:
        reason = str(e) if isinstance(e, Refuse) else 'target operation failed (details suppressed)'
        print('FAIL ' + PHASE + ': ' + reason, file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
