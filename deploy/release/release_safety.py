#!/usr/bin/env python3
"""Small fail-closed predicates for the release entry point. Never print inputs."""
from __future__ import annotations

import json
import os
import pathlib
import re
import socket
import subprocess
import sys
import tarfile
import hashlib


def connection_parts(text: str) -> dict[str, str]:
    """Supported Npgsql key=value syntax, including doubled single/double quotes.

    Delimiters inside quoted values have no syntactic meaning. Unsupported keys,
    duplicates (including aliases), and ambiguous/unfinished syntax are refused.
    """
    aliases = {'host': 'host', 'server': 'host', 'port': 'port',
               'database': 'database', 'initial catalog': 'database',
               'username': 'username', 'user id': 'username', 'user': 'username',
               'password': 'password', 'pwd': 'password'}
    result = {}
    pos, size = 0, len(text)
    while pos < size:
        while pos < size and (text[pos].isspace() or text[pos] == ';'):
            pos += 1
        if pos == size:
            break
        start = pos
        while pos < size and text[pos] not in '=;':
            pos += 1
        if pos == size or text[pos] != '=':
            raise ValueError
        key = aliases.get(text[start:pos].strip().lower())
        if key is None or key in result:
            raise ValueError
        pos += 1
        while pos < size and text[pos].isspace():
            pos += 1
        if pos < size and text[pos] in ('"', "'"):
            quote = text[pos]
            pos += 1
            value = []
            while True:
                if pos == size:
                    raise ValueError
                char = text[pos]
                pos += 1
                if char == quote:
                    if pos < size and text[pos] == quote:
                        value.append(quote)
                        pos += 1
                    else:
                        break
                else:
                    value.append(char)
            while pos < size and text[pos].isspace():
                pos += 1
            if pos < size and text[pos] != ';':
                raise ValueError
            value = ''.join(value)
        else:
            start = pos
            while pos < size and text[pos] != ';':
                pos += 1
            value = text[start:pos].strip()
            if any(c in value for c in ('"', "'")):
                raise ValueError
        result[key] = value
    return result


def unique_object(pairs):
    out = {}
    for key, value in pairs:
        if key.lower() in {k.lower() for k in out}:
            raise ValueError
        out[key] = value
    return out


def database_settings(config: pathlib.Path) -> dict[str, str]:
    data = json.loads(config.read_text(encoding='utf-8-sig'), object_pairs_hook=unique_object)
    # ASP.NET accepts flattened/case-insensitive keys. This baseline deliberately
    # refuses flattened alternatives rather than guessing their precedence.
    if not isinstance(data, dict) or any(':' in k for k in data):
        raise ValueError
    data = {k.lower(): v for k, v in data.items()}
    section = data.get('connectionstrings')
    if not isinstance(section, dict):
        raise ValueError
    section = {k.lower(): v for k, v in section.items()}
    text = section.get('db')
    if not isinstance(text, str):
        raise ValueError
    parts = connection_parts(text)
    if (parts.get('host') not in ('localhost', '127.0.0.1', '/var/run/postgresql') or
            parts.get('port', '5432') != '5432' or parts.get('username') != 'mayak' or
            not re.fullmatch(r'[A-Za-z0-9_]{1,63}', parts.get('database', ''))):
        raise ValueError
    return parts


def database_name(config: pathlib.Path) -> str:
    return database_settings(config)['database']


def database_identity(config: pathlib.Path):
    parts = database_settings(config)
    db = parts['database']
    sql = ("SELECT current_database() || ':' || oid::text || ':' || current_setting('port') || ':' || "
           "extract(epoch from pg_postmaster_start_time())::text FROM pg_database WHERE datname=current_database()")
    common = ['psql', '-X', '-A', '-t', '-v', 'ON_ERROR_STOP=1', '--no-password', '--port=5432', '--dbname=' + db, '-c', sql]
    local = output(['runuser', '-u', 'postgres', '--', *common, '--host=/var/run/postgresql', '--username=postgres']).strip()
    if not local:
        raise ValueError
    if parts['host'] == '/var/run/postgresql':
        return
    # Probe every address the API could select. A second local cluster, an
    # unreachable/foreign localhost resolution, or missing auth must refuse.
    addresses = {row[4][0] for row in socket.getaddrinfo(parts['host'], 5432, type=socket.SOCK_STREAM)}
    if not addresses or not addresses.issubset({'127.0.0.1', '::1'}):
        raise ValueError
    password = parts.get('password')
    if password is None or '\n' in password or '\r' in password or not hasattr(os, 'memfd_create'):
        raise ValueError
    # An anonymous Linux FD supplies libpq's password file. No credential is
    # written to disk, argv, environment values, diagnostics, or stdout.
    fd = os.memfd_create('mayak-release-pgpass', flags=os.MFD_CLOEXEC)
    try:
        os.fchmod(fd, 0o600)
        escape = lambda value: value.replace('\\', '\\\\').replace(':', '\\:')
        payload = ''.join(':'.join(map(escape, [host, '5432', db, 'mayak', password])) + '\n' for host in sorted(addresses))
        os.write(fd, payload.encode())
        os.lseek(fd, 0, os.SEEK_SET)
        environment = {k: v for k, v in os.environ.items() if not k.upper().startswith('PG')}
        environment['PGPASSFILE'] = '/proc/self/fd/' + str(fd)
        for host in sorted(addresses):
            actual = subprocess.check_output([*common, '--host=' + host, '--username=mayak'],
                stderr=subprocess.DEVNULL, text=True, timeout=15, env=environment, pass_fds=(fd,)).strip()
            if actual != local:
                raise ValueError
    finally:
        os.close(fd)


def candidate_endpoint(config: pathlib.Path) -> str:
    data = json.loads(config.read_text(encoding='utf-8-sig'), object_pairs_hook=unique_object)
    data = {k.lower(): v for k, v in data.items()}
    kestrel = data.get('kestrel', {})
    if not isinstance(kestrel, dict) or any(k.lower() != 'endpoints' for k in kestrel):
        raise ValueError
    kestrel = {k.lower(): v for k, v in kestrel.items()}
    endpoints = kestrel.get('endpoints', {})
    if not isinstance(endpoints, dict) or len(endpoints) > 1:
        raise ValueError
    for name, options in endpoints.items():
        if (not re.fullmatch(r'[A-Za-z][A-Za-z0-9-]{0,63}', name) or
                not isinstance(options, dict) or {k.lower() for k in options} != {'url'} or
                next(iter(options.values())) != 'http://127.0.0.1:5080'):
            raise ValueError
        return name
    return ''


def output(argv):
    return subprocess.check_output(argv, stderr=subprocess.DEVNULL, text=True, timeout=30)


def caddy_baseline(path: str):
    raw = pathlib.Path(path).read_bytes()
    if hashlib.sha256(raw).hexdigest() == '4371021453096fa9990acaedc0fb23fb18950e46f7199a70ebfdb553ff4e5353':
        return
    text = raw.decode('utf-8')
    text = re.sub(r'(?m)^\s*#.*$', '', text)
    text = re.sub(r'\s+', ' ', text).strip()
    base = r'mayaklight\.ru\s*\{\s*(?:encode gzip\s+)?reverse_proxy 127\.0\.0\.1:5080\s*\}'
    static = r'mayaklight\.ru\s*\{\s*(?:encode gzip\s+)?handle /updates/\* \{\s*root \* /opt/mayak/static\s+file_server\s*\}\s*reverse_proxy 127\.0\.0\.1:5080\s*\}'
    if not (re.fullmatch(base, text) or re.fullmatch(static, text)):
        raise ValueError


def caddy_config(path: str):
    caddy_baseline(path)
    expected = json.loads(output(['caddy', 'adapt', '--config', path, '--adapter', 'caddyfile']))
    loaded = json.loads(output(['curl', '--noproxy', '*', '--fail', '--silent', '--max-time', '4',
                               'http://127.0.0.1:2019/config/']))
    if not isinstance(expected, dict) or loaded != expected:
        raise ValueError
    if expected.get('admin', {}).get('listen', 'localhost:2019') not in ('localhost:2019', '127.0.0.1:2019'):
        raise ValueError
    servers = expected.get('apps', {}).get('http', {}).get('servers', {})
    if not servers or any(s.get('logs') for s in servers.values()):
        raise ValueError


def caddy_hash(path: str, expected: str):
    if not re.fullmatch(r'[0-9a-f]{64}', expected):
        raise ValueError
    if hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest() != expected:
        raise ValueError


PRESERVED_OVERLAYS = {
    'wwwroot/index.html': 'e695c41bbe2130791262ceba4d35429b9b1733e1c39d135e8c4a14c2c89257bd',
    'wwwroot/my/index.html': 'b4fae4de1b1ddd720e927e409bcd40c3eb6d934a4f7928998e5d762eb97d3e55',
    'wwwroot/admin/index.html': '54599890493e816159ef60f1795cd65ed2704b8e7632335f43212de4201981e5',
}


def overlays_match(api_root: pathlib.Path):
    for relative, expected in PRESERVED_OVERLAYS.items():
        path = api_root / relative
        if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError


PRIOR_MIGRATIONS = [
    '20261027112717_Initial', '20261027141625_Invites', '20261027142901_Portal',
    '20261028084612_LoginReturn', '20261028170000_DeviceSubscriptions',
    '20261028210000_VlessPool', '20261028220000_PoolCredentialsSnapshot',
    '20261029200000_ServerProvisioning', '20261029210000_ProvisioningReadiness',
]
ADDITIVE_MIGRATIONS = ['20261030120000_EmailPasswordCredentials', '20261030170000_TodayAdmission']


def fixture_state(database: str):
    db = re.fullmatch(r'[A-Za-z0-9_]{1,63}', database)
    if db is None:
        raise ValueError
    def query(sql):
        return output(['runuser', '-u', 'postgres', '--', 'psql', '-X', '-A', '-t', '-F', '\t',
                       '-v', 'ON_ERROR_STOP=1', '--host=/var/run/postgresql', '--port=5432',
                       '--username=postgres', '--no-password', '--dbname=' + database, '-c', sql]).strip()
    migrations = query('SELECT "MigrationId" FROM "__EFMigrationsHistory" ORDER BY "MigrationId"').splitlines()
    tables = query("SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename").splitlines()
    counts = {}
    identities = {}
    for table in tables:
        ident = '"' + table.replace('"', '""') + '"'
        counts[table] = int(query('SELECT count(*) FROM ' + ident))
        if table in ('Accounts', 'Devices', 'Servers', 'Clusters', 'ExitEndpoints', 'AwgAllocations'):
            identities[table] = query('SELECT COALESCE(string_agg("Id"::text, chr(10) ORDER BY "Id"::text), \'\') FROM ' + ident)
        elif table == 'Sessions':
            identities[table] = query('SELECT COALESCE(string_agg("TokenHash", chr(10) ORDER BY "TokenHash"), \'\') FROM ' + ident)
    interrupted = int(query("SELECT count(*) FROM \"Servers\" WHERE \"ProvisioningStatus\" IN ('queued','preflight','installing','installing_awg','installing_xray','installing_agent','awaiting_agent','syncing')"))
    columns = query("SELECT table_name || '.' || column_name || ':' || data_type || ':' || COALESCE(character_maximum_length::text,'') || ':' || is_nullable FROM information_schema.columns WHERE table_schema='public' AND ((table_name='Accounts' AND column_name IN ('LoginEmailNormalized','PasswordHash')) OR (table_name='Devices' AND column_name='AutoConnectManaged') OR (table_name='Servers' AND column_name IN ('AutoSelectEnabled','NativeCapacity','ExpectedEgressIpsJson')) OR table_name='AwgAllocations') ORDER BY table_name,column_name").splitlines()
    return {'migrations': migrations, 'tables': tables, 'counts': counts,
            'identities': identities, 'interrupted': interrupted, 'columns': columns}


def fixture_snapshot(database: str, destination: pathlib.Path):
    state = fixture_state(database)
    if state['migrations'] not in (PRIOR_MIGRATIONS, PRIOR_MIGRATIONS + ADDITIVE_MIGRATIONS):
        raise ValueError
    if state['interrupted']:
        raise ValueError
    destination.write_text(json.dumps(state, sort_keys=True), encoding='utf-8')


def fixture_verify(database: str, baseline_path: pathlib.Path):
    baseline = json.loads(baseline_path.read_text(encoding='utf-8'))
    state = fixture_state(database)
    prior = baseline['migrations']
    expected = prior if prior == PRIOR_MIGRATIONS + ADDITIVE_MIGRATIONS else PRIOR_MIGRATIONS + ADDITIVE_MIGRATIONS
    if state['migrations'] != expected or state['interrupted']:
        raise ValueError
    before_tables, after_tables = set(baseline['tables']), set(state['tables'])
    if prior == PRIOR_MIGRATIONS:
        if after_tables - before_tables != {'AwgAllocations'}:
            raise ValueError
        if state['counts'].get('AwgAllocations') != 0:
            raise ValueError
    elif after_tables != before_tables:
        raise ValueError
    if any(state['counts'].get(name) != count for name, count in baseline['counts'].items()
           if name != '__EFMigrationsHistory'):
        raise ValueError
    if any(state['identities'].get(name) != value for name, value in baseline['identities'].items()):
        raise ValueError
    expected_columns = {
        'Accounts.LoginEmailNormalized:character varying:254:YES', 'Accounts.PasswordHash:text::YES',
        'Devices.AutoConnectManaged:boolean::NO', 'Servers.AutoSelectEnabled:boolean::NO',
        'Servers.ExpectedEgressIpsJson:text::NO', 'Servers.NativeCapacity:integer::NO',
        'AwgAllocations.AttemptId:character varying:128:NO', 'AwgAllocations.CreatedAt:timestamp with time zone::NO',
        'AwgAllocations.DeviceId:uuid::NO', 'AwgAllocations.Id:uuid::NO',
        'AwgAllocations.ProvenAt:timestamp with time zone::YES', 'AwgAllocations.ReleasedAt:timestamp with time zone::YES',
        'AwgAllocations.ServerId:uuid::NO',
    }
    if set(state['columns']) != expected_columns:
        raise ValueError


def fixture_contract(action: str, database: str, path: pathlib.Path):
    if action == 'fixture-snapshot':
        fixture_snapshot(database, path)
    else:
        fixture_verify(database, path)


def journal_canary(token: str):
    if not re.fullmatch(r'[A-Za-z0-9_-]{40,64}', token):
        raise ValueError
    # Read failures propagate separately from a successful absence observation.
    for unit in ('mayak-api.service', 'caddy.service'):
        log = output(['journalctl', '-u', unit, '--since', '-2 minutes', '--no-pager', '--quiet'])
        if token in log:
            raise ValueError


def extract_snapshot(archive_path: pathlib.Path, target: pathlib.Path):
    # Never allow a retained tar to write links/devices or escape its stage.
    if target.is_symlink() or (target.exists() and any(target.iterdir())):
        raise ValueError
    with tarfile.open(archive_path, 'r:gz') as archive:
        names = set()
        members = archive.getmembers()
        for member in members:
            path = pathlib.PurePosixPath(member.name)
            if (path.is_absolute() or '..' in path.parts or '\\' in member.name or
                    not (member.isfile() or member.isdir()) or path.as_posix() in names):
                raise ValueError
            names.add(path.as_posix())
        if 'mayak-api.dll' not in names or 'mayak-api.runtimeconfig.json' not in names:
            raise ValueError
        target.mkdir(parents=True, exist_ok=True)
        for member in members:
            path = target.joinpath(*pathlib.PurePosixPath(member.name).parts)
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError
                with stream, path.open('xb') as destination:
                    while block := stream.read(1024 * 1024):
                        destination.write(block)
    runtime = json.loads((target / 'mayak-api.runtimeconfig.json').read_text())
    if runtime.get('runtimeOptions', {}).get('tfm') != 'net10.0':
        raise ValueError


def main():
    try:
        action = sys.argv[1]
        if action == 'database' and len(sys.argv) == 3:
            print(database_name(pathlib.Path(sys.argv[2])))
        elif action == 'database-identity' and len(sys.argv) == 3:
            database_identity(pathlib.Path(sys.argv[2]))
        elif action == 'candidate-endpoint' and len(sys.argv) == 3:
            print(candidate_endpoint(pathlib.Path(sys.argv[2])))
        elif action == 'caddy-config' and len(sys.argv) == 3:
            caddy_config(sys.argv[2])
        elif action == 'caddy-baseline' and len(sys.argv) == 3:
            caddy_baseline(sys.argv[2])
        elif action == 'caddy-hash' and len(sys.argv) == 4:
            caddy_hash(sys.argv[2], sys.argv[3])
        elif action == 'overlay-hashes' and len(sys.argv) == 3:
            overlays_match(pathlib.Path(sys.argv[2]))
        elif action in ('fixture-snapshot', 'fixture-verify') and len(sys.argv) == 4:
            fixture_contract(action, sys.argv[2], pathlib.Path(sys.argv[3]))
        elif action == 'journal-canary' and len(sys.argv) == 2:
            journal_canary(sys.stdin.readline().rstrip('\n'))
        elif action == 'extract-snapshot' and len(sys.argv) == 4:
            extract_snapshot(pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3]))
        else:
            return 2
        return 0
    except (OSError, ValueError, TypeError, KeyError, IndexError, AttributeError,
            subprocess.SubprocessError, tarfile.TarError):
        # Fixed diagnostic only; never interpolate config, commands, or logs.
        print('Release safety check failed; unsupported or unavailable input.', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
