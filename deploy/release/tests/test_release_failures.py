"""Executable, target-free regressions for the six reviewed release failures.

Run on Windows with Git Bash or Linux with Bash. Files, commands and service
state live in TemporaryDirectory; no production entry point is executed.
"""
from __future__ import annotations

import importlib.util
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
ENTRY = (ROOT / 'release-entry.sh').read_text()
BASH = os.environ.get('MAYAK_TEST_BASH') or (r'C:\Program Files\Git\bin\bash.exe' if os.name == 'nt' else shutil.which('bash'))
spec = importlib.util.spec_from_file_location('release_safety', ROOT / 'release_safety.py')
safety = importlib.util.module_from_spec(spec)
spec.loader.exec_module(safety)


def bash_path(path):
    path = str(Path(path).absolute()).replace('\\', '/')
    return '/' + path[0].lower() + path[2:] if re.match(r'^[A-Za-z]:/', path) else path


def function(name):
    start = ENTRY.index(name + '() {')
    return ENTRY[start:ENTRY.index('\n}\n', start) + 3]


def archive(path, marker='restored', malicious=None):
    with tarfile.open(path, 'w:gz') as tar:
        for name, data in [('mayak-api.dll', b'fixture dll'), ('marker', marker.encode()),
                           ('mayak-api.runtimeconfig.json', b'{"runtimeOptions":{"tfm":"net10.0"}}')]:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        if malicious:
            info = tarfile.TarInfo(malicious)
            info.size = 1
            tar.addfile(info, io.BytesIO(b'x'))


class SafetyTests(unittest.TestCase):
    def test_caddy_hash_gate_accepts_exact_snapshot_and_rejects_drift(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            path = Path(tmp) / 'Caddyfile'
            path.write_bytes(b'fixture caddy bytes\n')
            expected = hashlib.sha256(path.read_bytes()).hexdigest()
            safety.caddy_hash(path, expected)
            with self.assertRaises(ValueError): safety.caddy_hash(path, '0' * 64)
            path.write_bytes(b'drifted caddy bytes\n')
            with self.assertRaises(ValueError): safety.caddy_hash(path, expected)

    def test_database_endpoint_identity_no_credentials_in_process_arguments(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            config = Path(tmp) / 'config.json'
            secret = 'synthetic;Database=wrong_backup;:password'
            config.write_text(json.dumps({'ConnectionStrings': {'Db':
                'Host=127.0.0.1;Database=mayak;Username=mayak;Password="' + secret + '"'}}))
            for same_cluster in (True, False):
                with tempfile.TemporaryFile() as backing:
                    fd = os.dup(backing.fileno())
                    def probe(argv, **kwargs):
                        self.assertNotIn(secret, str(argv))
                        self.assertNotIn(secret, str(kwargs['env']))
                        self.assertEqual(kwargs['pass_fds'], (fd,))
                        self.assertEqual(kwargs['env']['PGPASSFILE'], '/proc/self/fd/' + str(fd))
                        self.assertIn('--username=mayak', argv)
                        self.assertIn('--dbname=mayak', argv)
                        return 'cluster-A' if same_cluster else 'cluster-B'
                    with patch.object(safety, 'output', return_value='cluster-A'), \
                         patch.object(safety.socket, 'getaddrinfo', return_value=[(2, 1, 6, '', ('127.0.0.1', 5432))]), \
                         patch.object(safety.os, 'memfd_create', return_value=fd, create=True), \
                         patch.object(safety.os, 'MFD_CLOEXEC', 1, create=True), \
                         patch.object(safety.os, 'fchmod', create=True), \
                         patch.object(safety.subprocess, 'check_output', side_effect=probe):
                        if same_cluster:
                            safety.database_identity(config)
                        else:
                            with self.assertRaises(ValueError): safety.database_identity(config)

    def test_quoted_connection_values_and_aliases(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            config = Path(tmp) / 'config.json'
            for text in [
                'Password="fixture;Database=wrong_backup;";Host=127.0.0.1;Username=mayak;Database=mayak',
                "Password='it''s;a=fixture';Server='localhost';User ID=mayak;Initial Catalog=mayak;Port=5432",
                'Host=/var/run/postgresql;Username=mayak;Database="mayak";Password="a""b;c"',
            ]:
                config.write_text(json.dumps({'ConnectionStrings': {'Db': text}}))
                self.assertEqual(safety.database_name(config), 'mayak')

    def test_unsupported_database_inputs_fail_closed(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            config = Path(tmp) / 'config.json'
            cases = [{'ConnectionStrings': {'DefaultConnection': 'Host=127.0.0.1;Username=mayak;Database=other'}},
                     {'ConnectionStrings': {'Db': 'Host=127.0.0.1;Port=5433;Username=mayak;Database=mayak'}},
                     {'ConnectionStrings': {'Db': 'Host=remote.example;Username=mayak;Database=mayak'}},
                     {'ConnectionStrings': {'Db': 'Host=127.0.0.1;Username=postgres;Database=mayak'}},
                     {'ConnectionStrings': {'Db': 'Host=127.0.0.1;Username=mayak;Database=mayak;Initial Catalog=other'}},
                     {'ConnectionStrings': {'Db': 'Password="unfinished;Host=127.0.0.1;Username=mayak;Database=mayak'}},
                     {'ConnectionStrings:Db': 'Host=127.0.0.1;Username=mayak;Database=mayak'},
                     {'ConnectionStrings': {'Db': 'Host=127.0.0.1;Username=mayak;Database=mayak;Options=-c dangerous'}}]
            for data in cases:
                config.write_text(json.dumps(data))
                with self.subTest(data=data), self.assertRaises(ValueError):
                    safety.database_name(config)

    def test_caddy_exact_adaptation_rejects_cross_route_and_logs(self):
        good = {'apps': {'http': {'servers': {'srv0': {'routes': [
            {'match': [{'host': ['mayaklight.ru']}], 'handle': [
                {'handler': 'reverse_proxy', 'upstreams': [{'dial': '127.0.0.1:5080'}]}]}]}}}}}
        bad = json.loads(json.dumps(good))
        routes = bad['apps']['http']['servers']['srv0']['routes']
        routes[0]['handle'][0]['upstreams'][0]['dial'] = '127.0.0.1:9999'
        routes.append({'match': [{'host': ['other.example']}], 'handle': [
            {'handler': 'reverse_proxy', 'upstreams': [{'dial': '127.0.0.1:5080'}]}]})
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            config = Path(tmp) / 'Caddyfile'
            config.write_text('mayaklight.ru { reverse_proxy 127.0.0.1:5080 }')
            with patch.object(safety, 'output', side_effect=[json.dumps(good), json.dumps(good)]):
                safety.caddy_config(str(config))
            with patch.object(safety, 'output', side_effect=[json.dumps(good), json.dumps(bad)]):
                with self.assertRaises(ValueError): safety.caddy_config(str(config))
            logged = json.loads(json.dumps(good))
            logged['apps']['http']['servers']['srv0']['logs'] = {'default_logger_name': 'access'}
            with patch.object(safety, 'output', return_value=json.dumps(logged)):
                with self.assertRaises(ValueError): safety.caddy_config(str(config))

    def test_journal_unavailable_token_found_and_confirmed_absence(self):
        token = 'A' * 43
        with patch.object(safety, 'output', return_value='fixture unrelated log') as read:
            safety.journal_canary(token)
            self.assertEqual(read.call_count, 2)
        with patch.object(safety, 'output', return_value=token):
            with self.assertRaises(ValueError): safety.journal_canary(token)
        with patch.object(safety, 'output', side_effect=subprocess.CalledProcessError(1, 'journalctl')):
            with self.assertRaises(subprocess.SubprocessError): safety.journal_canary(token)

    def test_snapshot_validation_before_extraction(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            root = Path(tmp)
            source = root / 'snapshot.tar.gz'
            archive(source)
            safety.extract_snapshot(source, root / 'valid')
            self.assertEqual((root / 'valid/marker').read_text(), 'restored')
            archive(source, malicious='../escape')
            with self.assertRaises(ValueError): safety.extract_snapshot(source, root / 'unsafe')
            self.assertFalse((root / 'unsafe').exists())
            source.write_bytes(b'corrupt snapshot')
            with self.assertRaises(tarfile.TarError): safety.extract_snapshot(source, root / 'corrupt')


@unittest.skipUnless(BASH and Path(BASH).exists(), 'Bash unavailable; executable service fixtures NOT VERIFIED')
class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='.failure-fixture-', dir=ROOT)
        self.root = Path(self.temp.name)
        for name in ('api', 'releases', 'backup', 'dist', 'static/updates/stable'):
            (self.root / name).mkdir(parents=True)
        (self.root / 'api/marker').write_text('current')
        (self.root / 'api/mayak-api.dll').write_text('current dll')
        (self.root / 'config').write_text('{"ConnectionStrings":{"Db":"Host=127.0.0.1;Database=mayak;Username=mayak;Password=fixture"}}')
        (self.root / 'caddy').write_text('mayaklight.ru { reverse_proxy 127.0.0.1:5080 }')
        shutil.copyfile(self.root / 'config', self.root / 'backup/api.json.previous')
        shutil.copyfile(self.root / 'caddy', self.root / 'backup/Caddyfile.previous')
        (self.root / 'backup/Caddyfile.previous.sha256').write_text(hashlib.sha256((self.root / 'caddy').read_bytes()).hexdigest())
        for name in ('windows-x64', 'android-arm64'):
            (self.root / f'backup/{name}.json.previous').write_text('old feed')
            (self.root / f'static/updates/stable/{name}.json').write_text('old feed')
        (self.root / 'backup/agent.previous').write_text('old agent')
        (self.root / 'dist/mayak-agent').write_text('old agent')

    def tearDown(self):
        self.temp.cleanup()

    def prefix(self):
        helpers = ENTRY[ENTRY.index('# BEGIN TRANSACTION HELPERS'):ENTRY.index('# END TRANSACTION HELPERS')]
        q = shlex.quote(bash_path(self.root))
        return f'''set -Eeuo pipefail
shopt -s inherit_errexit
base={q}
API_DIR="$base/api"; RELEASES="$base/releases"; BACKUPS="$base/backups"
CONFIG="$base/config"; CADDYFILE="$base/caddy"; DIST="$base/dist"
static_root="$base/static"; UNIT=FIXTURE; HEALTH_URL=http://fixture.invalid/health
release_id=test; recovery="$base/backup"; old_api="$base/old-api"; failed_api="$base/failed-api"
SAFETY={shlex.quote(bash_path(ROOT / 'release_safety.py'))}
log="$base/events"
service_stopped=0; release_swapped=0; fixture=; candidate_pid=
die() {{ printf 'REFUSED: %s\\n' "$1" >&2; exit 2; }}
note() {{ printf '%s\\n' "$1"; }}
        python3() {{ if [[ ${{2:-}} == caddy-config || ${{2:-}} == overlay-hashes ]]; then return 0; fi; {shlex.quote(bash_path(sys.executable))} "$@"; }}
timeout() {{ shift; "$@"; }}
sleep() {{ :; }}
systemctl() {{ printf '%s\\n' "$*" >> "$log"; if [[ ${{fail_at:-}} == reload && $1 == reload ]]; then fail_at=; return 43; fi; }}
caddy() {{ return 0; }}
curl() {{ if [[ ${{fail_at:-}} == health && $(cat "$API_DIR/marker") == restored ]]; then return 7; fi; return 0; }}
install() {{
  while [[ ${{1:-}} == -* ]]; do shift 2; done
  if [[ ${{fail_at:-}} == restore && $1 == "$recovery/api.json.previous" ]]; then return 44; fi
  if [[ ${{fail_at:-}} == selected && $1 == "$dir/Caddyfile.previous" ]]; then fail_at=; return 45; fi
  command cp -- "$1" "$2"
}}
mkdir() {{ if [[ ${{1:-}} == -m ]]; then shift 2; fi; command mkdir "$@"; }}
chown() {{ :; }}
chmod() {{ :; }}
mv() {{ if [[ ${{fail_at:-}} == swap && ${{2:-}} == "$restore_api" ]]; then fail_at=; return 49; fi; command mv "$@"; }}
{helpers}
'''

    def run_shell(self, body, rc):
        script = self.root / 'fixture.sh'
        script.write_text(self.prefix() + body, encoding='utf-8', newline='\n')
        run = subprocess.run([BASH, bash_path(script)], capture_output=True, text=True, timeout=35)
        self.assertEqual(run.returncode, rc, run.stdout + run.stderr)
        return run

    def test_automatic_failure_after_stop_preserves_original_status(self):
        self.run_shell('''trap 'exit_release "$?"' EXIT
service_stopped=1
systemctl stop "$UNIT"
exit 37
''', 37)
        self.assertEqual((self.root / 'api/marker').read_text(), 'current')
        self.assertIn('start FIXTURE', (self.root / 'events').read_text())

    def test_failed_cleanup_cannot_replace_status_or_skip_recovery(self):
        self.run_shell('''cleanup_fixture() { return 71; }
trap 'exit_release "$?"' EXIT
service_stopped=1
exit 37
''', 37)
        self.assertIn('start FIXTURE', (self.root / 'events').read_text())

    def test_automatic_failure_after_api_move_and_after_static_switch(self):
        for phase in ('moved', 'swapped', 'static'):
            with self.subTest(phase=phase):
                if (self.root / 'failed-api').exists(): shutil.rmtree(self.root / 'failed-api')
                body = '''trap 'exit_release "$?"' EXIT
service_stopped=1
systemctl stop "$UNIT"
mv "$API_DIR" "$old_api"
'''
                if phase != 'moved':
                    body += '''mkdir "$API_DIR"
printf candidate > "$API_DIR/marker"
release_swapped=1
'''
                if phase == 'static':
                    body += '''printf changed > "$CONFIG"
printf changed > "$CADDYFILE"
printf changed > "$DIST/mayak-agent"
printf changed > "$static_root/updates/stable/windows-x64.json"
'''
                self.run_shell(body + 'exit 38\n', 38)
                self.assertEqual((self.root / 'api/marker').read_text(), 'current')
                self.assertEqual((self.root / 'config').read_text(), (self.root / 'backup/api.json.previous').read_text())
                self.assertEqual((self.root / 'dist/mayak-agent').read_text(), 'old agent')
                self.assertEqual((self.root / 'static/updates/stable/windows-x64.json').read_text(), 'old feed')
                self.assertIn('start FIXTURE', (self.root / 'events').read_text())

    def test_recovery_asset_error_still_attempts_api_restart(self):
        run = self.run_shell('''trap 'exit_release "$?"' EXIT
service_stopped=1
fail_at=restore
exit 39
''', 39)
        self.assertIn('start FIXTURE', (self.root / 'events').read_text())
        self.assertIn('RECOVERY INCOMPLETE', run.stderr)

    def manual_body(self, fail_at='', corrupt=False, legacy=False):
        backups = self.root / 'backups'
        backups.mkdir()
        selected = backups / 'retained'
        shutil.copytree(self.root / 'backup', selected)
        snapshot = selected / 'api.previous.tar.gz'
        archive(snapshot)
        if legacy:
            (selected / 'api.previous.tar.gz.sha256').unlink(missing_ok=True)
            (selected / 'Caddyfile.previous.sha256').unlink(missing_ok=True)
        else:
            (selected / 'api.previous.tar.gz.sha256').write_text(hashlib.sha256(snapshot.read_bytes()).hexdigest())
        if corrupt: snapshot.write_bytes(b'not gzip')
        branch = ENTRY[ENTRY.index('if [[ $ACTION == rollback ]]'):ENTRY.index('[[ $ACTION == apply')]
        branch = branch.replace('static_root=/opt/mayak/static', 'static_root="$base/static"')
        drift = 'printf drift > "$CADDYFILE"\n' if fail_at in ('selected', 'reload') else ''
        return f'''ACTION=rollback; ROLLBACK_ID=retained; fail_at={shlex.quote(fail_at)}
{drift} 
check_rollback_target() {{ :; }}
stat() {{ if [[ $2 == '%U:%G' ]]; then printf root:root; elif [[ -d $3 ]]; then printf 700; else printf 600; fi; }}
check_disk_requirement() {{ :; }}
candidate_check() {{ printf 'candidate-check\\n' >> "$log"; if [[ $fail_at == smoke ]]; then die 'fixture restore failure before stop'; fi; }}
runuser() {{ printf 'fixture dump'; }}
{function('read_local_database_name')}
# Caddy live equality is separately executed in SafetyTests; fake only this call.
python3() {{ if [[ ${{2:-}} == caddy-config || ${{2:-}} == overlay-hashes ]]; then return 0; fi; {shlex.quote(bash_path(sys.executable))} "$@"; }}
{branch}
'''

    def test_manual_corrupt_snapshot_never_stops_or_moves_api(self):
        self.run_shell(self.manual_body(corrupt=True), 2)
        self.assertEqual((self.root / 'api/marker').read_text(), 'current')
        self.assertFalse((self.root / 'events').exists())

    def test_legacy_snapshot_without_recorded_hashes_refuses_before_stop(self):
        self.run_shell(self.manual_body(legacy=True), 2)
        self.assertEqual((self.root / 'api/marker').read_text(), 'current')
        self.assertFalse((self.root / 'events').exists())

    def test_manual_restore_failure_keeps_api_on(self):
        self.run_shell(self.manual_body(fail_at='smoke'), 2)
        self.assertEqual((self.root / 'events').read_text(), 'candidate-check\n')
        self.assertEqual((self.root / 'api/marker').read_text(), 'current')

    def test_manual_switch_failure_returns_current_api(self):
        for failure in ('swap', 'selected', 'reload', 'health'):
            with self.subTest(failure=failure):
                # Each manual attempt intentionally retains its evidence.
                for path in (self.root / 'backups',):
                    if path.exists(): shutil.rmtree(path)
                self.run_shell(self.manual_body(fail_at=failure), 49 if failure == 'swap' else 2)
                self.assertEqual((self.root / 'api/marker').read_text(), 'current')
                self.assertIn('start FIXTURE', (self.root / 'events').read_text())

    def test_manual_success_checks_candidate_before_stop(self):
        self.run_shell(self.manual_body(), 0)
        events = (self.root / 'events').read_text()
        self.assertLess(events.index('candidate-check'), events.index('stop FIXTURE'))
        self.assertEqual((self.root / 'api/marker').read_text(), 'restored')

    def test_actual_caddy_identity_predicate(self):
        line = next(x for x in ENTRY.splitlines() if '[[ $caddy_user == caddy && $caddy_group' in x)
        for user, group, fragment, rc in [
            ('caddy', 'caddy', '/usr/lib/systemd/system/caddy.service', 0),
            ('root', 'root', '/usr/lib/systemd/system/caddy.service', 2),
            ('caddy', 'caddy', '/etc/systemd/system/custom-root.service', 2),
        ]:
            self.run_shell(f'caddy_user={user}; caddy_group={group}; caddy_fragment={fragment}; caddy_dropins=; caddy_envfiles=\n' + line + '\n', rc)

    def test_canary_request_or_journal_failure_cannot_apply(self):
        start = ENTRY.index("canary=$(python3 -c 'import secrets")
        tail = ENTRY[start:]
        for failure in ('request', 'status', 'journal'):
            with self.subTest(failure=failure):
                body = f'''service_stopped=0; release_swapped=1
failure={failure}
trap 'exit_release "$?"' EXIT
python3() {{
  if [[ $1 == -c ]]; then printf '%s\\n' {'A' * 43}; return 0; fi
  if [[ $2 == journal-canary ]]; then cat >/dev/null; return 2; fi
  return 0
}}
curl() {{
  if [[ $1 != --config ]]; then return 0; fi
  cat >/dev/null
  if [[ $failure == request ]]; then return 7; fi
  if [[ $failure == status ]]; then printf 500; else printf 404; fi
}}
'''
                run = self.run_shell(body + tail, 2)
                self.assertNotIn('RELEASE APPLIED', run.stdout)
                self.assertNotIn('A' * 43, run.stdout + run.stderr)
                self.assertIn('start FIXTURE', (self.root / 'events').read_text())


class PostgresRestoreTests(unittest.TestCase):
    def test_actual_dump_stdin_restore_and_ownership(self):
        pg = Path(os.environ.get('MAYAK_TEST_PG_BIN', ROOT.parents[2] / 'toolchains/postgresql/pgsql/bin'))
        suffix = '.exe' if os.name == 'nt' else ''
        if not (pg / ('initdb' + suffix)).is_file():
            self.skipTest('Disposable PostgreSQL binaries unavailable; actual restore NOT VERIFIED')
        with tempfile.TemporaryDirectory(prefix='.postgres-fixture-', dir=ROOT) as tmp:
            root = Path(tmp)
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                port = str(sock.getsockname()[1])
            def command(tool, *args, data=None):
                if tool == 'pg_ctl':
                    # Windows postmaster inherits pipe handles from pg_ctl.
                    # DEVNULL avoids waiting for a daemon-owned pipe to close.
                    return subprocess.run([str(pg / (tool + suffix)), *map(str, args)],
                                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)
                return subprocess.run([str(pg / (tool + suffix)), *map(str, args)], input=data,
                                      capture_output=True, timeout=60)
            init = command('initdb', '-D', root / 'data', '-U', 'fixture_admin', '-A', 'trust', '--no-locale', '-E', 'UTF8')
            self.assertEqual(init.returncode, 0, init.stderr.decode(errors='replace'))
            started = False
            try:
                started = True
                run = command('pg_ctl', '-D', root / 'data', '-l', root / 'server.log', '-o', f'-h 127.0.0.1 -p {port}', '-w', 'start')
                self.assertEqual(run.returncode, 0, (run.stderr or b'').decode(errors='replace'))
                conn = ['--host=127.0.0.1', '--port=' + port, '--username=fixture_admin', '--no-password']
                sql = 'CREATE ROLE mayak LOGIN; CREATE DATABASE source OWNER mayak; CREATE DATABASE restored OWNER mayak;'
                for statement in sql.split(';'):
                    if statement.strip():
                        run = command('psql', *conn, '--dbname=postgres', '-v', 'ON_ERROR_STOP=1', '-c', statement)
                        self.assertEqual(run.returncode, 0, run.stderr.decode(errors='replace'))
                run = command('psql', *conn, '--dbname=source', '-v', 'ON_ERROR_STOP=1', '-c', 'SET ROLE mayak; CREATE TABLE sample(id integer PRIMARY KEY); INSERT INTO sample VALUES (1),(2);')
                self.assertEqual(run.returncode, 0, run.stderr.decode(errors='replace'))
                dump = command('pg_dump', *conn, '--dbname=source', '--format=custom', '--no-owner', '--no-acl')
                self.assertEqual(dump.returncode, 0)
                # Take the actual release command's options, substituting only
                # disposable cluster endpoint/DB/admin and removing shell I/O.
                line = next(x for x in ENTRY.splitlines() if x.startswith('runuser -u postgres -- pg_restore '))
                args = shlex.split(line.split(' <', 1)[0])[5:]
                args = [x.replace('/var/run/postgresql', '127.0.0.1').replace('--port=5432', '--port=' + port)
                        .replace('--username=postgres', '--username=fixture_admin').replace('--dbname=$fixture', '--dbname=restored') for x in args]
                self.assertNotIn('-', args)
                restore = command('pg_restore', *args, data=dump.stdout)
                self.assertEqual(restore.returncode, 0, restore.stderr.decode(errors='replace'))
                result = command('psql', *conn, '--dbname=restored', '-A', '-t', '-c', "SELECT count(*)::text || ':' || (SELECT tableowner FROM pg_tables WHERE tablename='sample') FROM sample")
                self.assertEqual(result.stdout.decode().strip(), '2:mayak')
            finally:
                if started:
                    stopped = command('pg_ctl', '-D', root / 'data', '-m', 'immediate', '-w', 'stop')
                    self.assertEqual(stopped.returncode, 0, 'disposable cluster shutdown failed')


if __name__ == '__main__':
    unittest.main(verbosity=2)
