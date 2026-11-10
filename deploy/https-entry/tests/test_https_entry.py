import importlib.util
import pathlib
import unittest
import uuid
import contextlib
import sys
import json
import subprocess
import tempfile
from types import SimpleNamespace
from unittest.mock import patch, Mock

MODULE = pathlib.Path(__file__).parents[1] / 'https_entry.py'
TEST_TMP = MODULE.parents[3] / 'https-entry01' / 'test-tmp'
TEST_TMP.mkdir(parents=True, exist_ok=True)
tempfile.tempdir = str(TEST_TMP)
spec = importlib.util.spec_from_file_location('https_entry', MODULE)
entry = importlib.util.module_from_spec(spec)
spec.loader.exec_module(entry)


def exec_fixture(path='/usr/bin/caddy', arguments='run --environ --config /etc/caddy/Caddyfile', reset=False):
    accounting = 'start_time=[n/a] ; stop_time=[n/a] ; pid=0' if reset else \
        'start_time=[Wed 2026-10-28 09:46:14 UTC] ; stop_time=[n/a] ; pid=36438'
    return '{ path=' + path + ' ; argv[]=' + path + ' ' + arguments + \
        ' ; ignore_errors=no ; ' + accounting + ' ; code=(null) ; status=0/0 }'


def identity_fixture(reset=False):
    return dict(unit_sha='unit', binary_sha='binary', argv=exec_fixture(reset=reset),
                process=dict(pid=36438, start='12345', exe='/usr/bin/caddy', uid=998))


class MetadataTests(unittest.TestCase):
    def setUp(self):
        self.account = str(uuid.uuid4())
        self.device = str(uuid.uuid4())
        self.xid = str(uuid.uuid4())
        self.meta = {
            'Cluster': {'XrayJson': '{"Host":"147.45.41.230","Port":443,"PublicKey":"abcdefghijklmnopqrstuvwxyz_1234567890abcdef","Sni":"foreign.example","ShortId":"01234567","Transport":"xhttp","XhttpPath":"/secret","XhttpHost":"foreign.example","XhttpMode":"auto"}'},
            'Accounts': [{'Id': self.account, 'Enabled': True, 'PaidUntilEpoch': None}],
            'Devices': [{'Id': self.device, 'AccountId': self.account, 'Enabled': True, 'Name': 'Телефон', 'XrayId': self.xid, 'ServiceProtocol': None}],
        }

    def test_pascal_case_xray_endpoint_and_active_legacy_device(self):
        ep = entry.endpoint_from_db(self.meta)
        self.assertEqual(ep['path'], '/secret')
        self.assertEqual(entry.select_device(self.meta), self.xid)
        cfg = entry.build_xray(self.xid, str(uuid.uuid4()), '/randompathrandompath', ep)
        self.assertEqual(cfg['outbounds'][0]['settings']['vnext'][0]['address'], entry.FOREIGN)
        self.assertEqual(len(cfg['outbounds']), 1)

    def test_rejects_wrong_casing_missing_and_duplicate_fields(self):
        self.meta['Cluster']['XrayJson'] = '{"host":"x"}'
        with self.assertRaises(entry.Refuse): entry.endpoint_from_db(self.meta)
        self.meta['Cluster']['XrayJson'] = '{"Sni":"a","Sni":"b"}'
        with self.assertRaises(entry.Refuse): entry.endpoint_from_db(self.meta)

    def test_rejects_non_xhttp_and_bad_short_id(self):
        ep = entry.strict_json(self.meta['Cluster']['XrayJson'])
        ep['Transport'] = 'tcp'
        self.meta['Cluster']['XrayJson'] = entry.json.dumps(ep)
        with self.assertRaises(entry.Refuse): entry.endpoint_from_db(self.meta)
        ep['Transport'] = 'xhttp'; ep['ShortId'] = 'xyz'
        self.meta['Cluster']['XrayJson'] = entry.json.dumps(ep)
        with self.assertRaises(entry.Refuse): entry.endpoint_from_db(self.meta)

    def test_rejects_disabled_expired_or_managed_protocol_device(self):
        self.meta['Accounts'][0]['PaidUntilEpoch'] = 1
        with self.assertRaises(entry.Refuse): entry.select_device(self.meta)
        self.meta['Accounts'][0]['PaidUntilEpoch'] = None
        self.meta['Devices'][0]['ServiceProtocol'] = 'vless'
        with self.assertRaises(entry.Refuse): entry.select_device(self.meta)
        self.meta['Devices'][0]['ServiceProtocol'] = None
        self.meta['Devices'].append(dict(self.meta['Devices'][0], Id=str(uuid.uuid4()), Name='Other'))
        self.assertEqual(entry.select_device(self.meta), self.xid)  # unique Телефон preference

    def test_rejects_ambiguous_devices_and_invalid_uuid(self):
        self.meta['Devices'].append(dict(self.meta['Devices'][0], Id=str(uuid.uuid4()), Name='Other'))
        self.meta['Devices'][0]['Name'] = 'Other'
        with self.assertRaises(entry.Refuse): entry.select_device(self.meta)
        self.meta['Devices'] = [dict(self.meta['Devices'][0], XrayId='not-a-uuid')]
        with self.assertRaises(entry.Refuse): entry.select_device(self.meta)

    def test_expiration_zero_false_and_nonfinite_are_not_unlimited(self):
        for value in (0, False, float('inf'), float('nan'), '999999999999'):
            with self.subTest(value=value):
                self.meta['Accounts'][0]['PaidUntilEpoch'] = value
                with self.assertRaises(entry.Refuse): entry.select_device(self.meta)

    def test_only_explicit_null_is_unlimited(self):
        del self.meta['Accounts'][0]['PaidUntilEpoch']
        with self.assertRaises(entry.Refuse): entry.select_device(self.meta)

    def test_incompatible_port_flow_and_host_rejected(self):
        base = entry.strict_json(self.meta['Cluster']['XrayJson'])
        for field, value in [('Port', 8443), ('Port', '443'), ('Flow', 'xtls-rprx-vision'),
                             ('Host', 'evil.example'), ('Fingerprint', 'unsupported')]:
            with self.subTest(field=field, value=value):
                self.meta['Cluster']['XrayJson'] = json.dumps(dict(base, **{field: value}))
                with self.assertRaises(entry.Refuse): entry.endpoint_from_db(self.meta)


class StageTests(unittest.TestCase):
    ORIGINAL = '''mayaklight.ru {
    encode gzip
    handle /updates/* {
        root * /opt/mayak/static
        file_server
    }
    reverse_proxy 127.0.0.1:5080
}
'''

    def test_caddy_handler_is_multiline_exclusive_and_compression_scoped(self):
        route = '/mayak-connect/' + 'a' * 36 + '/'
        text = entry.candidate(self.ORIGINAL, route)
        self.assertIn('handle ' + route + '* {\n        reverse_proxy 127.0.0.1:18080\n    }', text)
        self.assertIn('handle {\n        encode gzip', text)
        self.assertNotIn('handle_path', text)
        self.assertEqual(text.count('encode gzip'), 1)
        self.assertIn('handle /updates/* {', text)

    def test_unsupported_caddy_drift_rejected(self):
        with self.assertRaises(entry.Refuse):
            entry.candidate(self.ORIGINAL.replace('5080', '5081'), '/mayak-connect/' + 'a' * 36 + '/')

    def make_stage(self, d):
        route = '/mayak-connect/' + 'a' * 36 + '/'
        up = dict(sni='example.org', sid='12345678', pbk='a' * 43, path='/', host='example.org', mode='auto')
        xid, iid = str(uuid.uuid4()), str(uuid.uuid4())
        blobs = {'Caddyfile.original': self.ORIGINAL, 'Caddyfile.candidate': entry.candidate(self.ORIGINAL, route),
                 'xray.bin': 'fixture', 'xray.json': json.dumps(entry.build_xray(xid, iid, route, up)),
                 'baseline.json': json.dumps({'caddy_sha256': entry.sha(self.ORIGINAL.encode())})}
        for name, blob in blobs.items():
            (d / name).write_bytes(blob.encode())
        m = dict(path=route, inbound_id=iid, upstream_device=xid, upstream=up,
                 files={name: entry.digest(d / name) for name in blobs})
        (d / 'manifest.json').write_text(json.dumps(m))
        return m

    def test_bound_stage_passes_and_changed_artifact_fails(self):
        with tempfile.TemporaryDirectory() as td, patch.object(entry, 'private_dir'), patch.object(entry, 'regular'):
            d = pathlib.Path(td)
            self.make_stage(d)
            self.assertTrue(entry.stage_files(d))
            (d / 'Caddyfile.original').write_text('changed')
            with self.assertRaises(entry.Refuse): entry.stage_files(d)

    def test_every_extra_stage_file_is_guarded(self):
        with tempfile.TemporaryDirectory() as td, patch.object(entry, 'private_dir'), patch.object(entry, 'regular') as guard:
            d = pathlib.Path(td)
            self.make_stage(d)
            extra = d / 'credentials.json'; extra.write_text('private')
            entry.stage_files(d)
            guard.assert_any_call(extra)

    def test_parent_symlink_and_writable_file_are_rejected(self):
        with patch.object(pathlib.Path, 'lstat', return_value=SimpleNamespace(st_mode=0o120777, st_uid=0)):
            with self.assertRaises(entry.Refuse): entry.parents_safe(pathlib.Path('/some/path'))
        with patch.object(entry, 'parents_safe'), patch.object(pathlib.Path, 'lstat',
                return_value=SimpleNamespace(st_mode=0o100644, st_uid=0, st_nlink=1)):
            with self.assertRaises(entry.Refuse): entry.regular(pathlib.Path('/some/file'))

    def test_metadata_file_symlink_rejected(self):
        with patch.object(entry, 'parents_safe'), patch.object(pathlib.Path, 'lstat',
                return_value=SimpleNamespace(st_mode=0o120600, st_uid=0, st_nlink=1)):
            with self.assertRaises(entry.Refuse): entry.load_meta(pathlib.Path('/some/file'))


class UpstreamOverrideTests(unittest.TestCase):
    def setUp(self):
        fixture = MetadataTests()
        fixture.setUp()
        self.meta, self.xid = fixture.meta, fixture.xid
        self.override = dict(Host=entry.FOREIGN, targetHost=entry.FOREIGN, Port=443,
            Security='reality', Transport='tcp', Flow='', Sni='foreign.example',
            ShortId='01234567', PublicKey='a' * 43, selectedClientSha256=entry.sha(self.xid.encode()))

    def parse(self, **values):
        return entry.upstream_override(json.dumps(dict(self.override, **values)), self.xid)

    def make_stage(self, d, **override):
        binary, caddy, metadata = d / 'xray', d / 'Caddyfile', d / 'exit.json'
        binary.write_bytes(b'fixture binary')
        caddy.write_text(StageTests.ORIGINAL)
        metadata.write_text(json.dumps(dict(self.override, **override)))
        args = SimpleNamespace(upstream_metadata=metadata, metadata=None, database='mayak', device_id=None,
                               xray_bin=binary, sha256_file=None, sha256=entry.digest(binary), out=d / 'stage-new')
        b = dict(caddy_sha256=entry.digest(caddy), identity={}, responses={})
        with patch.object(entry, 'preflight', return_value=b), patch.object(entry, 'read_db', return_value=self.meta), \
             patch.object(entry, 'regular') as regular, patch.object(entry, 'parents_safe'), \
             patch.object(entry, 'private_dir'), patch.object(entry, 'CADDY', caddy), \
             patch.object(entry, 'put', side_effect=lambda p, data, mode=0o600: p.write_bytes(data.encode() if isinstance(data, str) else data)), \
             patch('builtins.print'):
            entry.stage(args)
            regular.assert_any_call(metadata)
            m = entry.stage_files(args.out)
        return args.out, m, metadata

    def test_raw_and_tcp_normalize_with_explicit_blank_or_vision_flow(self):
        for transport in ('raw', 'tcp'):
            for flow in ('', 'xtls-rprx-vision'):
                with self.subTest(transport=transport, flow=flow):
                    up = self.parse(Transport=transport, Flow=flow)
                    cfg = entry.build_xray(self.xid, str(uuid.uuid4()), '/pilot/', up)
                    out = cfg['outbounds'][0]
                    self.assertEqual(out['streamSettings']['network'], 'raw')
                    self.assertEqual(out['streamSettings']['security'], 'reality')
                    self.assertNotIn('xhttpSettings', out['streamSettings'])
                    self.assertEqual(out['settings']['vnext'][0]['users'][0]['flow'], flow)
                    self.assertEqual(out['settings']['vnext'][0]['address'], entry.FOREIGN)
                    self.assertEqual(len(cfg['outbounds']), 1)
                    self.assertEqual(cfg['inbounds'][0]['streamSettings']['network'], 'xhttp')

    def test_xhttp_override_remains_compatible_and_vision_is_rejected(self):
        db_endpoint = json.loads(self.meta['Cluster']['XrayJson'])
        self.assertEqual(self.parse(Transport='xhttp', PublicKey=db_endpoint['PublicKey'], XhttpPath='/secret'),
                         entry.endpoint_from_db(self.meta))
        with self.assertRaises(entry.Refuse): self.parse(Transport='xhttp', Flow='xtls-rprx-vision')

    def test_override_rejects_wrong_target_transport_security_flow_and_binding(self):
        for field, value in [('Host', '127.0.0.1'), ('targetHost', 'other.example'), ('Port', 8443),
                             ('Transport', 'ws'), ('Security', 'none'), ('Security', 'tls'),
                             ('Flow', None), ('Flow', 'guess'), ('selectedClientSha256', '0' * 64),
                             ('XhttpPath', '/unexpected')]:
            with self.subTest(field=field, value=value):
                with self.assertRaises(entry.Refuse): self.parse(**{field: value})
        for field in ('Host', 'targetHost', 'Security', 'Flow', 'selectedClientSha256'):
            cfg = dict(self.override); del cfg[field]
            with self.subTest(missing=field):
                with self.assertRaises(entry.Refuse): entry.upstream_override(json.dumps(cfg), self.xid)
        with self.assertRaises(entry.Refuse): self.parse(PrivateKey='never accepted')

    def test_stage_binds_exact_override_snapshot_instead_of_stale_cluster(self):
        self.meta['Cluster']['XrayJson'] = 'stale endpoint is deliberately unusable'
        with tempfile.TemporaryDirectory() as td:
            d, m, source = self.make_stage(pathlib.Path(td), Flow='xtls-rprx-vision')
            self.assertFalse(m['metadata_fixture'])
            self.assertTrue(m['upstream_metadata'])
            self.assertEqual((d / 'upstream-metadata.json').read_bytes(), source.read_bytes())
            self.assertEqual(m['files']['upstream-metadata.json'], entry.digest(source))
            self.assertEqual(m['upstream']['flow'], 'xtls-rprx-vision')
            source.write_text('original source is no longer needed')
            with patch.object(entry, 'regular'), patch.object(entry, 'private_dir'), \
                 patch.object(entry, 'read_db', return_value=self.meta) as db:
                entry.fresh_credentials(m, d)
                db.assert_called_once_with('mayak')

    def test_changed_staged_override_blocks_fresh_credentials_before_database_read(self):
        with tempfile.TemporaryDirectory() as td:
            d, m, _ = self.make_stage(pathlib.Path(td))
            (d / 'upstream-metadata.json').write_text('{}')
            with patch.object(entry, 'regular'), patch.object(entry, 'private_dir'), patch.object(entry, 'read_db') as db:
                with self.assertRaisesRegex(entry.Refuse, 'bound stage artifact changed'):
                    entry.fresh_credentials(m, d)
                db.assert_not_called()

    def test_rehashed_override_must_still_match_selected_credential_and_upstream(self):
        for field, value in [('selectedClientSha256', '0' * 64), ('ShortId', 'ff')]:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as td:
                d, m, _ = self.make_stage(pathlib.Path(td))
                p = d / 'upstream-metadata.json'
                p.write_text(json.dumps(dict(self.override, **{field: value})))
                m['files']['upstream-metadata.json'] = entry.digest(p)
                (d / 'manifest.json').write_text(json.dumps(m))
                with patch.object(entry, 'regular'), patch.object(entry, 'private_dir'):
                    with self.assertRaises(entry.Refuse): entry.stage_files(d)

    def test_fresh_database_still_rejects_ineligible_or_replaced_device(self):
        for mutation in ('disabled', 'expired', 'managed', 'replaced'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as td:
                d, m, _ = self.make_stage(pathlib.Path(td))
                meta = json.loads(json.dumps(self.meta))
                if mutation == 'disabled': meta['Devices'][0]['Enabled'] = False
                if mutation == 'expired': meta['Accounts'][0]['PaidUntilEpoch'] = 0
                if mutation == 'managed': meta['Devices'][0]['ServiceProtocol'] = 'vless'
                if mutation == 'replaced': meta['Devices'][0]['XrayId'] = str(uuid.uuid4())
                with patch.object(entry, 'regular'), patch.object(entry, 'private_dir'), patch.object(entry, 'read_db', return_value=meta):
                    with self.assertRaises(entry.Refuse): entry.fresh_credentials(m, d)

    def test_override_cannot_use_fixture_database_or_bypass_apply_gate(self):
        args = SimpleNamespace(upstream_metadata=pathlib.Path('exit.json'), metadata=pathlib.Path('fixture.json'))
        with patch.object(entry, 'preflight'), patch.object(entry, 'read_db') as db, patch.object(entry, 'load_meta') as fixture:
            with self.assertRaises(entry.Refuse): entry.stage(args)
            db.assert_not_called(); fixture.assert_not_called()
        with patch.object(entry, 'stage_files') as files, patch.object(entry, 'read_db') as db:
            with self.assertRaises(entry.Refuse): entry.fresh_credentials({'metadata_fixture': True}, pathlib.Path('stage'))
            files.assert_not_called(); db.assert_not_called()

    def test_database_only_freshness_still_checks_cluster_endpoint(self):
        m = dict(metadata_fixture=False, database='mayak', device_id=None, upstream_device=self.xid,
                 upstream=entry.endpoint_from_db(self.meta))
        with patch.object(entry, 'stage_files', return_value=m), patch.object(entry, 'read_db', return_value=self.meta):
            entry.fresh_credentials(m, pathlib.Path('stage'))
            self.meta['Cluster']['XrayJson'] = json.dumps(dict(self.override, PublicKey='b' * 43))
            with self.assertRaises(entry.Refuse): entry.fresh_credentials(m, pathlib.Path('stage'))

    def test_private_regular_guard_is_required_for_override_input(self):
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / 'exit.json'
            p.write_text(json.dumps(self.override))
            args = SimpleNamespace(upstream_metadata=p, metadata=None, database='mayak', device_id=None)
            with patch.object(entry, 'preflight'), patch.object(entry, 'read_db', return_value=self.meta), \
                 patch.object(entry, 'regular', side_effect=entry.Refuse('unsafe file permissions')) as regular:
                with self.assertRaisesRegex(entry.Refuse, 'unsafe file permissions'): entry.stage(args)
                regular.assert_called_once_with(p)


class ProbeTests(unittest.TestCase):
    PROBE_PORT = 45783

    def probe(self, effects, negative=False, owns=True, timeout_wait=False):
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        d = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(lambda: entry.shutil.rmtree(d))
        child = Mock(pid=123)
        child.poll.return_value = None
        if timeout_wait:
            child.wait.side_effect = [subprocess.TimeoutExpired('redacted', 5), 0]
        stack.enter_context(patch.object(entry, 'free_port', return_value=self.PROBE_PORT))
        stack.enter_context(patch.object(entry, 'listener_owned', return_value=owns))
        stack.enter_context(patch.object(entry, 'put', side_effect=lambda path, text: path.write_text(text)))
        stack.enter_context(patch.object(entry.subprocess, 'Popen', return_value=child))
        curl = stack.enter_context(patch.object(entry, 'curl_socks', side_effect=effects))
        return d, child, curl, lambda: entry.probe_socks(d, {}, {'protocol': 'vless'}, negative)

    def test_example_failure_cannot_be_masked_by_ipify_success(self):
        d, child, curl, probe = self.probe([subprocess.CalledProcessError(22, ['curl']), entry.FOREIGN])
        with self.assertRaises(entry.Refuse): probe()
        self.assertEqual(curl.call_count, 1)
        child.terminate.assert_called_once(); child.wait.assert_called_once()
        self.assertEqual(list(d.iterdir()), [])

    def test_foreign_ip_and_example_are_both_required(self):
        _, _, curl, probe = self.probe(['example HTML', entry.FOREIGN])
        probe(); self.assertEqual(curl.call_count, 2)

    def test_kernel_selected_port_flows_through_config_ownership_and_each_request(self):
        _, child, curl, probe = self.probe(['example HTML', entry.FOREIGN])
        calls = []
        entry.listener_owned.side_effect = lambda pid, port: calls.append(('owned', pid, port)) or True
        results = iter(['example HTML', entry.FOREIGN])
        curl.side_effect = lambda port, url: calls.append(('curl', port, url)) or next(results)
        probe()
        entry.free_port.assert_called_once_with(0)
        inbound = json.loads(entry.put.call_args.args[1])['inbounds'][0]
        self.assertEqual((inbound['listen'], inbound['port']), ('127.0.0.1', self.PROBE_PORT))
        self.assertGreater(inbound['port'], 0)
        owned = ('owned', child.pid, self.PROBE_PORT)
        self.assertEqual(calls, [owned, owned, ('curl', self.PROBE_PORT, 'https://example.com/'),
                                 owned, ('curl', self.PROBE_PORT, 'https://api.ipify.org'), owned])

    def test_preflight_only_reserves_actual_entry_port(self):
        grp = SimpleNamespace(getgrnam=Mock(side_effect=KeyError))
        with patch.dict(sys.modules, {'grp': grp}), patch.object(entry.shutil, 'which', return_value='tool'), \
             patch.object(entry, 'run', return_value='2.6.2'), patch.object(entry, 'baseline', return_value={}), \
             patch.object(entry, 'free_port') as free_port, \
             patch.object(pathlib.Path, 'exists', return_value=False), patch.object(pathlib.Path, 'is_symlink', return_value=False), \
             patch.object(entry, 'props', return_value={'LoadState': 'not-found'}), \
             patch.object(entry.subprocess, 'run', return_value=SimpleNamespace(returncode=1)), patch('builtins.print'):
            entry.preflight(SimpleNamespace())
            free_port.assert_called_once_with(entry.PORT)

    def test_egress_mismatch_fails(self):
        _, _, _, probe = self.probe(['example HTML', '127.0.0.1'])
        with self.assertRaises(entry.Refuse): probe()

    def test_negative_requires_both_destinations_fail(self):
        _, _, curl, probe = self.probe([subprocess.CalledProcessError(22, ['curl'])] * 2, negative=True)
        probe(); self.assertEqual(curl.call_count, 2)

    def test_negative_unexpected_success_fails(self):
        _, _, _, probe = self.probe(['example HTML'], negative=True)
        with self.assertRaises(entry.Refuse): probe()

    def test_killed_child_is_reaped_and_temp_removed(self):
        d, child, _, probe = self.probe(['example HTML', entry.FOREIGN], timeout_wait=True)
        probe()
        child.kill.assert_called_once(); self.assertEqual(child.wait.call_count, 2)
        self.assertEqual(list(d.iterdir()), [])

    def test_no_http_before_owned_listener(self):
        _, child, curl, probe = self.probe([], owns=False)
        with patch.object(entry.time, 'monotonic', side_effect=[0, 0, 10]), patch.object(entry.time, 'sleep'):
            with self.assertRaises(entry.Refuse): probe()
        curl.assert_not_called(); child.terminate.assert_called_once()

    def test_occupied_port_never_spawns_process(self):
        with patch.object(entry, 'free_port', side_effect=OSError()) as free_port, patch.object(entry.subprocess, 'Popen') as popen:
            with self.assertRaises(OSError): entry.probe_socks(pathlib.Path('.'), {}, {})
            free_port.assert_called_once_with(0)
            popen.assert_not_called()

    def test_curl_disables_user_config_and_all_direct_bypass(self):
        with patch.object(entry, 'run', return_value='HTML\n200') as run:
            self.assertEqual(entry.curl_socks(self.PROBE_PORT, 'https://example.com/'), 'HTML')
            argv = run.call_args.args[0]
            self.assertEqual(argv[:3], ['curl', '--disable', '--noproxy'])
            self.assertEqual(argv[3], '')
            self.assertIn('socks5h://127.0.0.1:' + str(self.PROBE_PORT), argv)


class CaddyAdaptTests(unittest.TestCase):
    def config(self, hide):
        return {'apps': {'http': {'servers': {'srv0': {'routes': [
            {'handle': [{'handler': 'subroute', 'routes': [
                {'handle': [{'handler': 'file_server', 'hide': hide}]}]}]}]}}}}}

    def test_staged_generated_hide_matches_live_original_and_candidate(self):
        for name in ('Caddyfile.original', 'Caddyfile.candidate'):
            with self.subTest(name=name):
                source = '/root/mayak-https.fixture/stage/' + name
                raw = self.config([source, '/srv/private'])
                with patch.object(entry, 'run', return_value=json.dumps(raw)) as run:
                    self.assertEqual(entry.adapt(source), self.config([str(entry.CADDY), '/srv/private']))
                self.assertEqual(run.call_args.args[0],
                                 ['caddy', 'adapt', '--config', source, '--adapter', 'caddyfile'])

    def test_only_exact_file_server_hide_entry_is_canonicalized(self):
        source = '/root/mayak-https.fixture/stage/Caddyfile.original'
        hide = ['/srv/private', source + '.bak', source, 'Caddyfile.original', '/other/Caddyfile.original']
        raw = self.config(hide)
        raw['other'] = {'handler': 'reverse_proxy', 'hide': [source], 'path': source}
        with patch.object(entry, 'run', return_value=json.dumps(raw)):
            actual = entry.adapt(source)
        expected = self.config([str(entry.CADDY) if item == source else item for item in hide])
        expected['other'] = raw['other']
        self.assertEqual(actual, expected)

    def test_unrelated_hide_drift_still_blocks_before_probe(self):
        with tempfile.TemporaryDirectory() as td:
            d = pathlib.Path(td)
            source = d / 'Caddyfile.original'
            (d / 'baseline.json').write_text(json.dumps({'identity': {}, 'responses': {}}))
            with patch.object(entry, 'stage_files', return_value={}), patch.object(entry, 'regular'), \
                 patch.object(entry, 'digest', return_value='same'), \
                 patch.object(entry, 'loaded', return_value=self.config([str(entry.CADDY), '/srv/changed'])), \
                 patch.object(entry, 'run', return_value=json.dumps(self.config([str(source), '/srv/private']))), \
                 patch.object(entry, 'probe_socks') as probe:
                with self.assertRaisesRegex(entry.Refuse, 'Caddy disk/runtime drift'):
                    entry.check(SimpleNamespace(stage=d))
                probe.assert_not_called()

    def test_equivalent_generated_hide_retains_identity_and_endpoint_checks(self):
        with tempfile.TemporaryDirectory() as td:
            d = pathlib.Path(td)
            (d / 'baseline.json').write_text(json.dumps({'identity': identity_fixture(), 'responses': {'/': 'body'}}))
            with patch.object(entry, 'stage_files', return_value={}), patch.object(entry, 'regular'), \
                 patch.object(entry, 'digest', return_value='same'), \
                 patch.object(entry, 'loaded', return_value=self.config([str(entry.CADDY)])), \
                 patch.object(entry, 'run', side_effect=lambda argv: json.dumps(self.config([argv[3]]))), \
                 patch.object(entry, 'caddy_identity', return_value=identity_fixture(reset=True)) as identity, \
                 patch.object(entry, 'response_baseline', return_value={'/': 'body'}) as responses:
                for candidate_live in (False, True):
                    entry.check_drift(d, candidate_live=candidate_live)
                self.assertEqual(identity.call_count, 2)
                self.assertEqual(responses.call_count, 2)


class CaddyIdentityTests(unittest.TestCase):
    def test_accounting_reset_matches_old_baseline_without_rewriting_it(self):
        original = identity_fixture()
        before = json.dumps(original)
        self.assertTrue(entry.same_caddy_identity(identity_fixture(reset=True), original))
        self.assertEqual(json.dumps(original), before)

    def test_executable_arguments_ignore_flag_and_hash_changes_do_not_match(self):
        original = identity_fixture()
        for field, value in [('argv', exec_fixture(path='/bin/caddy')),
                             ('argv', exec_fixture(arguments='run --config /etc/caddy/other')),
                             ('argv', exec_fixture(arguments='run --environ --config /etc/caddy/Caddyfile --watch')),
                             ('argv', exec_fixture().replace('ignore_errors=no', 'ignore_errors=yes')),
                             ('unit_sha', 'changed'), ('binary_sha', 'changed')]:
            with self.subTest(field=field, value=value):
                self.assertFalse(entry.same_caddy_identity(dict(original, **{field: value}), original))

    def test_actual_process_identity_is_never_normalized(self):
        original = identity_fixture()
        for field, value in [('pid', 999), ('start', 'different'), ('exe', '/other/caddy'), ('uid', 0)]:
            changed = identity_fixture(reset=True)
            changed['process'][field] = value
            with self.subTest(field=field):
                self.assertFalse(entry.same_caddy_identity(changed, original))

    def test_malformed_or_multiple_commands_are_refused(self):
        command = exec_fixture()
        for value in (None, '', command + command, command.replace(' ; argv[]=', ' ; other='),
                      command.replace('argv[]=/usr/bin/caddy', 'argv[]=/bin/caddy'),
                      command.replace(' --environ', ' "--environ"'), command.replace(' --environ', '\n--environ')):
            with self.subTest(value=value):
                with self.assertRaises(entry.Refuse): entry.exec_start(value)


class ResumeTests(unittest.TestCase):
    @contextlib.contextmanager
    def simulation(self, failure_probe=0):
        with tempfile.TemporaryDirectory() as td, contextlib.ExitStack() as stack:
            d = pathlib.Path(td)
            stack.enter_context(patch.object(entry, 'ROOT', pathlib.PurePosixPath('/opt/mayak/https-entry')))
            stack.enter_context(patch.object(entry, 'UNIT', pathlib.PurePosixPath('/etc/systemd/system/mayak-https-entry.service')))
            m = dict(metadata_fixture=False, path='/mayak-connect/' + 'a' * 36 + '/', inbound_id=str(uuid.uuid4()),
                     files={'Caddyfile.original': 'old', 'Caddyfile.candidate': 'new', 'xray.bin': 'binary', 'xray.json': 'config'})
            cfg = entry.build_xray(str(uuid.uuid4()), m['inbound_id'], m['path'],
                                   dict(transport='raw', flow='xtls-rprx-vision', sni='example.org', sid='1234', pbk='a' * 43))
            (d / 'xray.json').write_text(json.dumps(cfg))
            b = dict(identity=identity_fixture(), loaded={'old': True}, caddy_sha256='old', responses={'/': 'body'})
            (d / 'baseline.json').write_text(json.dumps(b))
            baseline_bytes = (d / 'baseline.json').read_bytes()
            r = dict(installed=True, process={'pid': 99318}, files={
                str(entry.ROOT / 'xray'): {'sha': 'binary'}, str(entry.ROOT / 'config.json'): {'sha': 'config'},
                str(entry.UNIT): {'sha': entry.sha(entry.UNIT_TEXT.encode())}})
            state = {'disk': 'old', 'runtime': b['loaded'], 'active': 'active', 'pid': 99318, 'probes': 0}
            events = []

            def run(argv, **kwargs):
                events.append(('run', argv))
                if argv == ['systemctl', 'reload', 'caddy.service']:
                    state['runtime'] = {state['disk']: True}
                if argv == ['systemctl', 'disable', '--now', entry.SERVICE]:
                    state['active'] = 'inactive'

            def copy(source, destination, expected):
                self.assertEqual(state['disk'], expected)
                events.append(('copy', source.name))
                state['disk'] = 'new' if source.name == 'Caddyfile.candidate' else 'old'

            def probe(*args, **kwargs):
                state['probes'] += 1
                events.append(('probe', state['probes']))
                if state['probes'] == failure_probe:
                    raise entry.Refuse('simulated probe failure')

            stage = stack.enter_context(patch.object(entry, 'stage_files', return_value=m))
            stack.enter_context(patch.object(entry, 'regular'))
            stack.enter_context(patch.object(entry, 'digest', side_effect=lambda p: state['disk'] if p == entry.CADDY else m['files'].get(p.name, 'receipt')))
            stack.enter_context(patch.object(entry, 'adapt', side_effect=lambda p: {'new' if p.name == 'Caddyfile.candidate' else 'old': True}))
            stack.enter_context(patch.object(entry, 'loaded', side_effect=lambda: state['runtime']))
            stack.enter_context(patch.object(entry, 'caddy_identity', return_value=identity_fixture(reset=True)))
            stack.enter_context(patch.object(entry, 'response_baseline', return_value=b['responses']))
            owned = stack.enter_context(patch.object(entry, 'owned', side_effect=lambda d: (r, state['pid'])))
            stack.enter_context(patch.object(entry, 'props', side_effect=lambda s: dict(ActiveState=state['active'], LoadState='loaded', MainPID=str(state['pid']),
                ExecStart=exec_fixture(str(entry.ROOT / 'xray'), 'run -config ' + str(entry.ROOT / 'config.json'), reset=True))))
            listener = stack.enter_context(patch.object(entry, 'listener_owned', return_value=True))
            fresh = stack.enter_context(patch.object(entry, 'fresh_credentials', side_effect=lambda *args: events.append(('fresh',))))
            run_mock = stack.enter_context(patch.object(entry, 'run', side_effect=run))
            copy_mock = stack.enter_context(patch.object(entry, 'atomic_copy', side_effect=copy))
            probes = stack.enter_context(patch.object(entry, 'probe_socks', side_effect=probe))
            saved = stack.enter_context(patch.object(entry, 'save_json', side_effect=lambda p, obj: events.append(('save', p.name))))
            stack.enter_context(patch('builtins.print'))
            yield SimpleNamespace(args=SimpleNamespace(stage=d), m=m, r=r, state=state, events=events, fresh=fresh,
                                  owned=owned, stage=stage, listener=listener, probes=probes, run=run_mock, copy=copy_mock, saved=saved)
            self.assertEqual((d / 'baseline.json').read_bytes(), baseline_bytes)

    def test_resume_repeats_positive_negative_syntax_and_full_verify_without_reinstall(self):
        with self.simulation() as s:
            entry.resume(s.args)
            self.assertEqual(s.fresh.call_count, 2)
            self.assertEqual(s.probes.call_count, 4)
            self.assertFalse(s.probes.call_args_list[0].kwargs.get('negative', False))
            wrong_out = s.probes.call_args_list[1]
            self.assertTrue(wrong_out.kwargs['negative'])
            self.assertEqual(wrong_out.args[2]['streamSettings']['network'], 'raw')
            self.assertEqual(wrong_out.args[2]['settings']['vnext'][0]['users'][0]['flow'], 'xtls-rprx-vision')
            tls_out = s.probes.call_args_list[2].args[2]
            self.assertEqual(tls_out['streamSettings']['security'], 'tls')
            self.assertFalse(tls_out['streamSettings']['tlsSettings']['allowInsecure'])
            self.assertTrue(s.probes.call_args_list[3].kwargs['negative'])
            cmds = [call.args[0] for call in s.run.call_args_list]
            self.assertEqual(cmds, [[str(s.args.stage / 'xray.bin'), 'run', '-test', '-config', str(s.args.stage / 'xray.json')],
                ['caddy', 'validate', '--config', str(s.args.stage / 'Caddyfile.candidate'), '--adapter', 'caddyfile'],
                ['runuser', '-u', entry.USER, '--', str(entry.ROOT / 'xray'), 'run', '-test', '-config', str(entry.ROOT / 'config.json')],
                ['systemctl', 'reload', 'caddy.service']])
            self.assertEqual(s.state['disk'], 'new')
            self.assertEqual(s.state['active'], 'active')
            self.assertEqual([event for event in s.events if event[0] in ('probe', 'copy')],
                             [('probe', 1), ('probe', 2), ('copy', 'Caddyfile.candidate'), ('probe', 3), ('probe', 4)])
            self.assertEqual(s.saved.call_args.args[0].name, 'verified.json')

    def test_resume_rejects_foreign_tampered_rolled_back_or_inactive_admission(self):
        for mutation in ('foreign', 'tampered', 'rolled_back', 'missing_process', 'inactive', 'pid', 'listener', 'fixture',
                         'public_disk', 'public_runtime', 'public_identity', 'public_endpoint', 'unit_hash', 'unit_args'):
            with self.subTest(mutation=mutation), self.simulation() as s:
                if mutation == 'foreign': s.owned.side_effect = entry.Refuse('foreign receipt')
                if mutation == 'tampered': s.r['files'][str(entry.ROOT / 'config.json')]['sha'] = 'changed'
                if mutation == 'rolled_back': s.r['rolled_back'] = True
                if mutation == 'missing_process': del s.r['process']
                if mutation == 'inactive': s.state['active'] = 'inactive'
                if mutation == 'pid': s.state['pid'] = 111
                if mutation == 'listener': s.listener.return_value = False
                if mutation == 'fixture': s.m['metadata_fixture'] = True
                if mutation == 'public_disk': s.state['disk'] = 'foreign'
                if mutation == 'public_runtime': s.state['runtime'] = {'foreign': True}
                if mutation == 'public_identity': entry.caddy_identity.return_value['process']['pid'] = 1
                if mutation == 'public_endpoint': entry.response_baseline.return_value = {'/': 'changed'}
                if mutation == 'unit_hash': s.r['files'][str(entry.UNIT)]['sha'] = 'changed'
                if mutation == 'unit_args':
                    entry.props.side_effect = None
                    entry.props.return_value = dict(ActiveState='active', LoadState='loaded', MainPID='99318',
                        ExecStart=exec_fixture(str(entry.ROOT / 'xray'), 'run -config ' + str(entry.ROOT / 'config.json') + ' -other'))
                with self.assertRaises(entry.Refuse): entry.resume(s.args)
                s.probes.assert_not_called(); s.run.assert_not_called(); s.copy.assert_not_called(); s.fresh.assert_not_called()

    def test_resume_outbound_failure_recovers_without_public_switch(self):
        with self.simulation(failure_probe=1) as s:
            with self.assertRaisesRegex(entry.Refuse, 'owned route/service recovery completed'): entry.resume(s.args)
            s.copy.assert_not_called()
            self.assertEqual(s.state['disk'], 'old')
            self.assertEqual(s.state['active'], 'inactive')
            self.assertTrue(s.r['rolled_back'])

    def test_resume_tls_failure_restores_caddy_before_stopping_owned_service(self):
        with self.simulation(failure_probe=3) as s:
            with self.assertRaisesRegex(entry.Refuse, 'owned route/service recovery completed'): entry.resume(s.args)
            events = [event for event in s.events if event[0] == 'copy' or
                      event[0] == 'run' and event[1][0] == 'systemctl']
            self.assertEqual(events, [('copy', 'Caddyfile.candidate'), ('run', ['systemctl', 'reload', 'caddy.service']),
                ('copy', 'Caddyfile.original'), ('run', ['systemctl', 'reload', 'caddy.service']),
                ('run', ['systemctl', 'disable', '--now', entry.SERVICE])])
            self.assertEqual(s.state['runtime'], {'old': True})
            self.assertEqual(s.state['active'], 'inactive')

    def test_resume_reports_incomplete_recovery_if_guarded_rollback_refuses(self):
        with self.simulation(failure_probe=1) as s, patch.object(entry, 'rollback', side_effect=entry.Refuse('unexpected drift')):
            with self.assertRaisesRegex(entry.Refuse, 'RECOVERY INCOMPLETE'): entry.resume(s.args)
            s.copy.assert_not_called()
            self.assertEqual(s.state['active'], 'active')

    def test_resume_rechecks_credentials_and_caddy_drift_immediately_before_switch(self):
        for mutation in ('credentials', 'caddy'):
            with self.subTest(mutation=mutation), self.simulation() as s:
                if mutation == 'credentials':
                    s.fresh.side_effect = [None, entry.Refuse('eligibility changed')]
                else:
                    original_run = s.run.side_effect

                    def run(argv, **kwargs):
                        original_run(argv, **kwargs)
                        if argv[0] == 'runuser': s.state['runtime'] = {'foreign': True}

                    s.run.side_effect = run
                with self.assertRaises(entry.Refuse): entry.resume(s.args)
                s.copy.assert_not_called()
                self.assertEqual(s.probes.call_count, 2)
                self.assertEqual(s.state['active'], 'inactive' if mutation == 'credentials' else 'active')


class RecoveryTests(unittest.TestCase):
    def test_actual_owned_predicate_rejects_modified_unit_hash(self):
        files = {str(p): {'sha': 'original'} for p in (entry.ROOT / 'xray', entry.ROOT / 'config.json', entry.UNIT)}
        r = {'installed': True, 'files': files}
        with patch.dict(sys.modules, {'pwd': SimpleNamespace()}), \
             patch.object(entry, 'receipt', return_value=r), \
             patch.object(entry, 'stamp', side_effect=lambda p: {'sha': 'modified'} if p == entry.UNIT else {'sha': 'original'}):
            with self.assertRaisesRegex(entry.Refuse, 'ownership/hash drift'):
                entry.owned(pathlib.Path('/stage'))

    def test_actual_owned_predicate_rejects_foreign_receipt_paths(self):
        with patch.dict(sys.modules, {'pwd': SimpleNamespace()}), \
             patch.object(entry, 'receipt', return_value={'installed': True, 'files': {'/foreign': {}}}), \
             patch.object(entry, 'stamp') as stamp:
            with self.assertRaises(entry.Refuse): entry.owned(pathlib.Path('/stage'))
            stamp.assert_not_called()

    def test_loaded_caddy_drift_blocks_check_before_any_probe(self):
        with tempfile.TemporaryDirectory() as td:
            d = pathlib.Path(td)
            (d / 'baseline.json').write_text(json.dumps({'identity': {}, 'responses': {}}))
            with patch.object(entry, 'stage_files', return_value={}), patch.object(entry, 'regular'), \
                 patch.object(entry, 'digest', return_value='same'), patch.object(entry, 'loaded', return_value={'foreign': 1}), \
                 patch.object(entry, 'adapt', return_value={'expected': 1}), patch.object(entry, 'probe_socks') as probe:
                with self.assertRaises(entry.Refuse): entry.check(SimpleNamespace(stage=d))
                probe.assert_not_called()

    def test_rollback_restores_caddy_before_examining_modified_service(self):
        with tempfile.TemporaryDirectory() as td:
            d = pathlib.Path(td)
            m = {'files': {'Caddyfile.original': 'old', 'Caddyfile.candidate': 'new'}}
            b = dict(identity=identity_fixture(), loaded={'old': True}, caddy_sha256='old', responses={})
            (d / 'baseline.json').write_text(json.dumps(b))
            calls = []
            with patch.object(entry, 'stage_files', return_value=m), patch.object(entry, 'regular'), \
                 patch.object(entry, 'caddy_identity', return_value=b['identity']), \
                 patch.object(entry, 'digest', side_effect=['new', 'old']), \
                 patch.object(entry, 'loaded', side_effect=[{'new': True}, {'new': True}, b['loaded']]), \
                 patch.object(entry, 'adapt', return_value={'new': True}), \
                 patch.object(entry, 'atomic_copy', side_effect=lambda *a: calls.append('restore')), \
                 patch.object(entry, 'run', side_effect=lambda argv: calls.append(argv)), \
                 patch.object(entry, 'owned', side_effect=entry.Refuse('installed file ownership/hash drift')):
                with self.assertRaises(entry.Refuse): entry.rollback(SimpleNamespace(stage=d))
            self.assertEqual(calls, ['restore', ['systemctl', 'reload', 'caddy.service']])

    def test_apply_failure_before_outbound_gate_never_installs(self):
        with patch.object(entry, 'stage_files', return_value={}), patch.object(entry, 'check', side_effect=entry.Refuse('failed')), \
             patch.object(entry, 'run') as run, patch.object(entry, 'save_json') as save:
            with self.assertRaises(entry.Refuse): entry.apply(SimpleNamespace(stage=pathlib.Path('/nonexistent')))
            run.assert_not_called(); save.assert_not_called()

    def test_export_cannot_bypass_full_verification(self):
        with patch.object(entry, 'verify', side_effect=entry.Refuse('failed')), patch.object(entry, 'put') as put:
            with self.assertRaises(entry.Refuse):
                entry.client_link(SimpleNamespace(stage=pathlib.Path('/stage'), out=pathlib.Path('/private/profile')))
            put.assert_not_called()

    def test_tls_outbound_requires_certificate_and_matching_path_host(self):
        route = '/mayak-connect/' + 'a' * 36 + '/'
        outbound = entry.tls_outbound({'path': route}, str(uuid.uuid4()))
        stream = outbound['streamSettings']
        self.assertFalse(stream['tlsSettings']['allowInsecure'])
        self.assertEqual(stream['tlsSettings']['serverName'], entry.DOMAIN)
        self.assertEqual(stream['xhttpSettings'], dict(host=entry.DOMAIN, path=route, mode='packet-up'))


if __name__ == '__main__':
    unittest.main()
