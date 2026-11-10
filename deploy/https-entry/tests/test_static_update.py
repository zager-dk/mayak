import contextlib
import json
import os
import pathlib
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import test_https_entry as base

entry, identity_fixture = base.entry, base.identity_fixture
ACTUAL_STATIC_TEMP = entry.static_temp


class StaticUpdateTests(unittest.TestCase):
    @contextlib.contextmanager
    def scenario(self):
        with tempfile.TemporaryDirectory() as td, contextlib.ExitStack() as stack:
            root = pathlib.Path(td)
            d, bundle, web = root / 'stage', root / 'bundle', root / 'web'
            for p in (d, bundle, web, web / 'my'):
                p.mkdir()
            targets = {'/': web / 'index.html', '/my/': web / 'my/index.html'}
            m = base.StageTests().make_stage(d)
            m.update(metadata_fixture=False, database='mayak', device_id=None)
            old = {'/': b'<html>old welcome</html>', '/my/': b'<html>old cabinet</html>'}
            new = {'/': b'<html>new welcome</html>', '/my/': b'<html>new cabinet</html>'}
            protected = {endpoint: {'status': '200', 'sha256': entry.sha(endpoint.encode())}
                         for endpoint in entry.ENDPOINTS if endpoint not in targets}
            responses = dict(protected, **{endpoint: {'status': '200', 'sha256': entry.sha(data)} for endpoint, data in old.items()})
            b = dict(caddy_sha256=m['files']['Caddyfile.original'], identity=identity_fixture(),
                     loaded={'original': True}, responses=responses)
            (d / 'baseline.json').write_text(json.dumps(b))
            m['files']['baseline.json'] = entry.digest(d / 'baseline.json')
            (d / 'manifest.json').write_text(json.dumps(m))
            r = {'installed': True, 'manifest_sha': entry.digest(d / 'manifest.json')}
            (d / 'receipt.json').write_text(json.dumps(r))
            for endpoint, target in targets.items():
                target.write_bytes(old[endpoint])
                (bundle / entry.STATIC_NAMES[endpoint]).write_bytes(new[endpoint])
            spec = {endpoint: {'old_sha256': entry.sha(old[endpoint]), 'new_sha256': entry.sha(new[endpoint])} for endpoint in targets}
            (bundle / 'manifest.json').write_text(json.dumps(spec, sort_keys=True))
            caddy = root / 'Caddyfile.live'
            caddy.write_bytes((d / 'Caddyfile.candidate').read_bytes())
            state = dict(runtime={'candidate': True}, active='active', moves=0, temp=0, http_mismatch=False, protected_drift=False)
            events = []

            def regular(p, private=True):
                s = pathlib.Path(p).stat()
                return SimpleNamespace(st_ino=s.st_ino, st_dev=s.st_dev, st_uid=0, st_gid=986, st_mode=0o100640)

            def put(p, data, mode=0o600):
                if p.exists():
                    raise FileExistsError()
                p.write_bytes(data.encode() if isinstance(data, str) else data)

            def prepare(source, target, before):
                self.assertEqual(entry.stamp(target), before)
                state['temp'] += 1
                tmp = target.parent / ('.mayak-static-test' + str(state['temp']))
                tmp.write_bytes(source.read_bytes())
                return tmp, entry.stamp(tmp)

            actual_move = entry.static_move

            def move(*args):
                state['moves'] += 1
                events.append(('move', args[1].name))
                # Windows: exercise real guarded replace; Linux directory fsync is mocked.
                with patch.object(entry.os, 'O_DIRECTORY', 0, create=True), patch.object(entry.os, 'open', return_value=999), \
                     patch.object(entry.os, 'fsync'), patch.object(entry.os, 'close'):
                    return actual_move(*args)

            def http():
                out = dict(protected)
                for endpoint, target in targets.items():
                    digest = entry.digest(target)
                    if state['http_mismatch'] and digest == entry.sha(new[endpoint]):
                        digest = entry.sha(b'unexpected rendered response')
                    out[endpoint] = {'status': '200', 'sha256': digest}
                if state['protected_drift']:
                    out['/admin/'] = {'status': '200', 'sha256': 'unexpected'}
                return out

            def run(argv, **kwargs):
                events.append(('run', argv))
                if argv == ['systemctl', 'reload', 'caddy.service']:
                    state['runtime'] = {'original': True}
                if argv == ['systemctl', 'disable', '--now', entry.SERVICE]:
                    state['active'] = 'inactive'

            stack.enter_context(patch.object(entry, 'STATIC_TARGETS', targets))
            stack.enter_context(patch.object(entry, 'CADDY', caddy))
            regular_mock = stack.enter_context(patch.object(entry, 'regular', side_effect=regular))
            stack.enter_context(patch.object(entry, 'private_dir'))
            stack.enter_context(patch.object(entry, 'parents_safe'))
            stack.enter_context(patch.object(entry, 'put', side_effect=put))
            stack.enter_context(patch.object(entry, 'static_temp', side_effect=prepare))
            stack.enter_context(patch.object(entry, 'static_sync'))
            moves = stack.enter_context(patch.object(entry, 'static_move', side_effect=move))
            stack.enter_context(patch.object(entry, 'loaded', side_effect=lambda: state['runtime']))
            stack.enter_context(patch.object(entry, 'adapt', side_effect=lambda p: {'original' if p.name.endswith('.original') else 'candidate': True}))
            stack.enter_context(patch.object(entry, 'caddy_identity', return_value=identity_fixture(reset=True)))
            response = stack.enter_context(patch.object(entry, 'response_baseline', side_effect=http))
            live = stack.enter_context(patch.object(entry, 'live_entry'))
            fresh = stack.enter_context(patch.object(entry, 'fresh_credentials'))
            stack.enter_context(patch.object(entry, 'owned', return_value=(r, 99318)))
            stack.enter_context(patch.object(entry, 'listener_owned', return_value=True))
            probes = stack.enter_context(patch.object(entry, 'probe_socks', side_effect=lambda *a, **kw: events.append(('probe', kw.get('negative', False)))))
            run_mock = stack.enter_context(patch.object(entry, 'run', side_effect=run))
            stack.enter_context(patch.object(entry, 'props', side_effect=lambda s: {'ActiveState': state['active']}))
            stack.enter_context(patch.object(entry, 'atomic_copy', side_effect=lambda src, dst, expected: dst.write_bytes(src.read_bytes())))
            stack.enter_context(patch('builtins.print'))
            original = {name: (d / name).read_bytes() for name in ('baseline.json', 'manifest.json', 'Caddyfile.original', 'Caddyfile.candidate')}
            args = SimpleNamespace(stage=d, bundle=bundle, bundle_sha256=entry.digest(bundle / 'manifest.json'))
            yield SimpleNamespace(args=args, d=d, b=b, m=m, spec=spec, old=old, new=new, targets=targets, state=state,
                events=events, moves=moves, actual_move=move, response=response, http=http, probes=probes, regular=regular_mock,
                fresh=fresh, live=live, run=run_mock, caddy=caddy)
            for name, value in original.items():
                self.assertEqual((d / name).read_bytes(), value)

    def test_success_preserves_original_proof_and_changes_only_two_response_expectations(self):
        with self.scenario() as s:
            caddy = s.caddy.read_bytes()
            entry.update_static(s.args)
            plan, state = entry.static_revision(s.d)
            self.assertEqual(state['status'], 'committed')
            self.assertEqual(s.caddy.read_bytes(), caddy)
            self.assertEqual(s.probes.call_count, 4)
            self.assertEqual(s.events[:2], [('probe', False), ('probe', True)])
            s.run.assert_not_called()
            self.assertEqual(s.fresh.call_count, 2)
            expected = entry.response_expectations(s.d, s.b)
            for endpoint in entry.ENDPOINTS:
                self.assertEqual(expected[endpoint], {'status': '200', 'sha256': entry.sha(s.new[endpoint])}
                                 if endpoint in s.new else s.b['responses'][endpoint])
            for endpoint, item in plan['files'].items():
                self.assertEqual((item['before']['uid'], item['after']['gid'], item['after']['mode']), (0, 986, 0o640))
                self.assertEqual(s.targets[endpoint].read_bytes(), s.new[endpoint])
            self.assertEqual((s.d / 'static-baseline.json').read_bytes(), (s.d / 'baseline.json').read_bytes())
            self.assertEqual((s.d / 'static-manifest.json').read_bytes(), (s.d / 'manifest.json').read_bytes())
            entry.client_link(SimpleNamespace(stage=s.d, out=s.d.parent / 'private-profile'))
            self.assertTrue((s.d.parent / 'private-profile').exists())

    def test_real_temporary_writer_copies_bytes_and_applies_original_owner_group_mode(self):
        with self.scenario() as s, patch.object(entry.os, 'fchown', create=True) as chown, \
             patch.object(entry.os, 'fchmod', create=True) as chmod:
            target = s.targets['/']
            before = entry.stamp(target)
            tmp, after = ACTUAL_STATIC_TEMP(s.args.bundle / 'index.html', target, before)
            self.assertEqual(tmp.parent, target.parent)
            self.assertEqual(tmp.read_bytes(), s.new['/'])
            self.assertEqual(after['sha'], entry.sha(s.new['/']))
            self.assertEqual(chown.call_args.args[1:], (0, 986))
            self.assertEqual(chmod.call_args.args[1:], (0o640,))
            tmp.unlink()

    def test_invalid_bundle_members_hashes_or_paths_refuse_before_target_change(self):
        for mutation in ('missing', 'extra', 'path', 'tampered', 'unknown_hash', 'bad_hash', 'credential'):
            with self.subTest(mutation=mutation), self.scenario() as s:
                p = s.args.bundle
                if mutation == 'missing': (p / 'my.html').unlink()
                if mutation == 'extra': (p / 'extra.html').write_text('<html>extra</html>')
                if mutation == 'path': s.spec['/']['target'] = '/other/index.html'
                if mutation == 'tampered': (p / 'index.html').write_bytes(b'<html>tampered</html>')
                if mutation == 'bad_hash': s.spec['/']['new_sha256'] = 'unknown'
                if mutation == 'credential':
                    (p / 'index.html').write_text('<html>vless://secret</html>')
                    s.spec['/']['new_sha256'] = entry.digest(p / 'index.html')
                if mutation in ('path', 'bad_hash', 'credential'):
                    (p / 'manifest.json').write_text(json.dumps(s.spec))
                    s.args.bundle_sha256 = entry.digest(p / 'manifest.json')
                if mutation == 'unknown_hash': s.args.bundle_sha256 = '0' * 64
                with self.assertRaises(entry.Refuse): entry.update_static(s.args)
                s.moves.assert_not_called()
                for endpoint, target in s.targets.items(): self.assertEqual(target.read_bytes(), s.old[endpoint])

    def test_bundle_regular_and_private_guards_are_required(self):
        with self.scenario() as s:
            original = s.regular.side_effect

            def guard(p, private=True):
                if p.parent == s.args.bundle: raise entry.Refuse('unsafe linked or public file')
                return original(p, private)

            s.regular.side_effect = guard
            with self.assertRaisesRegex(entry.Refuse, 'unsafe linked or public file'): entry.update_static(s.args)
            s.moves.assert_not_called()

    def test_wrong_target_file_even_if_http_is_old_refuses(self):
        with self.scenario() as s:
            s.targets['/'].write_bytes(b'wrong target file')
            s.response.side_effect = None; s.response.return_value = s.b['responses']
            with self.assertRaisesRegex(entry.Refuse, 'static target/HTTP old identity mismatch'): entry.update_static(s.args)
            s.moves.assert_not_called()

    def test_unexpected_target_group_or_mode_is_refused(self):
        for field, value in (('st_gid', 999), ('st_mode', 0o100644)):
            with self.subTest(field=field), self.scenario() as s:
                original = s.regular.side_effect

                def regular(p, private=True):
                    result = original(p, private)
                    if p in s.targets.values(): setattr(result, field, value)
                    return result

                s.regular.side_effect = regular
                with self.assertRaisesRegex(entry.Refuse, 'unexpected static target ownership/mode'): entry.update_static(s.args)
                s.moves.assert_not_called()

    def test_failure_after_first_file_or_after_rename_restores_both(self):
        for after_rename in (False, True):
            with self.subTest(after_rename=after_rename), self.scenario() as s:
                calls = 0

                def move(*args):
                    nonlocal calls
                    calls += 1
                    if calls == (1 if after_rename else 2):
                        if after_rename: s.actual_move(*args)
                        raise OSError('injected failure')
                    return s.actual_move(*args)

                s.moves.side_effect = move
                with self.assertRaisesRegex(entry.Refuse, 'owned HTML restored and fully verified'): entry.update_static(s.args)
                self.assertEqual(entry.static_revision(s.d)[1]['status'], 'rolled_back')
                for endpoint, target in s.targets.items(): self.assertEqual(target.read_bytes(), s.old[endpoint])

    def test_unexpected_new_http_body_rolls_back_to_old_exact_responses(self):
        with self.scenario() as s:
            s.state['http_mismatch'] = True
            with self.assertRaisesRegex(entry.Refuse, 'owned HTML restored and fully verified'): entry.update_static(s.args)
            self.assertEqual(entry.response_expectations(s.d, s.b), s.b['responses'])
            for endpoint, target in s.targets.items(): self.assertEqual(target.read_bytes(), s.old[endpoint])

    def test_pending_revision_blocks_generic_verify_and_recovery_uses_owned_stamps(self):
        with self.scenario() as s:
            entry.update_static(s.args)
            plan, state = entry.static_revision(s.d)
            state['status'] = 'verifying'
            entry.save_json(s.d / 'static-state.json', state)
            before = s.probes.call_count
            with self.assertRaisesRegex(entry.Refuse, 'static transaction pending'): entry.verify(s.args)
            self.assertEqual(s.probes.call_count, before)
            entry.rollback_static(s.args)
            self.assertEqual(entry.static_revision(s.d)[1]['status'], 'rolled_back')

    def test_foreign_same_bytes_inode_drift_refuses_recovery_before_either_file_change(self):
        with self.scenario() as s:
            entry.update_static(s.args)
            foreign = s.targets['/'].with_name('foreign')
            foreign.write_bytes(s.new['/'])
            os.replace(foreign, s.targets['/'])
            moves = s.moves.call_count
            with self.assertRaisesRegex(entry.Refuse, 'RECOVERY INCOMPLETE'): entry.rollback_static(s.args)
            self.assertEqual(s.moves.call_count, moves)
            self.assertEqual(entry.static_revision(s.d)[1]['status'], 'recovery_incomplete')

    def test_tampered_history_or_state_refuses_verification(self):
        for name in ('static-new-index.html', 'static-baseline.json', 'static-plan.json'):
            with self.subTest(name=name), self.scenario() as s:
                entry.update_static(s.args)
                (s.d / name).write_text('{}')
                before = s.probes.call_count
                with self.assertRaises(entry.Refuse): entry.verify(s.args)
                self.assertEqual(s.probes.call_count, before)

    def test_protected_response_drift_is_never_accepted(self):
        with self.scenario() as s:
            def move(*args):
                result = s.actual_move(*args)
                if s.state['moves'] == 2: s.state['protected_drift'] = True
                return result

            s.moves.side_effect = move
            with self.assertRaisesRegex(entry.Refuse, 'RECOVERY INCOMPLETE'): entry.update_static(s.args)
            self.assertEqual(entry.static_revision(s.d)[1]['status'], 'recovery_incomplete')
            for endpoint, target in s.targets.items(): self.assertEqual(target.read_bytes(), s.old[endpoint])
            s.state['protected_drift'] = False
            entry.rollback_static(s.args)

    def test_vpn_rollback_preserves_accepted_ui_and_original_caddy_rollback(self):
        with self.scenario() as s:
            entry.update_static(s.args)
            entry.rollback(s.args)
            self.assertEqual(s.caddy.read_bytes(), (s.d / 'Caddyfile.original').read_bytes())
            for endpoint, target in s.targets.items(): self.assertEqual(target.read_bytes(), s.new[endpoint])
            self.assertEqual(entry.static_revision(s.d)[1]['status'], 'committed')
            self.assertEqual(s.state['active'], 'inactive')

    def test_repeat_publish_refuses_with_existing_revision(self):
        with self.scenario() as s:
            entry.update_static(s.args)
            moves = s.moves.call_count
            with self.assertRaisesRegex(entry.Refuse, 'static revision already exists'): entry.update_static(s.args)
            self.assertEqual(s.moves.call_count, moves)


if __name__ == '__main__':
    unittest.main()
