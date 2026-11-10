import contextlib
import json
import pathlib
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import test_https_entry as base

entry, identity_fixture = base.entry, base.identity_fixture


class AdminUpdateTests(unittest.TestCase):
    @contextlib.contextmanager
    def scenario(self):
        with tempfile.TemporaryDirectory() as td, contextlib.ExitStack() as stack:
            root = pathlib.Path(td)
            d, bundle, static_bundle, web = root / 'stage', root / 'admin-bundle', root / 'static-bundle', root / 'web'
            for p in (d, bundle, static_bundle, web, web / 'my', web / 'admin'):
                p.mkdir()
            targets = {'/': web / 'index.html', '/my/': web / 'my/index.html'}
            admin_targets = {'/admin/': web / 'admin/index.html'}
            all_targets = dict(targets, **admin_targets)
            m = base.StageTests().make_stage(d)
            m.update(metadata_fixture=False, database='mayak', device_id=None)
            old = {'/': b'<html>old welcome</html>', '/my/': b'<html>old cabinet</html>',
                   '/admin/': b'<html>old admin</html>'}
            static_new = {'/': b'<html>new welcome</html>', '/my/': b'<html>new cabinet</html>'}
            new = b'<html><script>const link="vless://"+userId</script>new admin</html>'
            protected = {endpoint: {'status': '200', 'sha256': entry.sha(endpoint.encode())}
                         for endpoint in entry.ENDPOINTS if endpoint not in all_targets}
            responses = dict(protected, **{endpoint: {'status': '200', 'sha256': entry.sha(data)}
                                           for endpoint, data in old.items()})
            b = dict(caddy_sha256=m['files']['Caddyfile.original'], identity=identity_fixture(),
                     loaded={'original': True}, responses=responses)
            (d / 'baseline.json').write_text(json.dumps(b))
            m['files']['baseline.json'] = entry.digest(d / 'baseline.json')
            (d / 'manifest.json').write_text(json.dumps(m))
            r = {'installed': True, 'manifest_sha': entry.digest(d / 'manifest.json')}
            (d / 'receipt.json').write_text(json.dumps(r))
            (d / 'verified.json').write_text(json.dumps({'manifest_sha': entry.digest(d / 'manifest.json')}))
            for endpoint, target in all_targets.items():
                target.write_bytes(old[endpoint])
                if endpoint in targets:
                    (static_bundle / entry.STATIC_NAMES[endpoint]).write_bytes(static_new[endpoint])
            static_spec = {endpoint: {'old_sha256': entry.sha(old[endpoint]),
                                      'new_sha256': entry.sha(static_new[endpoint])} for endpoint in targets}
            (static_bundle / 'manifest.json').write_text(json.dumps(static_spec))
            (bundle / 'admin.html').write_bytes(new)
            (bundle / 'manifest.json').write_text(json.dumps({'/admin/': {
                'old_sha256': entry.sha(old['/admin/']), 'new_sha256': entry.sha(new)}}))
            caddy = root / 'Caddyfile.live'
            caddy.write_bytes((d / 'Caddyfile.candidate').read_bytes())
            state = dict(runtime={'candidate': True}, active='active', moves=0, temp=0,
                         http_mismatch=False, protected_drift=False)
            events = []

            def regular(p, private=True):
                s = pathlib.Path(p).stat()
                return SimpleNamespace(st_ino=s.st_ino, st_dev=s.st_dev, st_uid=0, st_gid=986, st_mode=0o100640)

            def put(p, data, mode=0o600):
                if p.exists(): raise FileExistsError()
                p.write_bytes(data.encode() if isinstance(data, str) else data)

            def prepare(source, target, before):
                self.assertEqual(entry.stamp(target), before)
                state['temp'] += 1
                tmp = target.parent / ('.mayak-static-test' + str(state['temp']))
                tmp.write_bytes(source.read_bytes())
                return tmp, entry.stamp(tmp)

            actual_move = entry.static_move
            def move(*args):
                state['moves'] += 1; events.append(('move', args[1].name))
                with patch.object(entry.os, 'O_DIRECTORY', 0, create=True), patch.object(entry.os, 'open', return_value=999), \
                     patch.object(entry.os, 'fsync'), patch.object(entry.os, 'close'):
                    return actual_move(*args)

            def http():
                out = dict(protected)
                for endpoint, target in all_targets.items():
                    body = entry.digest(target)
                    if state['http_mismatch'] and body == entry.sha(new): body = entry.sha(b'wrong HTTP body')
                    out[endpoint] = {'status': '200', 'sha256': body}
                return out

            def run(argv, **kwargs):
                events.append(('run', argv))
                if argv == ['systemctl', 'reload', 'caddy.service']: state['runtime'] = {'original': True}
                if argv == ['systemctl', 'disable', '--now', entry.SERVICE]: state['active'] = 'inactive'

            stack.enter_context(patch.object(entry, 'STATIC_TARGETS', targets))
            stack.enter_context(patch.object(entry, 'ADMIN_TARGETS', admin_targets))
            stack.enter_context(patch.object(entry, 'CADDY', caddy))
            stack.enter_context(patch.object(entry, 'regular', side_effect=regular))
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
            originals = {name: (d / name).read_bytes() for name in ('baseline.json', 'manifest.json', 'Caddyfile.original', 'Caddyfile.candidate')}
            args = SimpleNamespace(stage=d, bundle=bundle, bundle_sha256=entry.digest(bundle / 'manifest.json'))
            yield SimpleNamespace(args=args, d=d, b=b, m=m, old=old, new=new, targets=targets,
                admin_targets=admin_targets, all_targets=all_targets, static_bundle=static_bundle,
                static_new=static_new, state=state, events=events,
                moves=moves, actual_move=actual_move, response=response, http=http, probes=probes,
                fresh=fresh, live=live, run=run_mock, caddy=caddy, originals=originals)
            for name, value in originals.items(): self.assertEqual((d / name).read_bytes(), value)

    def test_success_preserves_response_overlay_and_main_rollback(self):
        with self.scenario() as s:
            s.state['active'] = 'active'
            s.args.bundle = s.static_bundle
            s.args.bundle_sha256 = entry.digest(s.static_bundle / 'manifest.json')
            entry.update_static(s.args)
            static_plan_bytes = (s.d / 'static-plan.json').read_bytes()
            static_state_bytes = (s.d / 'static-state.json').read_bytes()
            s.args.bundle = s.d.parent / 'admin-bundle'
            s.args.bundle_sha256 = entry.digest(s.args.bundle / 'manifest.json')
            caddy = s.caddy.read_bytes()
            entry.update_admin(s.args)
            plan, state = entry.admin_revision(s.d)
            self.assertEqual(state['status'], 'committed')
            self.assertEqual(s.caddy.read_bytes(), caddy)
            self.assertEqual(s.probes.call_count, 8)
            expected = entry.response_expectations(s.d, s.b)
            self.assertEqual(expected['/admin/'], {'status': '200', 'sha256': entry.sha(s.new)})
            for endpoint in ('/', '/my/'):
                self.assertEqual(expected[endpoint], {'status': '200', 'sha256': entry.sha(s.static_new[endpoint])})
            self.assertEqual(s.b['responses']['/health'], expected['/health'])
            self.assertEqual(s.fresh.call_count, 4)
            self.assertEqual((s.d / 'baseline.json').read_bytes(), s.originals['baseline.json'])
            self.assertEqual((s.d / 'manifest.json').read_bytes(), s.originals['manifest.json'])
            entry.rollback(s.args)
            self.assertEqual(s.admin_targets['/admin/'].read_bytes(), s.new)
            self.assertEqual(entry.admin_revision(s.d)[1]['status'], 'committed')
            self.assertEqual((s.d / 'static-plan.json').read_bytes(), static_plan_bytes)
            self.assertEqual((s.d / 'static-state.json').read_bytes(), static_state_bytes)

    def test_publish_http_failure_restores_old_admin(self):
        with self.scenario() as s:
            s.state['http_mismatch'] = True
            with self.assertRaisesRegex(entry.Refuse, 'owned HTML restored and fully verified'):
                entry.update_admin(s.args)
            self.assertEqual(entry.admin_revision(s.d)[1]['status'], 'rolled_back')
            self.assertEqual(s.admin_targets['/admin/'].read_bytes(), s.old['/admin/'])

    def test_repeat_publish_and_foreign_inode_drift_refuse(self):
        with self.scenario() as s:
            entry.update_admin(s.args)
            moves = s.moves.call_count
            with self.assertRaisesRegex(entry.Refuse, 'admin revision already exists'):
                entry.update_admin(s.args)
            self.assertEqual(s.moves.call_count, moves)
            foreign = s.admin_targets['/admin/'].with_name('foreign')
            foreign.write_bytes(s.new); foreign.replace(s.admin_targets['/admin/'])
            with self.assertRaisesRegex(entry.Refuse, 'admin target file identity drift'):
                entry.rollback_admin(s.args)

    def test_explicit_admin_rollback_then_static_rollback_preserves_protected_endpoints(self):
        with self.scenario() as s:
            s.args.bundle = s.static_bundle
            s.args.bundle_sha256 = entry.digest(s.static_bundle / 'manifest.json')
            entry.update_static(s.args)
            s.args.bundle = s.d.parent / 'admin-bundle'
            s.args.bundle_sha256 = entry.digest(s.args.bundle / 'manifest.json')
            entry.update_admin(s.args)
            entry.rollback_admin(s.args)
            self.assertEqual(entry.admin_revision(s.d)[1]['status'], 'rolled_back')
            self.assertEqual(s.admin_targets['/admin/'].read_bytes(), s.old['/admin/'])
            entry.rollback_static(s.args)
            self.assertEqual(entry.static_revision(s.d)[1]['status'], 'rolled_back')
            for endpoint in ('/', '/my/'):
                self.assertEqual(s.targets[endpoint].read_bytes(), s.old[endpoint])
            self.assertEqual(entry.response_expectations(s.d, s.b)['/admin/'], s.b['responses']['/admin/'])

    def test_static_rollback_refusal_does_not_damage_receipt_or_block_admin_rollback(self):
        with self.scenario() as s:
            s.args.bundle = s.static_bundle
            s.args.bundle_sha256 = entry.digest(s.static_bundle / 'manifest.json')
            entry.update_static(s.args)
            s.args.bundle = s.d.parent / 'admin-bundle'
            s.args.bundle_sha256 = entry.digest(s.args.bundle / 'manifest.json')
            entry.update_admin(s.args)
            static_state = (s.d / 'static-state.json').read_bytes()
            target = s.targets['/']
            before = entry.stamp(target)
            moves = s.moves.call_count
            with self.assertRaisesRegex(entry.Refuse, 'admin revision is active or pending'):
                entry.rollback_static(s.args)
            self.assertEqual((s.d / 'static-state.json').read_bytes(), static_state)
            self.assertEqual(entry.stamp(target), before)
            self.assertEqual(s.moves.call_count, moves)
            entry.rollback_admin(s.args)
            self.assertEqual(entry.admin_revision(s.d)[1]['status'], 'rolled_back')

    def test_pending_admin_recovery_refuses_runtime_drift_before_journal_or_target_change(self):
        with self.scenario() as s:
            entry.update_admin(s.args)
            _, state = entry.admin_revision(s.d)
            state['status'] = 'verifying'
            entry.save_json(s.d / 'admin-state.json', state)
            state_before = (s.d / 'admin-state.json').read_bytes()
            target = s.admin_targets['/admin/']
            target_before = entry.stamp(target)
            moves = s.moves.call_count
            s.state['runtime'] = {'foreign': True}
            with self.assertRaisesRegex(entry.Refuse, 'Caddy disk/runtime drift'):
                entry.rollback_admin(s.args)
            self.assertEqual((s.d / 'admin-state.json').read_bytes(), state_before)
            self.assertEqual(entry.stamp(target), target_before)
            self.assertEqual(s.moves.call_count, moves)

    def test_interrupted_publish_state_recovers_by_guarded_admin_rollback(self):
        with self.scenario() as s:
            entry.update_admin(s.args)
            plan, state = entry.admin_revision(s.d)
            state['status'] = 'verifying'
            entry.save_json(s.d / 'admin-state.json', state)
            entry.rollback_admin(s.args)
            self.assertEqual(entry.admin_revision(s.d)[1]['status'], 'rolled_back')
            self.assertEqual(s.admin_targets['/admin/'].read_bytes(), s.old['/admin/'])

    def test_admin_receipts_bind_real_stage_bundle_and_verification_anchors(self):
        with self.scenario() as s:
            entry.update_admin(s.args)
            plan, state = entry.admin_revision(s.d)
            self.assertEqual(plan['reviewed_bundle_manifest_sha256'], entry.digest(s.d / 'admin-bundle-manifest.json'))

            # Replacing a copied stage manifest and rehashing the local journal
            # still cannot detach it from the live stage manifest anchor.
            (s.d / 'admin-manifest.json').write_text('{}')
            plan['history']['admin-manifest.json'] = entry.digest(s.d / 'admin-manifest.json')
            entry.save_json(s.d / 'admin-plan.json', plan)
            state['plan_sha256'] = entry.digest(s.d / 'admin-plan.json')
            entry.save_json(s.d / 'admin-state.json', state)
            with self.assertRaisesRegex(entry.Refuse, 'proof binding mismatch'):
                entry.admin_revision(s.d)

        with self.scenario() as s:
            entry.update_admin(s.args)
            receipt = json.loads((s.d / 'receipt.json').read_text())
            receipt['unexpected_change'] = True
            (s.d / 'receipt.json').write_text(json.dumps(receipt))
            with self.assertRaisesRegex(entry.Refuse, 'current entry receipt drift'):
                entry.admin_revision(s.d)

        with self.scenario() as s:
            entry.update_admin(s.args)
            plan, state = entry.admin_revision(s.d)
            prior = json.loads((s.d / 'admin-verified.json').read_text())
            prior['egress'] = '203.0.113.7'
            (s.d / 'admin-verified.json').write_text(json.dumps(prior))
            plan['history']['admin-verified.json'] = entry.digest(s.d / 'admin-verified.json')
            entry.save_json(s.d / 'admin-plan.json', plan)
            state['plan_sha256'] = entry.digest(s.d / 'admin-plan.json')
            entry.save_json(s.d / 'admin-state.json', state)
            with self.assertRaisesRegex(entry.Refuse, 'prior admin verification proof invalid'):
                entry.admin_revision(s.d)

    def test_bundle_rejects_tamper_and_secret_but_allows_link_builder(self):
        with self.scenario() as s:
            # The reviewed manifest is fixed; changing bytes without updating it is refused.
            (s.args.bundle / 'admin.html').write_text('<html>changed</html>')
            with self.assertRaises(entry.Refuse): entry.admin_bundle(s.args.bundle, s.args.bundle_sha256, s.m)
            bad = '<html>' + s.m['inbound_id'] + '</html>'
            (s.args.bundle / 'admin.html').write_text(bad)
            spec = {'/admin/': {'old_sha256': entry.sha(s.old['/admin/']),
                                'new_sha256': entry.sha(bad.encode())}}
            (s.args.bundle / 'manifest.json').write_text(json.dumps(spec))
            s.args.bundle_sha256 = entry.digest(s.args.bundle / 'manifest.json')
            with self.assertRaisesRegex(entry.Refuse, 'pilot credentials'):
                entry.admin_bundle(s.args.bundle, s.args.bundle_sha256, s.m)
            for uri in (
                '<html>vless://deadbeef-1234-1234-1234-123456789abc@edge.example:443</html>',
                '<html>vless%3A%2F%2Fdeadbeef-1234-1234-1234-123456789abc%40edge.example%3A443</html>',
            ):
                data = uri.encode()
                (s.args.bundle / 'admin.html').write_bytes(data)
                spec['/admin/']['new_sha256'] = entry.sha(data)
                (s.args.bundle / 'manifest.json').write_text(json.dumps(spec))
                s.args.bundle_sha256 = entry.digest(s.args.bundle / 'manifest.json')
                with self.assertRaisesRegex(entry.Refuse, 'credential-bearing VLESS URI'):
                    entry.admin_bundle(s.args.bundle, s.args.bundle_sha256, s.m)

    def test_manifest_format_change_after_bundle_validation_refuses_before_history_writes(self):
        with self.scenario() as s:
            manifest = s.args.bundle / 'manifest.json'

            def change_format(name):
                if name == 'admin.prepare-history':
                    manifest.write_text(json.dumps(json.loads(manifest.read_text()), indent=2))

            with patch.object(entry, 'phase', side_effect=change_format):
                with self.assertRaisesRegex(entry.Refuse, 'reviewed admin manifest hash mismatch'):
                    entry.update_admin(s.args)
            self.assertNotEqual(entry.digest(manifest), s.args.bundle_sha256)
            self.assertFalse(any(p.name.startswith('admin-') for p in s.d.iterdir()))
            self.assertEqual(s.moves.call_count, 0)
            self.assertEqual(s.admin_targets['/admin/'].read_bytes(), s.old['/admin/'])

    def test_committed_static_state_drift_refuses_without_changing_admin_receipts(self):
        with self.scenario() as s:
            s.args.bundle = s.static_bundle
            s.args.bundle_sha256 = entry.digest(s.static_bundle / 'manifest.json')
            entry.update_static(s.args)
            s.args.bundle = s.d.parent / 'admin-bundle'
            s.args.bundle_sha256 = entry.digest(s.args.bundle / 'manifest.json')
            entry.update_admin(s.args)
            static_plan, static_state = entry.static_revision(s.d)
            for endpoint, item in static_plan['files'].items():
                static_state['restores'][endpoint] = {
                    'stamp': item['before'], 'temp': '.mayak-static-unaccepted'}
            entry.save_json(s.d / 'static-state.json', static_state)
            receipts = {p.name: p.read_bytes() for p in s.d.iterdir() if p.name.startswith('admin-')}
            moves = s.moves.call_count
            for action in (lambda: entry.admin_revision(s.d), lambda: entry.verify(s.args),
                           lambda: entry.rollback_admin(s.args), lambda: entry.rollback_static(s.args)):
                with self.assertRaisesRegex(entry.Refuse, 'static state binding mismatch'):
                    action()
            self.assertEqual(s.moves.call_count, moves)
            self.assertEqual(receipts, {p.name: p.read_bytes() for p in s.d.iterdir()
                                        if p.name.startswith('admin-')})

    def test_static_rollback_exception_requires_rolled_back_admin_and_actual_restore_identities(self):
        with self.scenario() as s:
            s.args.bundle = s.static_bundle
            s.args.bundle_sha256 = entry.digest(s.static_bundle / 'manifest.json')
            entry.update_static(s.args)
            s.args.bundle = s.d.parent / 'admin-bundle'
            s.args.bundle_sha256 = entry.digest(s.args.bundle / 'manifest.json')
            entry.update_admin(s.args)
            static_plan, static_state = entry.static_revision(s.d)
            static_state['status'] = 'rolled_back'
            for endpoint, item in static_plan['files'].items():
                static_state['restores'][endpoint] = {
                    'stamp': item['before'], 'temp': '.mayak-static-unaccepted'}
            entry.save_json(s.d / 'static-state.json', static_state)
            with self.assertRaisesRegex(entry.Refuse, 'static state binding mismatch'):
                entry.admin_revision(s.d)
            # Even a completed admin rollback cannot authorize static old stamps
            # while the static targets still have their published identities.
            admin_state = json.loads((s.d / 'admin-state.json').read_text())
            admin_state.update(status='rolled_back', direction='rollback')
            entry.save_json(s.d / 'admin-state.json', admin_state)
            with self.assertRaisesRegex(entry.Refuse, 'static rollback target identity drift'):
                entry.admin_revision(s.d)

    def test_interrupted_static_rollback_after_admin_rollback_is_resumable(self):
        with self.scenario() as s:
            s.args.bundle = s.static_bundle
            s.args.bundle_sha256 = entry.digest(s.static_bundle / 'manifest.json')
            entry.update_static(s.args)
            s.args.bundle = s.d.parent / 'admin-bundle'
            s.args.bundle_sha256 = entry.digest(s.args.bundle / 'manifest.json')
            entry.update_admin(s.args)
            entry.rollback_admin(s.args)
            move = entry.static_move

            def interrupt(source, target, after, before):
                if target == s.targets['/my/']:
                    raise RuntimeError('simulated interrupted second restore')
                return move(source, target, after, before)

            with patch.object(entry, 'static_move', side_effect=interrupt):
                with self.assertRaisesRegex(entry.Refuse, 'static rollback RECOVERY INCOMPLETE'):
                    entry.rollback_static(s.args)
            self.assertEqual(entry.static_revision(s.d)[1]['status'], 'recovery_incomplete')
            for status in ('recovering', 'recovery_incomplete'):
                with self.subTest(status=status):
                    _, static_state = entry.static_revision(s.d)
                    static_state['status'] = status
                    entry.save_json(s.d / 'static-state.json', static_state)
                    self.assertEqual(entry.admin_revision(s.d)[1]['status'], 'rolled_back')
                    with self.assertRaisesRegex(entry.Refuse, 'static transaction pending'):
                        entry.verify(s.args)
            entry.rollback_static(s.args)
            self.assertEqual(entry.static_revision(s.d)[1]['status'], 'rolled_back')
            self.assertEqual(entry.admin_revision(s.d)[1]['status'], 'rolled_back')
            entry.verify(s.args)
            for endpoint, target in s.all_targets.items():
                self.assertEqual(target.read_bytes(), s.old[endpoint])


if __name__ == '__main__': unittest.main()
