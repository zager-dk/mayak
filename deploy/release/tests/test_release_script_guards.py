from __future__ import annotations

import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
ENTRY = (ROOT / "release-entry.sh").read_text(encoding="utf-8")


class ReleaseScriptGuards(unittest.TestCase):
    def test_apply_requires_explicit_confirmations_and_preflights_before_stop(self):
        apply = ENTRY[ENTRY.index("[[ $ACTION == apply") :]
        self.assertIn("--confirm-api-only and --confirm-write-window", apply)
        # The staged candidate snapshot, restore and smoke happen before the
        # API is stopped. The final retained dump is taken after the stop.
        stop = apply.index('systemctl stop "$UNIT"', apply.index("# Only after restore"))
        self.assertLess(apply.index("initial pg_dump"), apply.index('candidate_check "$stage/api"'))
        self.assertLess(apply.index('candidate_check "$stage/api"'), stop)
        self.assertLess(apply.index('cp -a "$stage/api"'), stop)
        self.assertLess(apply.index('caddy validate --config "$CADDYFILE"'), stop)
        self.assertIn('caddy-hash "$CADDYFILE" "$EXPECTED_CADDY_SHA256"', ENTRY)
        self.assertNotIn('CADDYFILE.next', apply)
        self.assertLess(stop, apply.index("final pg_dump"))
        self.assertLess(apply.lower().index("static packages are staged before stopping"), stop)
        candidate = ENTRY[ENTRY.index('candidate_check() {'):ENTRY.index('if [[ $ACTION == inspect ]]')]
        self.assertLess(candidate.index('fixture-verify "$fixture"'), candidate.index('rollback-compat.log'))
        self.assertIn('fixture-snapshot "$fixture" "$fixture_root/schema-before.json"', candidate)

    def test_current_caddy_is_preserved_and_metadata_is_bound_to_signed_feeds(self):
        apply = ENTRY[ENTRY.index("# Static packages are staged before stopping"):]
        self.assertNotIn('mv "$CADDYFILE.next" "$CADDYFILE"', apply)
        self.assertNotIn('systemctl reload caddy', apply)
        self.assertIn('Caddy bytes unchanged', apply)
        self.assertIn('fixture-verify "$fixture" "$fixture_root/schema-before.json"', ENTRY)

    def test_rollback_never_rewinds_database_or_touches_vpn(self):
        begin = ENTRY.index('if [[ $ACTION == rollback ]]')
        end = ENTRY.index('[[ $ACTION == apply', begin)
        rollback = ENTRY[begin:end]
        self.assertNotIn("pg_restore", rollback)
        self.assertNotIn("psql", rollback)
        self.assertNotIn("DROP DATABASE", rollback)
        for forbidden in ("awg", "xray", "docker", "iptables", "nft", "ip route", "mayak-agent.service"):
            self.assertNotIn(forbidden, rollback.lower())
        self.assertIn("Database was not rewound", rollback)
        required = rollback.index('api.previous.tar.gz.sha256')
        stop = rollback.index('systemctl stop "$UNIT"')
        self.assertLess(required, stop)
        self.assertIn('historical snapshots require their previous reviewed controller', rollback)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("d7a098e39237d9303922c2eb54b73acf97e94a350103864228128fec4c5857f0", readme)


if __name__ == "__main__":
    unittest.main()
