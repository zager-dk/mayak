from __future__ import annotations

import base64
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import tarfile
import tempfile
import io
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
BUILDER = ROOT / "build_bundle.py"
VERIFY = ROOT / "verify_bundle.py"
CLIENT_KEY = ROOT.parents[2] / "mayak-client" / "mayak" / "update_signing_public.pem"


def call(args, ok=True):
    args = list(map(str, args))
    command = [shutil.which(args[0]), *args[1:]] if args[0] == "openssl" else [sys.executable, *args]
    result = subprocess.run(command, capture_output=True, text=True)
    if (result.returncode == 0) != ok:
        raise AssertionError(f"unexpected command status {result.returncode}: {result.stderr}")
    return result


class BundleTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix=".mayak-release-test-", dir=ROOT)
        self.root = pathlib.Path(self.temp.name)
        self.api = self.root / "api"
        self.api.mkdir()
        (self.api / "mayak-api.dll").write_bytes(b"dll-fixture")
        (self.api / "mayak-api.deps.json").write_text("{}", encoding="utf-8")
        (self.api / "mayak-api.runtimeconfig.json").write_text("{}", encoding="utf-8")
        (self.api / "appsettings.json").write_text('{"Password":"not-a-real-secret"}', encoding="utf-8")
        (self.api / "mayak-api.pdb").write_bytes(b"debug")
        self.agent = self.root / "agent"
        self.agent.write_bytes(b"agent-fixture")
        self.win = self.root / "windows.exe"
        self.win.write_bytes(b"win-fixture")
        self.apk = self.root / "android.apk"
        self.apk.write_bytes(b"apk-fixture")
        self.private = self.root / "ephemeral-ed25519-test-key.pem"
        self.public = self.root / "ephemeral-ed25519-test-key.pub.pem"
        call(["openssl", "genpkey", "-algorithm", "ED25519", "-out", self.private])
        call(["openssl", "pkey", "-in", self.private, "-pubout", "-out", self.public])
        # Positive bundle fixtures use a throwaway signing key. Patch only the
        # trusted pin constant in isolated copies of the controls; production
        # controls remain pinned to the client's embedded public resource.
        der = subprocess.check_output([shutil.which("openssl"), "pkey", "-pubin", "-in", str(self.public), "-outform", "DER"])
        fixture_pin = hashlib.sha256(der).hexdigest()
        self.controls = self.root / "controls"
        self.controls.mkdir()
        for source in (BUILDER, VERIFY, ROOT / "release-entry.sh", ROOT / "inspect-target.sh", ROOT / "release_safety.py"):
            destination = self.controls / source.name
            raw = source.read_text(encoding="utf-8") if source.suffix == ".py" else source.read_bytes().decode("utf-8")
            raw = raw.replace("98951331395b223d3039043b3f0dcaa15e177eedc459cd84fbab27d2eaaa3584", fixture_pin)
            destination.write_text(raw, encoding="utf-8", newline="\n")
        self.builder = self.controls / BUILDER.name
        self.verify = self.controls / VERIFY.name
        self.win_feed = self.root / "windows.json"
        self.apk_feed = self.root / "android.json"
        self.sign_feed(self.win_feed, "windows-x64", self.win, "MayakVPN_5.1.0.5_windows_x64.exe")
        self.sign_feed(self.apk_feed, "android-arm64", self.apk, "Mayak-Android-5.1.0.5-arm64-v8a-api28-signed.apk")

    def tearDown(self):
        self.temp.cleanup()

    def sign_feed(self, path, platform, package, filename):
        payload = {"product": "mayak-vpn", "channel": "stable", "platform": platform,
                   "version": "5.1.0.5", "versionCode": 2187,
                   "url": "https://mayaklight.ru/updates/packages/" + filename,
                   "size": package.stat().st_size, "sha256": hashlib.sha256(package.read_bytes()).hexdigest(),
                   "publishedAt": "2026-10-28T22:08:02Z", "expiresAt": "2027-04-29T00:00:00Z",
                   "releaseNotes": "fixture"}
        raw = json.dumps(payload, separators=(",", ":")).encode()
        payload_path, sig_path = self.root / "payload", self.root / "signature"
        payload_path.write_bytes(raw)
        call(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", self.private,
              "-in", payload_path, "-out", sig_path])
        path.write_text(json.dumps({"schema": 1, "alg": "Ed25519",
                                    "payload": base64.b64encode(raw).decode(),
                                    "signature": base64.b64encode(sig_path.read_bytes()).decode()}), encoding="utf-8")

    def build(self, out, windows_feed=None):
        return call([self.builder, "--api-publish", self.api, "--agent", self.agent,
                     "--windows-package", self.win, "--android-package", self.apk,
                     "--windows-feed", windows_feed or self.win_feed,
                     "--android-feed", self.apk_feed, "--update-public-key", self.public,
                     "--output", out, "--release-id", "pilot-20261029-fixture",
                     "--version", "5.1.0.5", "--android-version-code", "2187"])

    def test_deterministic_signed_bundle_and_public_file_filter(self):
        first, second = self.root / "one.tar.gz", self.root / "two.tar.gz"
        self.build(first)
        self.build(second)
        self.assertEqual(hashlib.sha256(first.read_bytes()).digest(), hashlib.sha256(second.read_bytes()).digest())
        digest = hashlib.sha256(first.read_bytes()).hexdigest()
        validated = call([self.verify, first, "--expected-sha", digest])
        self.assertIn("pilot-20261029-fixture", validated.stdout)
        with tarfile.open(first, "r:gz") as archive:
            names = set(archive.getnames())
            self.assertIn("api/mayak-api.dll", names)
            self.assertIn("control/inspect-target.sh", names)
            self.assertNotIn("api/appsettings.json", names)
            self.assertNotIn("api/mayak-api.pdb", names)

    def test_bad_hash_and_bad_signature_refused_without_output(self):
        output = self.root / "invalid.tar.gz"
        self.build(output)
        call([self.verify, output, "--expected-sha", "0" * 64], ok=False)
        bad_feed = self.root / "bad-signature.json"
        doc = json.loads(self.win_feed.read_text(encoding="utf-8"))
        doc["signature"] = base64.b64encode(bytes(64)).decode()
        bad_feed.write_text(json.dumps(doc), encoding="utf-8")
        refused = self.root / "refused.tar.gz"
        call([self.builder, "--api-publish", self.api, "--agent", self.agent,
              "--windows-package", self.win, "--android-package", self.apk,
              "--windows-feed", bad_feed, "--android-feed", self.apk_feed,
              "--update-public-key", self.public, "--output", refused,
              "--release-id", "pilot-20261029-fixture", "--version", "5.1.0.5",
              "--android-version-code", "2187"], ok=False)
        self.assertFalse(refused.exists())

    def test_package_metadata_is_exact_and_mismatches_are_refused(self):
        for platform, package, filename in (
            ("windows-x64", self.win, "MayakVPN_5.1.0.5_windows_x64.exe"),
            ("android-arm64", self.apk, "Mayak-Android-5.1.0.5-arm64-v8a-api28-signed.apk"),
        ):
            with self.subTest(platform=platform):
                feed = self.root / f"bad-{platform}.json"
                self.sign_feed(feed, platform, package, filename)
                doc = json.loads(feed.read_text())
                payload = json.loads(base64.b64decode(doc["payload"]))
                payload["versionCode"] += 1
                raw = json.dumps(payload, separators=(",", ":")).encode()
                payload_file, sig_file = self.root / "payload", self.root / "signature"
                payload_file.write_bytes(raw)
                call(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", self.private,
                      "-in", payload_file, "-out", sig_file])
                feed.write_text(json.dumps({"schema": 1, "alg": "Ed25519",
                    "payload": base64.b64encode(raw).decode(),
                    "signature": base64.b64encode(sig_file.read_bytes()).decode()}))
                output = self.root / f"refused-{platform}.tar.gz"
                call([self.builder, "--api-publish", self.api, "--agent", self.agent,
                      "--windows-package", self.win, "--android-package", self.apk,
                      "--windows-feed", feed if platform == "windows-x64" else self.win_feed,
                      "--android-feed", feed if platform == "android-arm64" else self.apk_feed,
                      "--update-public-key", self.public, "--output", output,
                      "--release-id", "pilot-20261029-fixture", "--version", "5.1.0.5",
                      "--android-version-code", "2187"], ok=False)
                self.assertFalse(output.exists())

    def rewrite_signed_bundle_feed(self, bundle, platform, mutate):
        with tarfile.open(bundle, "r:gz") as archive:
            members = {item.name: (item, archive.extractfile(item).read()) for item in archive.getmembers()}
        feed_name = f"updates/stable/{platform}.json"
        envelope = json.loads(members[feed_name][1])
        payload = json.loads(base64.b64decode(envelope["payload"]))
        mutate(payload)
        raw = json.dumps(payload, separators=(",", ":")).encode()
        payload_path, sig_path = self.root / "payload", self.root / "signature"
        payload_path.write_bytes(raw)
        call(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", self.private,
              "-in", payload_path, "-out", sig_path])
        envelope["payload"] = base64.b64encode(raw).decode()
        envelope["signature"] = base64.b64encode(sig_path.read_bytes()).decode()
        members[feed_name] = (members[feed_name][0], json.dumps(envelope).encode())
        manifest = json.loads(members["bundle.json"][1])
        for record in manifest["files"]:
            if record["path"] == feed_name:
                record["size"] = len(members[feed_name][1])
                record["sha256"] = hashlib.sha256(members[feed_name][1]).hexdigest()
        members["bundle.json"] = (members["bundle.json"][0], json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode())
        with tarfile.open(bundle, "w:gz") as output:
            for name, (old, data) in members.items():
                info = tarfile.TarInfo(name)
                info.mode, info.size = old.mode, len(data)
                info.mtime = 0
                output.addfile(info, io.BytesIO(data))

    def rewrite_bundle_member(self, bundle, target, content):
        with tarfile.open(bundle, "r:gz") as archive:
            members = {item.name: (item, archive.extractfile(item).read()) for item in archive.getmembers()}
        members[target] = (members[target][0], content)
        manifest = json.loads(members["bundle.json"][1])
        for record in manifest["files"]:
            if record["path"] == target:
                record["size"] = len(content)
                record["sha256"] = hashlib.sha256(content).hexdigest()
        members["bundle.json"] = (members["bundle.json"][0], json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode())
        with tarfile.open(bundle, "w:gz") as output:
            for name, (old, data) in members.items():
                info = tarfile.TarInfo(name)
                info.mode, info.size, info.mtime = old.mode, len(data), 0
                output.addfile(info, io.BytesIO(data))

    def test_target_verifier_rechecks_feed_identity_and_expiry(self):
        mutations = (("product", lambda p: p.update(product="other")),
                     ("channel", lambda p: p.update(channel="beta")),
                     ("expired", lambda p: p.update(expiresAt="2000-01-01T00:00:00Z")))
        for label, mutation in mutations:
            with self.subTest(label=label):
                bundle = self.root / f"negative-{label}.tar.gz"
                self.build(bundle)
                self.rewrite_signed_bundle_feed(bundle, "windows-x64", mutation)
                digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
                call([self.verify, bundle, "--expected-sha", digest], ok=False)

    def test_target_verifier_refuses_unpinned_bundled_key(self):
        bundle = self.root / "wrong-key.tar.gz"
        self.build(bundle)
        alternate_private = self.root / "alternate-test-key.pem"
        alternate_public = self.root / "alternate-test-key.pub.pem"
        call(["openssl", "genpkey", "-algorithm", "ED25519", "-out", alternate_private])
        call(["openssl", "pkey", "-in", alternate_private, "-pubout", "-out", alternate_public])
        self.rewrite_bundle_member(bundle, "control/update-public-key.pem", alternate_public.read_bytes())
        digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
        call([self.verify, bundle, "--expected-sha", digest], ok=False)

    def test_trusted_client_key_pin_matches_public_resource(self):
        der = subprocess.check_output([shutil.which("openssl"), "pkey", "-pubin", "-in", str(CLIENT_KEY), "-outform", "DER"])
        self.assertEqual(hashlib.sha256(der).hexdigest(),
                         "98951331395b223d3039043b3f0dcaa15e177eedc459cd84fbab27d2eaaa3584")

    def test_production_builder_rejects_throwaway_unpinned_key(self):
        output = self.root / "unpinned.tar.gz"
        call([BUILDER, "--api-publish", self.api, "--agent", self.agent,
              "--windows-package", self.win, "--android-package", self.apk,
              "--windows-feed", self.win_feed, "--android-feed", self.apk_feed,
              "--update-public-key", self.public, "--output", output,
              "--release-id", "pilot-20261029-fixture", "--version", "5.1.0.5",
              "--android-version-code", "2187"], ok=False)
        self.assertFalse(output.exists())

    def test_archive_traversal_and_symlink_members_refused(self):
        for name, kind in (("../escape", "file"), ("api/link", "symlink")):
            archive_path = self.root / ("attack-" + str(len(name)) + ".tar.gz")
            with tarfile.open(archive_path, "w:gz") as archive:
                manifest = tarfile.TarInfo("bundle.json")
                manifest_payload = b"{}"
                manifest.size = len(manifest_payload)
                archive.addfile(manifest, io.BytesIO(manifest_payload))
                attack = tarfile.TarInfo(name)
                if kind == "symlink":
                    attack.type = tarfile.SYMTYPE
                    attack.linkname = "../../outside"
                    archive.addfile(attack)
                else:
                    attack.size = 4
                    archive.addfile(attack, io.BytesIO(b"oops"))
            digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
            call([VERIFY, archive_path, "--expected-sha", digest], ok=False)
        self.assertFalse((self.root.parent / "escape").exists())


if __name__ == "__main__":
    unittest.main()
