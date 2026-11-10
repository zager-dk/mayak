#!/usr/bin/env python3
"""Fail-closed validator/extractor for Mayak release archives."""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import base64
import subprocess
import tarfile
import sys
import tempfile
from datetime import datetime, timezone

ALLOW_PREFIXES = ("api/", "control/", "dist/", "updates/packages/", "updates/stable/")
GATEWAY_PIN = "06537531B7171787CA75D9F94B3EDC49E55FEB0DBB8FF7DAE5559C23C00C1DA2"
# Trusted control pin copied from the production client's embedded resource.
CLIENT_UPDATE_KEY_SPKI_SHA256 = "98951331395b223d3039043b3f0dcaa15e177eedc459cd84fbab27d2eaaa3584"
PRESERVED_OVERLAYS = {
    "wwwroot/index.html": "e695c41bbe2130791262ceba4d35429b9b1733e1c39d135e8c4a14c2c89257bd",
    "wwwroot/my/index.html": "b4fae4de1b1ddd720e927e409bcd40c3eb6d934a4f7928998e5d762eb97d3e55",
    "wwwroot/admin/index.html": "54599890493e816159ef60f1795cd65ed2704b8e7632335f43212de4201981e5",
}


def validate(bundle: pathlib.Path, expected_sha: str) -> tuple[list[tarfile.TarInfo], dict]:
    if not re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha):
        raise ValueError("an exact 64-digit SHA-256 is required")
    h = hashlib.sha256()
    with bundle.open("rb") as stream:
        while data := stream.read(1024 * 1024):
            h.update(data)
    if h.hexdigest().lower() != expected_sha.lower():
        raise ValueError("bundle SHA-256 mismatch")
    with tarfile.open(bundle, "r:gz") as archive:
        members = archive.getmembers()
        names = [m.name for m in members]
        if len(names) != len(set(names)) or "bundle.json" not in names:
            raise ValueError("missing manifest or duplicate archive paths")
        for member in members:
            p = pathlib.PurePosixPath(member.name)
            if (p.is_absolute() or "\\" in member.name or ".." in p.parts or
                    not member.isfile() or member.size < 0):
                raise ValueError("unsafe archive path or file type")
            if member.name != "bundle.json" and not member.name.startswith(ALLOW_PREFIXES):
                raise ValueError("archive member is outside the allowlist")
        manifest_file = archive.extractfile("bundle.json")
        if manifest_file is None:
            raise ValueError("bundle manifest cannot be read")
        manifest = json.loads(manifest_file.read())
        version = manifest.get("clientVersion")
        code = manifest.get("androidVersionCode")
        if (manifest.get("schema") != 1 or manifest.get("product") != "mayak" or
                manifest.get("gatewaySpkiSha256") != GATEWAY_PIN or
                not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{2,63}", str(manifest.get("releaseId", ""))) or
                not isinstance(version, str) or
                not re.fullmatch(r"(?:0|[1-9][0-9]{0,4})\.(?:0|[1-9][0-9]{0,4})\.(?:0|[1-9][0-9]{0,4})\.(?:0|[1-9][0-9]{0,4})", version) or
                any(int(part) > 65535 for part in version.split(".")) or
                type(code) is not int or not 1 <= code <= 2_147_483_647 or
                manifest.get("preservedOverlayHashes") != PRESERVED_OVERLAYS or
                not isinstance(manifest.get("files"), list)):
            raise ValueError("unsupported bundle manifest or gateway pin")
        package_names = {
            "windows-x64": f"MayakVPN_{version}_windows_x64.exe",
            "android-arm64": f"Mayak-Android-{version}-arm64-v8a-api28-signed.apk",
        }
        feed_payloads = {}
        key_member = archive.extractfile("control/update-public-key.pem")
        if key_member is None:
            raise ValueError("update public key is missing")
        with tempfile.TemporaryDirectory(prefix=".mayak-bundle-key-", dir=bundle.parent) as tmp:
            key_path = pathlib.Path(tmp) / "public.pem"
            key_path.write_bytes(key_member.read())
            der = subprocess.check_output(["openssl", "pkey", "-pubin", "-in", str(key_path), "-outform", "DER"],
                                          stderr=subprocess.DEVNULL)
        if hashlib.sha256(der).hexdigest() != CLIENT_UPDATE_KEY_SPKI_SHA256:
            raise ValueError("bundled update public key does not match the production client pin")
        for platform, filename in package_names.items():
            feed_name = f"updates/stable/{platform}.json"
            package_name = f"updates/packages/{filename}"
            if feed_name not in names or package_name not in names:
                raise ValueError("versioned package/feed pair is missing")
            with tarfile.open(bundle, "r:gz") as source_archive:
                envelope = json.loads(source_archive.extractfile(feed_name).read())
                payload_bytes = base64.b64decode(envelope["payload"], validate=True)
                payload = json.loads(payload_bytes)
                if set(envelope) != {"schema", "alg", "payload", "signature"} or envelope["schema"] != 1 or envelope["alg"] != "Ed25519":
                    raise ValueError("unsupported signed feed envelope")
                signature = base64.b64decode(envelope["signature"], validate=True)
                with tempfile.TemporaryDirectory(prefix=".mayak-bundle-feed-", dir=bundle.parent) as tmp:
                    payload_path = pathlib.Path(tmp) / "payload.bin"
                    signature_path = pathlib.Path(tmp) / "signature.bin"
                    key_path = pathlib.Path(tmp) / "public.pem"
                    payload_path.write_bytes(payload_bytes)
                    signature_path.write_bytes(signature)
                    key_path.write_bytes(archive.extractfile("control/update-public-key.pem").read())
                    verified = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(key_path),
                                               "-rawin", "-in", str(payload_path), "-sigfile", str(signature_path)],
                                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                    if verified.returncode:
                        raise ValueError("signed feed signature verification failed")
            feed_payloads[platform] = (payload, package_name, filename)
        listed: dict[str, dict] = {}
        for record in manifest["files"]:
            name = record.get("path")
            p = pathlib.PurePosixPath(name or "")
            if (not name or name in listed or p.is_absolute() or "\\" in name or
                    ".." in p.parts or not name.startswith(ALLOW_PREFIXES) or
                    not isinstance(record.get("size"), int) or record["size"] < 0 or
                    not re.fullmatch(r"[0-9a-f]{64}", str(record.get("sha256", "")))):
                raise ValueError("invalid path/hash/size in bundle manifest")
            listed[name] = record
        for platform, (payload, package_name, filename) in feed_payloads.items():
            if (payload.get("product") != "mayak-vpn" or payload.get("channel") != "stable" or
                    payload.get("platform") != platform or payload.get("version") != version or
                    type(payload.get("versionCode")) is not int or payload.get("versionCode") != code or payload.get("url") !=
                    f"https://mayaklight.ru/updates/packages/{filename}" or
                    payload.get("sha256") != listed.get(package_name, {}).get("sha256") or
                    type(payload.get("size")) is not int or payload.get("size") != listed.get(package_name, {}).get("size")):
                raise ValueError("signed feed package metadata differs from bundle version")
            try:
                published = datetime.fromisoformat(payload["publishedAt"].replace("Z", "+00:00"))
                expires = datetime.fromisoformat(payload["expiresAt"].replace("Z", "+00:00"))
                now = datetime.now(timezone.utc)
                if (published.tzinfo is None or expires.tzinfo is None or published > now or
                        expires <= now or expires <= published):
                    raise ValueError
            except (KeyError, AttributeError, TypeError, ValueError):
                raise ValueError("signed feed validity interval is invalid or expired") from None
        fixed_paths = {
            "control/release-entry.sh", "control/inspect-target.sh", "control/verify_bundle.py", "control/release_safety.py", "control/update-public-key.pem",
            "dist/mayak-agent", "updates/stable/windows-x64.json", "updates/stable/android-arm64.json",
        }
        fixed_paths.update(f"updates/packages/{filename}" for filename in package_names.values())
        for name in listed:
            if not name.startswith("api/") and name not in fixed_paths:
                raise ValueError("unexpected non-API payload path")
            if name.startswith("api/"):
                leaf = pathlib.PurePosixPath(name).name.lower()
                if (leaf.endswith((".pdb", ".pem", ".pfx", ".key", ".env", ".user", ".db", ".dump")) or
                        leaf.startswith("appsettings") or
                        any(term in leaf for term in ("secret", "credential", "password"))):
                    raise ValueError("API payload includes a forbidden configuration/secret/debug file")
        if set(names) - {"bundle.json"} != set(listed):
            raise ValueError("manifest/archive member list differs")
        for name, record in listed.items():
            member = archive.getmember(name)
            if member.size != record["size"]:
                raise ValueError("payload size mismatch")
            payload = archive.extractfile(member)
            if payload is None:
                raise ValueError("payload cannot be read")
            digest = hashlib.sha256()
            script_bytes = bytearray() if name.endswith('.sh') else None
            while block := payload.read(1024 * 1024):
                digest.update(block)
                if script_bytes is not None:
                    script_bytes.extend(block)
            if digest.hexdigest() != record["sha256"]:
                raise ValueError("payload hash mismatch")
            if script_bytes is not None and (b'\r' in script_bytes or script_bytes.startswith(b'\xef\xbb\xbf')):
                raise ValueError('Unix shell script is not LF UTF-8 without BOM')
        required = {"api/mayak-api.dll", "control/release-entry.sh", "control/inspect-target.sh", "control/verify_bundle.py", "control/release_safety.py", "control/update-public-key.pem", "dist/mayak-agent",
                    "updates/stable/windows-x64.json", "updates/stable/android-arm64.json",
                    *(f"updates/packages/{filename}" for filename in package_names.values())}
        if not required.issubset(listed):
            raise ValueError("required API/agent/signed feed payload missing")
        return members, manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=pathlib.Path)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--extract", type=pathlib.Path)
    args = parser.parse_args()
    try:
        members, manifest = validate(args.bundle, args.expected_sha)
        if args.extract:
            root = args.extract
            if root.exists() and any(root.iterdir()):
                raise ValueError("extraction destination is not empty")
            root.mkdir(parents=True, exist_ok=True)
            # Members are already allowlisted regular files with canonical POSIX paths.
            with tarfile.open(args.bundle, "r:gz") as archive:
                for member in members:
                    if member.name == "bundle.json":
                        continue
                    destination = root.joinpath(*pathlib.PurePosixPath(member.name).parts)
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    src = archive.extractfile(member)
                    if src is None:
                        raise ValueError("archive member cannot be read")
                    with src, destination.open("xb") as dst:
                        while block := src.read(1024 * 1024):
                            dst.write(block)
                    destination.chmod(0o755 if member.name in {"dist/mayak-agent", "control/release-entry.sh", "control/inspect-target.sh"} else 0o640)
        print(json.dumps({"releaseId": manifest["releaseId"], "files": len(manifest["files"]),
                          "bytes": sum(item["size"] for item in manifest["files"]),
                          "bundleSha256": args.expected_sha.lower()}, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, json.JSONDecodeError, tarfile.TarError) as exc:
        print(f"bundle validation refused: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
