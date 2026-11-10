#!/usr/bin/env python3
"""Create a deterministic, public-only Mayak pull-release archive.

This tool only assembles caller-supplied build outputs. It never reads signing
private keys, contacts a server, or writes into the stable feed source files.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import gzip
from datetime import datetime, timezone
import json
import os
import pathlib
import re
import subprocess
import sys
import tarfile
import tempfile

EXPECTED_GATEWAY_SPKI = "06537531B7171787CA75D9F94B3EDC49E55FEB0DBB8FF7DAE5559C23C00C1DA2"
WINDOWS_TEMPLATE = "MayakVPN_{version}_windows_x64.exe"
ANDROID_TEMPLATE = "Mayak-Android-{version}-arm64-v8a-api28-signed.apk"
PRESERVED_OVERLAYS = {
    "wwwroot/index.html": "e695c41bbe2130791262ceba4d35429b9b1733e1c39d135e8c4a14c2c89257bd",
    "wwwroot/my/index.html": "b4fae4de1b1ddd720e927e409bcd40c3eb6d934a4f7928998e5d762eb97d3e55",
    "wwwroot/admin/index.html": "54599890493e816159ef60f1795cd65ed2704b8e7632335f43212de4201981e5",
}
FEED_NAMES = {"windows-x64.json", "android-arm64.json"}
# SPKI SHA-256 of mayak-client/mayak/update_signing_public.pem, whose bytes
# are embedded as :/mayak/update_signing_public.pem in both production clients.
# This is a trusted control constant; it is never learned from the bundle.
CLIENT_UPDATE_KEY_SPKI_SHA256 = "98951331395b223d3039043b3f0dcaa15e177eedc459cd84fbab27d2eaaa3584"


def package_names(version: str) -> dict[str, str]:
    return {"windows-x64": WINDOWS_TEMPLATE.format(version=version),
            "android-arm64": ANDROID_TEMPLATE.format(version=version)}


def valid_version(version: str) -> bool:
    return bool(re.fullmatch(r"(?:0|[1-9][0-9]{0,4})\.(?:0|[1-9][0-9]{0,4})\.(?:0|[1-9][0-9]{0,4})\.(?:0|[1-9][0-9]{0,4})", version)) and all(int(part) <= 65535 for part in version.split("."))


def digest(path: pathlib.Path) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            h.update(block)
            size += len(block)
    return h.hexdigest(), size


def public_key_spki_sha256(path: pathlib.Path) -> str:
    der = subprocess.check_output(
        ["openssl", "pkey", "-pubin", "-in", str(path), "-outform", "DER"],
        stderr=subprocess.DEVNULL,
    )
    return hashlib.sha256(der).hexdigest()


def regular_file(path: pathlib.Path) -> pathlib.Path:
    if path.is_symlink():
        raise ValueError(f"input must not be a symlink: {path.name}")
    path = path.resolve(strict=True)
    if not path.is_file():
        raise ValueError(f"input must be a regular file: {path.name}")
    return path


def verify_feed(path: pathlib.Path, platform: str, package_path: pathlib.Path,
                public_key: pathlib.Path, version: str, version_code: int,
                expected_name: str) -> dict:
    envelope = json.loads(path.read_text(encoding="utf-8"))
    if set(envelope) != {"schema", "alg", "payload", "signature"} or envelope["schema"] != 1 or envelope["alg"] != "Ed25519":
        raise ValueError(f"unsupported signed envelope: {path.name}")
    payload = base64.b64decode(envelope["payload"], validate=True)
    signature = base64.b64decode(envelope["signature"], validate=True)
    with tempfile.TemporaryDirectory(prefix=".mayak-feed-verify-", dir=package_path.parent) as tmp:
        payload_file = pathlib.Path(tmp) / "payload.bin"
        signature_file = pathlib.Path(tmp) / "signature.bin"
        payload_file.write_bytes(payload)
        signature_file.write_bytes(signature)
        result = subprocess.run(
            ["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(public_key),
             "-rawin", "-in", str(payload_file), "-sigfile", str(signature_file)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
        )
        if result.returncode:
            raise ValueError(f"signature verification failed: {path.name}")
    data = json.loads(payload)
    if data.get("product") != "mayak-vpn" or data.get("channel") != "stable" or data.get("platform") != platform:
        raise ValueError(f"feed identity mismatch: {path.name}")
    url = data.get("url", "")
    if url != f"https://mayaklight.ru/updates/packages/{expected_name}":
        raise ValueError(f"feed URL is not the fixed same-origin package path: {path.name}")
    feed_version = str(data.get("version", ""))
    if feed_version != version or not valid_version(feed_version):
        raise ValueError(f"invalid four-part version: {path.name}")
    if type(data.get("versionCode")) is not int or data["versionCode"] != version_code:
        raise ValueError(f"feed version code mismatch: {path.name}")
    try:
        published = datetime.fromisoformat(data["publishedAt"].replace("Z", "+00:00"))
        expires = datetime.fromisoformat(data["expiresAt"].replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        if (published.tzinfo is None or expires.tzinfo is None or published > now or
                expires <= now or expires <= published):
            raise ValueError
    except (KeyError, AttributeError, TypeError, ValueError):
        raise ValueError(f"invalid or expired feed validity interval: {path.name}") from None
    actual_hash, actual_size = digest(package_path)
    if data.get("sha256") != actual_hash or data.get("size") != actual_size:
        raise ValueError(f"feed package hash/size mismatch: {path.name}")
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-publish", type=pathlib.Path, required=True)
    parser.add_argument("--agent", type=pathlib.Path, required=True)
    parser.add_argument("--windows-package", type=pathlib.Path, required=True)
    parser.add_argument("--android-package", type=pathlib.Path, required=True)
    parser.add_argument("--windows-feed", type=pathlib.Path, required=True)
    parser.add_argument("--android-feed", type=pathlib.Path, required=True)
    parser.add_argument("--update-public-key", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--release-id", required=True, help="immutable safe label, e.g. pilot-20261029-a")
    parser.add_argument("--version", required=True, help="frozen four-component client version")
    parser.add_argument("--android-version-code", type=int, required=True, help="frozen Android versionCode used in signed feeds")
    args = parser.parse_args()
    try:
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]{2,63}", args.release_id):
            raise ValueError("release id contains unsupported characters")
        if not valid_version(args.version):
            raise ValueError("version must have four numeric components")
        if not 1 <= args.android_version_code <= 2_147_483_647:
            raise ValueError("Android versionCode is outside supported positive range")
        platform_names = package_names(args.version)
        openssl = subprocess.run(["openssl", "version"], stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, check=False)
        if openssl.returncode:
            raise ValueError("OpenSSL is required to verify Ed25519 feed signatures")
        api_root = args.api_publish.resolve(strict=True)
        if not api_root.is_dir() or api_root.is_symlink():
            raise ValueError("API publish input must be a real directory")
        agent = regular_file(args.agent)
        packages = {
            "windows-x64": regular_file(args.windows_package),
            "android-arm64": regular_file(args.android_package),
        }
        feeds = {"windows-x64": regular_file(args.windows_feed),
                 "android-arm64": regular_file(args.android_feed)}
        public_key = regular_file(args.update_public_key)
        if public_key_spki_sha256(public_key) != CLIENT_UPDATE_KEY_SPKI_SHA256:
            raise ValueError("update public key does not match the production client pin")
        release_dir = pathlib.Path(__file__).resolve().parent
        entry_script = regular_file(release_dir / "release-entry.sh")
        inspector_script = regular_file(release_dir / "inspect-target.sh")
        verifier_script = regular_file(release_dir / "verify_bundle.py")
        safety_script = regular_file(release_dir / "release_safety.py")
        for platform in platform_names:
            verify_feed(feeds[platform], platform, packages[platform], public_key,
                        args.version, args.android_version_code, platform_names[platform])

        files: dict[str, pathlib.Path] = {"dist/mayak-agent": agent,
                                          "control/release-entry.sh": entry_script,
                                          "control/inspect-target.sh": inspector_script,
                                          "control/verify_bundle.py": verifier_script,
                                          "control/release_safety.py": safety_script,
                                          "control/update-public-key.pem": public_key}
        for path in sorted(api_root.rglob("*")):
            if path.is_symlink():
                raise ValueError(f"API publish tree contains symlink: {path.relative_to(api_root)}")
            if path.is_file():
                relative = path.relative_to(api_root).as_posix()
                if not relative or relative.startswith("/") or ".." in pathlib.PurePosixPath(relative).parts:
                    raise ValueError("unsafe API publish path")
                # Publish output may contain PDBs, source link metadata or
                # appsettings files. They are never part of a production bundle.
                lower = relative.lower()
                if (lower.endswith((".pdb", ".pem", ".pfx", ".key", ".env", ".user", ".db", ".dump")) or
                        pathlib.PurePosixPath(lower).name.startswith("appsettings") or
                        any(term in pathlib.PurePosixPath(lower).name for term in ("secret", "credential", "password"))):
                    continue
                files[f"api/{relative}"] = path
        if not any(name == "api/mayak-api.dll" for name in files):
            raise ValueError("API publish tree must contain mayak-api.dll")
        for platform, package in packages.items():
            files[f"updates/packages/{platform_names[platform]}"] = package
        for platform, feed in feeds.items():
            files[f"updates/stable/{platform}.json"] = feed

        records = []
        for name, source in sorted(files.items()):
            if "\\" in name or name.startswith("/") or ".." in pathlib.PurePosixPath(name).parts:
                raise ValueError(f"unsafe archive name: {name}")
            if name.endswith('.sh'):
                script = source.read_bytes()
                if b'\r' in script or script.startswith(b'\xef\xbb\xbf'):
                    raise ValueError('Unix shell script must be LF UTF-8 without BOM')
            sha, size = digest(source)
            executable = name in {"dist/mayak-agent", "control/release-entry.sh", "control/inspect-target.sh"}
            records.append({"path": name, "sha256": sha, "size": size,
                            "mode": 0o755 if executable else 0o644})
        manifest = {"schema": 1, "product": "mayak", "releaseId": args.release_id,
                    "clientVersion": args.version, "androidVersionCode": args.android_version_code,
                    "preservedOverlayHashes": PRESERVED_OVERLAYS,
                    "gatewaySpkiSha256": EXPECTED_GATEWAY_SPKI, "files": records}
        output = args.output.absolute()
        output.parent.mkdir(parents=True, exist_ok=True)
        if output.exists():
            raise ValueError(f"refusing to overwrite existing output: {output}")
        fd, temp_name = tempfile.mkstemp(prefix=".mayak-bundle-", dir=output.parent)
        os.close(fd)
        temp = pathlib.Path(temp_name)
        try:
            import io
            with temp.open("wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as gz:
                with tarfile.open(fileobj=gz, mode="w|", format=tarfile.PAX_FORMAT) as tar:
                    payload = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
                    info = tarfile.TarInfo("bundle.json")
                    info.size = len(payload)
                    info.mtime = 0
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    info.mode = 0o644
                    tar.addfile(info, io.BytesIO(payload))
                    for record in records:
                        source = files[record["path"]]
                        info = tarfile.TarInfo(record["path"])
                        info.size = record["size"]
                        info.mtime = 0
                        info.uid = info.gid = 0
                        info.uname = info.gname = ""
                        info.mode = record["mode"]
                        with source.open("rb") as stream:
                            tar.addfile(info, stream)
            # Exclusive creation: even a race cannot overwrite a previously
            # reviewed candidate archive. Remove a partial file on write error.
            output_fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
            try:
                with os.fdopen(output_fd, "wb") as destination, temp.open("rb") as source:
                    while block := source.read(1024 * 1024):
                        destination.write(block)
                    destination.flush()
                    os.fsync(destination.fileno())
            except BaseException:
                try:
                    output.unlink()
                except OSError:
                    pass
                raise
            temp.unlink()
        finally:
            if temp.exists():
                temp.unlink()
        archive_hash, archive_size = digest(output)
        print(json.dumps({"output": str(output), "sha256": archive_hash,
                          "size": archive_size, "releaseId": args.release_id}, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        print(f"bundle build refused: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
