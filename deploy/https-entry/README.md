# Isolated HTTPS entry pilot — HTTPS-ENTRY-01, senior correction

Target-only Python 3 stdlib controller, Linux root, Caddy **2.6.2**. Extends `work/RELEASE_RUNBOOK.md` revision 3 for this isolated entry; existing release controls remain unchanged. No API/client/DB changes, no firewall/routes/VPN restart. The working PC VPN is outside this procedure. Independently review the exact controller hash before target invocation.

Pinned official asset: XTLS/Xray-core **v26.10.29**, `Xray-linux-64.zip`, SHA256 `8a5f3e6a1057e4bd0f8a7c57c9d91204b4be0b74222a6e210d070603101163c2`. The director has separately observed the verified archive and extracted Xray 26.10.29 on Moscow. This package did not contact that host. Optional `prepare` verifies the pinned archive and extracts **only** the amd64 ELF `xray` member with Python zipfile (no unzip needed). It never extracts paths or overwrites files.

## Read-only preparation and outbound gate

Use a root-owned 0700 directory below `/root`. All parent directories must be real, root-owned and not group/other writable. Public binaries/archives may be root-owned 0644; private stage/metadata/checksum files must have no group/other access. Existing extracted executable for `stage` must be 0700. Do not print DB exports, configs, manifests, profiles or raw errors. Fixed controller phase labels identify failures without credentials.

```sh
umask 077
pilot=/root/mayak-https.dYTEu8
controller="$pilot/https_entry.py"
python3 "$controller" preflight

# OPTIONAL if xray has not already been extracted:
python3 "$controller" prepare --archive "$pilot/Xray-linux-64.zip" --out "$pilot/xray"
# stage --xray-bin "$pilot/xray" --sha256-file "$pilot/xray.sha256" ...

# Existing director-verified extracted binary:
chmod 700 "$pilot/release/xray"
binary_sha=$(sha256sum "$pilot/release/xray")
binary_sha=${binary_sha%% *}
python3 "$controller" stage --xray-bin "$pilot/release/xray" --sha256 "$binary_sha" --out "$pilot/stage"
python3 "$controller" check --stage "$pilot/stage"
```

`preflight` verifies loaded/disk Caddy equality, distribution unit/argv/hash, process uid/executable/starttime, Caddy-owned localhost2019 listener, existing HTTPS certificate and endpoint status/body hashes. `/health` must be healthy, gateway public key and both stable feeds present; it snapshots `/`, `/my/`, `/admin/`, `/health`, `/gw/public-key`, and the Windows/Android feed. Entry port18080 and the dedicated install/unit/user/group must be absent/free.

`stage` reads only public `Cluster.XrayJson`, account eligibility and legacy device fields through local PostgreSQL peer access, without dumping rows. Only explicit null `PaidUntil` means unlimited; zero is expired. It prefers a unique eligible `Телефон`, otherwise pass `--device-id ID` before the stage exists. Only null/empty ServiceProtocol is eligible. Upstream must specify port443 and supported Reality metadata; XHTTP requires blank flow, RAW/TCP accepts blank or `xtls-rprx-vision` flow. Destination is pinned to `147.45.41.230:443`, without direct/freedom fallback. `--metadata FILE` is for private offline fixtures; **apply refuses fixture stages**.

HTTPS-ENTRY-03 adds `--upstream-metadata FILE` for an explicit per-exit public endpoint snapshot when the cluster endpoint is stale. Actual foreign-server reads identified RAW/REALITY while the cluster still described XHTTP. This option uses real DB device credentials and eligibility; it cannot be combined with fixture `--metadata`. It changes no DB, foreign-server or agent configuration and does not repair general cluster metadata or add native app TLS support.

The snapshot is a flat JSON object with these required keys (replace example values with the authorized per-exit read):

```json
{
  "Host": "147.45.41.230",
  "targetHost": "147.45.41.230",
  "Port": 443,
  "Security": "reality",
  "Transport": "raw",
  "Flow": "xtls-rprx-vision",
  "Sni": "foreign.example",
  "ShortId": "01234567",
  "PublicKey": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "selectedClientSha256": "<64 lowercase hex characters from the selected UUID>"
}
```

`selectedClientSha256` is SHA256 of the canonical lowercase UUID encoded as UTF-8, with no newline. No raw UUID, private key or auth assertion belongs in this public snapshot. `Security` and `Flow` are mandatory explicit fields: use the selected client's observed flow. `Transport` accepts `raw`/`tcp` (normalized to `raw`) or `xhttp`. Optional fields are `Fingerprint` (blank or `chrome`), and for XHTTP only `XhttpPath`, `XhttpHost`, `XhttpMode`. Unknown keys, other security/transports/flows and a different host/port/device hash are refused.

The input must pass the same root-owned private regular-file and parent guards as credentials. Its exact bytes are copied to private `upstream-metadata.json` inside the **new** stage and bound by the manifest SHA256. Before installation and before switching Caddy, fresh checks rehash/revalidate this staged snapshot and re-read current DB credential/eligibility; the original input file is no longer consulted. The existing DB-only path continues to check cluster endpoint freshness. An override is configuration input; real positive and wrong-UUID probes remain decisive mandatory gates.

```sh
# Retain the earlier stage untouched; use a separate stage for corrected metadata.
python3 "$controller" stage --xray-bin "$pilot/release/xray" --sha256 "$binary_sha" --upstream-metadata "$pilot/exit-public.json" --out "$pilot/stage-exit"
python3 "$controller" check --stage "$pilot/stage-exit"
# After independent acceptance and successful check, use stage-exit for apply/verify/export.
```

Original Caddy bytes, baseline, candidate, binary and Xray config are bound in a root-private manifest. The route is `/mayak-connect/<36 random hex>/`, preserved by a multiline Caddy `handle`. An exclusive fallback retains API/static behavior and gzip; the VPN route has no gzip handler. Every regular stage file (including receipts) is guarded against symlinks, hardlinks, nonroot ownership and public permissions. Unsupported Caddy configuration aborts.

Caddy 2.6.2 automatically adds its adapter input filename to `file_server.hide`. For comparisons, only entries exactly equal to the actual adapter input path are mapped to `/etc/caddy/Caddyfile`. Other hide entries, loaded/disk configuration, identity and endpoint drift remain checked. Existing private stage files and their manifest need no change for this correction (HTTPS-ENTRY-02).

`check` validates bound config/binary and the candidate using the installed Caddy parser. Each temporary SOCKS probe asks the kernel for an ephemeral loopback port with `free_port(0)`, then proves the listener socket belongs to its child PID before every request. This avoids false fixed-port collisions from a previous negative probe's TIME_WAIT (HTTPS-ENTRY-04); no port-reuse socket options or extra retry delay are used. A port taken between selection and child startup still fails the existing readiness/ownership checks. Both HTTPS example.com **and** exact ipify egress147.45.41.230 must succeed with HTTP200. A separate wrong outbound UUID must fail for both destinations. It terminates/reaps only that child and removes only its generated config. Existing stage config/manifest remain reusable because only temporary probe behavior changes. Public routes remain unchanged. Negative request timeouts can take several minutes overall; each command timeout is bounded.

## Apply, full verification, private export

Only after independent acceptance and successful actual `check`:

```sh
python3 "$controller" apply --stage "$pilot/stage"
python3 "$controller" verify --stage "$pilot/stage"
python3 "$controller" client-link --stage "$pilot/stage" --out "$pilot/mayak-pilot.vless"
```

Commands acquire the same nonblocking root-private `/run/mayak-https-entry.lock`. Other operators must serialize Caddy changes with this window; a noncooperating external writer cannot be made transactional by a file lock.

`apply` repeats real outbound checks before installing additive `/opt/mayak/https-entry` and `mayak-https-entry.service`. The service identity is newly created. Config/binary are root-owned, service-group readable; Xray syntax/read checks run **as that service user** before start. Inode/hash/uid/gid/mode receipts bind installed files. The controller proves loopback18080 belongs to its exact process, rechecks Caddy/DB selection immediately before switching, atomically replaces only the matching Caddyfile and gracefully reloads Caddy. It never stops/restarts Caddy/API/foreign VPN services.

Before success, `apply` runs full `verify`: valid same-origin TLS certificate, authenticated SOCKS→local TLS Xray client→Caddy443→entry→Reality→foreign→example.com, exact foreign egress, and wrong inbound UUID failure. It compares original endpoint statuses and exact response body hashes and rechecks disk/loaded/unit/listener identities. Both TLS clients use `packet-up`, matching host/path and blank flow; insecure TLS is disabled. Probe curl disables user curl configuration and direct proxy bypass.

`client-link` **reruns full verification**, then writes the matching `vless://` profile only to a new file inside a root-private directory (0600), without printing it. No operator assertion or stale receipt bypasses checks. Transfer that profile privately to the controlled Android pilot. Physical Android import, browsing, DNS and foreign egress remain **NOT VERIFIED** until user observation. Native Mayak integration/automatic profile updates are outside this pilot.

## Guarded resume before the public switch — HTTPS-ENTRY-05

The observed `systemctl daemon-reload` reset Caddy's serialized ExecStart accounting (`start_time`/`pid`) while the actual Caddy process, executable, starttime, uid and unit/binary hashes stayed unchanged. Identity comparisons now strictly parse the single ExecStart command and compare its executable, arguments and ignore flag, excluding command accounting. Malformed/multiple commands, changed executable/arguments and actual `/proc` identity or file hash changes are refused. Both drift checks and rollback normalize the existing baseline string in memory; no baseline bytes or manifest hashes are rewritten.

If apply stopped after the dedicated service started but **before** the Caddy switch, use the reviewed controller's `resume` on that exact stage:

```sh
python3 "$controller" resume --stage "$pilot/stage-exit"
# After successful resume, verify/client-link use this same stage as above.
```

Admission requires the original Caddy disk/loaded config, endpoint responses and semantic identity; a real DB stage; and the exact owned installed binary/config/unit/user/process receipt, active service and PID-owned loopback18080. Installed file hashes must also match the staged binary/config and controller's unit text. Foreign/tampered, missing-process, inactive or rolled-back receipts are refused without switching or stopping resources.

After admission, resume rechecks current DB eligibility/UUID and staged override hashes, repeats real outbound positive/wrong-UUID probes and staged Xray/Caddy validation, and runs installed Xray syntax as the service user. The shared switch step rechecks baseline, credentials and live ownership, atomically replaces only the matching original Caddyfile, gracefully reloads Caddy and runs the existing full TLS positive/negative/endpoint verification. It does not reinstall, create a user, replace a service unit or restart services. Errors after valid admission use guarded rollback, restoring Caddy before stopping the still-owned entry; refused recovery remains **RECOVERY INCOMPLETE**. Existing stage/manifest/receipt artifacts remain unchanged until normal verification or rollback receipts are written.

## Guarded rollback

```sh
python3 "$controller" rollback --stage "$pilot/stage"
```

The stage is single-use. Automatic recovery and manual rollback restore/verify original Caddy **before stopping the owned entry service**. Unexpected disk/runtime/identity drift is preserved and reported as failure. A modified/foreign unit, binary, config, service identity or process is never stopped/deleted. Partial installation without a complete receipt reports **RECOVERY INCOMPLETE**, retains evidence and requires diagnosis. Never interpret this as recovered.

Successful rollback disables/stops only the receipt-matching dedicated service. It deliberately retains the disabled unit, dedicated identity, binary, credentials and private stage; it deletes no installed resources or DB records. Repeat apply to that retained install is refused. Reuse/cleanup is a separately reviewed operation. Retention preserves information for manual recovery after unexpected drift.

## Exact static UI publish — WEB-DEPLOY-01

`update-static` publishes only the fixed `/opt/mayak/api/wwwroot/index.html` and `/opt/mayak/api/wwwroot/my/index.html` targets. The observed target identity is root uid0, gid986, mode0640, single-link regular files with safe real parents; this metadata is required and preserved. No target-path option, general rebaseline, service restart, Caddy change or DB write is provided. One static revision per stage is supported; another update is refused.

Prepare a root-owned private flat bundle with exactly `index.html` (welcome), `my.html` (cabinet) and `manifest.json`. Every file must pass the existing private regular-file/parent guards. HTML must be UTF-8 full documents; known pilot UUIDs and VLESS profile URLs are refused. This check complements the separate UI review; it does not prove arbitrary HTML/JavaScript contains no sensitive content.

The manifest has only the two endpoint keys and explicit reviewed old/new lowercase SHA256 hashes. No filenames or destination paths belong in it:

```json
{
  "/": {
    "old_sha256": "3e8cddde95fbcb612ebf46155aa1c74daeb4990dcc22294573e26dcbfb6c378d",
    "new_sha256": "<reviewed index.html SHA256>"
  },
  "/my/": {
    "old_sha256": "c8ed7a64e5f88af4337eacad51750c90ea1869c04823f6d25c38596a91d8910a",
    "new_sha256": "<reviewed my.html SHA256>"
  }
}
```

After independent acceptance of the exact controller and UI bundle, use the independently reviewed manifest SHA256 (not an assertion that HTTP/auth succeeded):

```sh
python3 "$controller" update-static --stage "$pilot/stage-exit" --bundle "$pilot/web-bundle" --bundle-sha256 "$reviewed_manifest_sha"
python3 "$controller" verify --stage "$pilot/stage-exit"
# Only if static publish failed or an explicit UI revert is needed while the pilot is active:
python3 "$controller" rollback-static --stage "$pilot/stage-exit"
```

The command first runs full existing VPN positive/wrong-UUID/TLS/endpoint verification, checks live entry ownership and current DB eligibility, and requires each old target hash to equal both the bundle and original HTTP baseline. It retains immutable SHA-bound old/new HTML, original baseline/manifest, install receipt and fresh verification proof as `static-*` history inside the private stage. `baseline.json`, `manifest.json` and original Caddy rollback artifacts remain byte-identical.

Each replacement uses a prepared temporary inode in its fixed target parent, with original uid/gid/mode, recorded before an atomic per-file rename. The two files are not one filesystem transaction; transient mixed responses are possible between renames. The new HTTP bodies must equal the exact candidate hashes; every protected `/admin/`, `/health`, key and feed expectation remains the original value. Full VPN positive/negative verification runs again before the revision commits; a final ordinary drift/ownership check proves the committed overlay is usable.

`static-plan.json` binds the history and only the two allowed old/new expectations; `static-state.json` records prepared/verifying/committed or recovery state. Pending state blocks ordinary verify/export/VPN rollback. `rollback-static` first checks both file identities, then restores only exact recorded old/new/restored inode+device+hash+metadata identities, journaling restore ownership before rename. Failures after either replacement automatically use this same recovery. Foreign edits are retained and reported as **RECOVERY INCOMPLETE**. If interruption occurs before the plan/state are fully prepared, no target has been replaced; private partial preparation requires diagnosis and must not be treated as published.

Successful static rollback verifies the original HTTP responses and full VPN path. It retains the disabled revision history and refuses another publish. Static recovery requires the unchanged active pilot and candidate Caddy config; it does not restart anything. After a committed UI revision, ordinary `verify`/`client-link` use that exact accepted response overlay, and VPN `rollback` restores original Caddy while checking the accepted UI revision. VPN rollback retains the updated website and all original static history.

## Exact admin publish — ADMIN-PUBLISH-01

`update-admin` publishes only `/opt/mayak/api/wwwroot/admin/index.html`. It is an append-only revision separate from the root/cabinet static receipt. The command accepts a private flat directory containing exactly `admin.html` and `manifest.json`; its argument is only the SHA256 of the reviewed manifest. No destination option, general rebaseline, API restart, Caddy change, database write or credential is accepted. The target must remain a root-owned, single-link regular file with uid0, gid986 and mode0640; the replacement preserves those values.

The manifest contains exactly one endpoint and the explicit old/new HTML SHA256 values:

```json
{
  "/admin/": {
    "old_sha256": "<observed current admin HTML SHA256>",
    "new_sha256": "<reviewed admin HTML SHA256>"
  }
}
```

The new document must be UTF-8 HTML. The check permits page code that constructs `vless://` user links, while refusing the pilot inbound and upstream UUIDs. This is a narrow leak guard, not a general HTML security review.

After independent review of the exact controller and admin HTML bundle:

```sh
python3 "$controller" update-admin --stage "$pilot/stage-exit" --bundle "$pilot/admin-bundle" --bundle-sha256 "$reviewed_admin_manifest_sha"
python3 "$controller" verify --stage "$pilot/stage-exit"
```

The controller runs full positive/wrong-UUID VPN and endpoint verification before and after publication. It records immutable admin copies of the original baseline, entry receipt, prior verification and any committed static revision receipt. The original baseline, manifest, Caddy rollback files, and existing static plan/state bytes are preserved. Existing `/` and `/my/` revision expectations remain in force, and the new admin hash is applied afterward. The publish is one atomic rename. On a failed HTTP/full verification, an owned admin inode is restored and the exact old response and full VPN checks run again. Unknown inode/hash/permissions fail closed as **RECOVERY INCOMPLETE**.

The manifest bytes are hashed and parsed together, then checked against the supplied reviewed hash again before any admin history is written; the exact checked bytes become the retained manifest. A committed static-state must remain byte-identical to the captured receipt. After completed admin rollback, only validated static rollback/recovery states may advance it: each target must match its recorded published or restored identity, and completed static rollback requires every recorded old restore identity. Pending static recovery blocks ordinary verification and remains resumable through `rollback-static`.

If publishing fails or the admin page needs to return to its prior version, use the guarded admin rollback:

```sh
python3 "$controller" rollback-admin --stage "$pilot/stage-exit"
python3 "$controller" verify --stage "$pilot/stage-exit"
```

`rollback-admin` restores only the recorded old/new/restored inode and keeps all history. The main VPN `rollback` retains the accepted admin revision. If a static rollback is also needed, run `rollback-admin` first; the static rollback command refuses while the admin revision is active or pending. The admin revision is single-use, including after rollback. Interrupted publish/rollback leaves its journal for the same `rollback-admin` recovery path; do not remove stage files or interpret an incomplete recovery as success.

## Evidence and limits

```sh
python -m unittest discover -s work/mayak/deploy/https-entry/tests -v
```

Windows-local tests use explicit mocks for Linux ownership, systemd, child sockets and requests. Actual Linux/Caddy parsing/service-user execution, root permissions, DB authentication, TLS/foreign traversal, graceful reload, live rollback and physical phone are **NOT VERIFIED by this package author**. They are mandatory runtime gates, never inferred PASS results. No live-target/network calls, commits, uploads or VPN changes were made during correction. Model usage/cost and first-version/rework wall time are unknown; test timing does not imply either.
