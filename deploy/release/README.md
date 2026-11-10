# Mayak pull release procedure

This API-only procedure is pending independent source acceptance. Target facts
are recorded in `work/release-20261029/TARGET_PREFLIGHT.md`. An informational
`inspect-target.sh` result is not an apply authorization. The director integrates
these instructions into the existing `work/RELEASE_RUNBOOK.md`; do not use the
old destructive `deploy/api/install.sh`.

## One preparation and switch path

1. After integrated source review, build the public-only bundle with this
   argument shape:

   ```bash
   python3 build_bundle.py --api-publish API_PUBLISH --agent AGENT \
     --windows-package WINDOWS_PACKAGE --android-package ANDROID_PACKAGE \
     --windows-feed WINDOWS_FEED --android-feed ANDROID_FEED \
     --update-public-key UPDATE_PUBLIC_KEY --output BUNDLE \
     --release-id RELEASE_ID --version FOUR_PART_VERSION \
     --android-version-code INTEGER
   ```

   Example only: `--version 5.1.0.5 --android-version-code 2187` remains
   provisional. The builder derives the
   fixed Windows/Android filenames and checks each Ed25519 feed signature,
   product/channel/platform, version/code, URL, package SHA-256 and size, and
   that the signed publication interval is current. Builder and target verifier
   both pin the supplied public key's SPKI SHA-256 to the production clients'
   embedded `mayak-client/mayak/update_signing_public.pem` resource
   (`98951331395b223d3039043b3f0dcaa15e177eedc459cd84fbab27d2eaaa3584`).
   The key carried in the archive is checked against this trusted control pin;
   it does not establish its own trust. The bundle also includes the four
   executable controls and observed pre-release HTML overlay hashes.
2. Obtain the exact archive SHA-256 independently from the release owner. Download
   via HTTPS without redirects. Verify that SHA before extracting or executing
   anything. Obtain the four bootstrap control files from that verified archive,
   or verify their independently supplied hashes before executing them. Keep them
   together in a root-controlled directory. The entry script compares all four
   files against the validated archive before staging or switching.
3. Run `sudo bash release-entry.sh --inspect --bundle BUNDLE --sha256 SHA256`.
   This checks the effective API unit, Caddy identity and exact loaded-vs-adapted
   configuration, local DB identity, protected paths, gateway public pin, runtime,
   disk capacity, and every archive member. No inspect result proves restore or
   candidate runtime; those are executable gates in apply.
4. Account for every DB writer and establish the quiet registration/admin write
   window. `--confirm-api-only` attests that this supported API is the only writer;
   `--confirm-write-window` attests that the agreed write window is active. Unknown
   writers, custom config, or unknown target layout require a separate review.
5. Run `sudo bash release-entry.sh --apply --bundle BUNDLE --sha256 SHA256 --confirm-api-only --confirm-write-window` as one command. The script stages
   packages, API, agent download and feed files while the API is on. It does not
   rewrite or reload Caddy. Apply requires the observed Caddyfile SHA-256
   `4371021453096fa9990acaedc0fb23fb18950e46f7199a70ebfdb553ff4e5353` and
   exact loaded-vs-adapted equality. Any drift blocks apply.
   It retains root-only binary/config/feed snapshots and an MVCC initial dump,
   restores that dump into a separate DB owned by `mayak`, compares table/row
   counts, checks the exact prior and additive migration IDs, checks table/column
   shape and preserved row counts/critical identifiers, and launches the
   candidate on a free loopback port. It then starts the currently installed
   API against that migrated clone and repeats the schema/data check. The clone
   remains present through candidate stop, both verification phases, and old
   API stop; it is dropped only afterward. The EXIT trap retries fixture
   cleanup and reports failure. Target verification also rechecks feed identity
   and that the signed publication interval has not expired. Telegram
   polling is disabled, the isolated snapshot must contain no interrupted
   provisioning work, and the fixture uses no production gateway key. All
   these gates finish before the first service stop. Test signatures use only
   isolated throwaway keys and do not touch production private-key material.
6. The switch stops only `mayak-api.service` (100-second command bound), takes an
   additional final dump (300-second bound), renames prepared API/agent files,
   starts and probes the API, verifies unchanged Caddy loaded equality, then
   atomically replaces the stable feeds. Same-origin
   HTTPS feed/package hashes and a `/sub/` canary must pass. Transport failure,
   unexpected canary status, token discovery, and unreadable journals all fail
   apply. The canary is never passed as an argument or printed.

The database parser reads only `ConnectionStrings:Db`, matching the application.
It accepts quoted semicolons/doubled quotes, local `localhost`, `127.0.0.1` or
`/var/run/postgresql`, port 5432, role `mayak`, and an ordinary identifier DB name.
The socket cluster must report port 5432 and DB owner `mayak`. Every resolved TCP loopback address must authenticate as the configured role and match the socket cluster DB OID and postmaster start time. The password is supplied through an anonymous Linux memory FD referenced by `PGPASSFILE`; no credential is placed in argv, environment values or a disk file. Missing memory-FD support, a mismatched local cluster, unavailable address or failed authentication refuses inspect/apply/rollback. Unknown options,
ambiguous/duplicate aliases, alternative keys, different ports/roles/hosts and
unsupported Kestrel endpoints are refused. Config values are never diagnostics.
Caddy must use User/Group `caddy`, the observed
`/usr/lib/systemd/system/caddy.service` fragment and exact baseline invocation.
The existing static update route and HTTPS pilot overlay are preserved byte for
byte; no Caddy reload occurs when the file remains unchanged. The pre-release
API snapshot records the full tree, including the observed root, `my`, and
`admin` HTML hashes, so rollback restores those bytes. New site files must come
from the frozen API bundle; stale live overlays are never merged over them.

## Failure and explicit rollback

Any nonzero exit after stop/switch preserves the original exit code and attempts
recovery through the same guarded transaction functions: prior API directory,
config, agent and feeds, Caddy restore/reload only if its bytes changed, API start and bounded health
probe. Each recovery operation is guarded so one failed file/Caddy restore does
not skip API restart. `RECOVERY INCOMPLETE` is a failure requiring console
diagnosis; it is never reported as a successful release. Retained files remain
available. Only API and Caddy service operations occur; VPN services, containers,
routes and firewall are unchanged.

For an explicit rollback, run:

```bash
sudo bash release-entry.sh --rollback RELEASE_ID
```

The script checks protected retained snapshot files, safely extracts regular
files into a new stage (no links/traversal/devices), verifies the retained API
and Caddy hash sidecars, checks the .NET 8 runtime config and service
readability, and runs the restored API against a fresh isolated restore of the
current database **before stopping**. Additive schema and current API compatibility
checks remain in place; rollback never executes a down migration or rewinds DB.
It refuses API config differences because this release path never changes that
config and cannot guess compatibility. It first saves current config/static
assets for a return path; failures after stop/swap/install/reload/health restore
the pre-rollback API and attempt to resume it. The prior current API is retained
under `/opt/mayak/releases/`, not deleted.

No path automatically restores a dump over production. Additive schema changes
and all writes after a backup remain. Retain `/var/backups/mayak-release/` and
old release directories until independent acceptance. A failed attempt retains
stages; do not reuse its immutable release ID or delete evidence blindly.

This revision refuses historical rollback receipts that lack the recorded API
and Caddy snapshot hashes. For those receipts, use the exact prior independently
reviewed revision-3 controller and its retained snapshot: controller SHA-256
`d7a098e39237d9303922c2eb54b73acf97e94a350103864228128fec4c5857f0`, as
documented in `work/RELEASE_RUNBOOK.md`. Do not synthesize sidecars for old
receipts or alter them. New snapshots from this controller include hash sidecars.

## Local evidence and limits

Run `python -m unittest discover -s deploy/release/tests -v` from the repository
root. `test_release_failures.py` executes real transaction/rollback code in
isolated temporary trees with fake service/ownership commands, tests DB parsing,
Caddy hash/equality/identity and journal failures, checks migration gate order, and restores a real custom dump in
a disposable loopback PostgreSQL cluster when local binaries are available.
Set `MAYAK_TEST_BASH` / `MAYAK_TEST_PG_BIN` for other installations. Missing tools
produce explicit skips, not production acceptance.

Windows Git Bash fixtures and local PostgreSQL evidence are not a Linux target
apply. Actual Linux candidate migration/old-binary compatibility, systemd/Unix
ownership and peer auth, loaded Caddy equality, HTTPS, actual DB/keys/config and
production apply/rollback remain NOT VERIFIED until observed on the target using
this reviewed procedure. No deployment is authorized by this local adaptation.
