from __future__ import annotations

import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
ENTRY = (ROOT / "release-entry.sh").read_text(encoding="utf-8")


class CandidateLifecycle(unittest.TestCase):
    def test_clone_survives_both_api_verifications_and_failure_cleans_up(self):
        helpers = ENTRY[ENTRY.index("stop_candidate() {"):ENTRY.index("restore_asset() {")]
        exit_handler = ENTRY[ENTRY.index("exit_release() {"):ENTRY.index("snapshot_assets() {")]
        candidate = ENTRY[ENTRY.index("candidate_check() {"):ENTRY.index("if [[ $ACTION == inspect ]]")]
        candidate = candidate[:candidate.rfind("\n}") + 2]
        with tempfile.TemporaryDirectory(prefix=".release-candidate-lifecycle-", dir=ROOT) as raw:
            root = pathlib.Path(raw)
            log = root / "events.log"
            template = r'''set -Eeuo pipefail
log=__LOG__; fixture=; candidate_pid=; release_id=lifecycle-test
API_DIR=/synthetic/old-api; DIST=/synthetic/dist; CONFIG=/synthetic/config
SAFETY=/synthetic/safety; db_name=source; static_root=/synthetic/static
candidate_env=(one two three four five six); endpoint_names=(); fixture_root=
candidate_api=/synthetic/candidate; service_stopped=0
note(){ printf 'note:%s\n' "$1" >>"$log"; }
die(){ printf 'die:%s\n' "$1" >>"$log"; exit 2; }
runuser(){
  case "$*" in
    *createdb*) printf 'createdb\n' >>"$log" ;;
    *pg_restore*) printf 'restore\n' >>"$log" ;;
    *dropdb*) printf 'dropdb\n' >>"$log"; [[ ${FAIL_DROPDB:-0} != 1 ]] ;;
  esac
  return $?
}
timeout(){ shift; "$@"; }
compare_database_counts(){ printf 'compare\n' >>"$log"; }
mkdir(){ if [[ $1 == -m ]]; then command mkdir "$3"; else command mkdir "$@"; fi; }
python3(){
  if [[ $1 == -c ]]; then printf '49123\n'; return 0; fi
  case "$2" in
    candidate-endpoint) return 0 ;;
    fixture-snapshot) printf 'snapshot\n' >>"$log" ;;
    fixture-verify)
      printf 'verify:%s\n' "${VERIFY_KIND:-candidate}" >>"$log"
      if [[ ${FAIL_VERIFY:-0} == 1 && ${VERIFY_KIND:-candidate} == candidate ]]; then return 1; fi
      if [[ ${VERIFY_KIND:-candidate} == candidate ]]; then VERIFY_KIND=old; fi
      ;;
    *) return 1 ;;
  esac
}
curl(){ return 0; }
setsid(){ sleep 20 & wait $!; }
trap 'exit_release "$?"' EXIT
'''
            scenarios = (("success", False, False), ("verify-failure", True, False),
                         ("cleanup-failure", False, True))
            for label, fail_verify, fail_cleanup in scenarios:
                case_dir = root / label
                case_dir.mkdir()
                dump_file = case_dir / "dump"
                dump_file.write_bytes(b"fixture dump")
                (case_dir / "candidate").mkdir()
                (case_dir / "old-api").mkdir()
                shell_dir = case_dir.as_posix()
                script = template.replace("__LOG__", shell_dir + "/events.log")
                script = script.replace("/synthetic/candidate", shell_dir + "/candidate")
                script = script.replace("/synthetic/old-api", shell_dir + "/old-api")
                script += "\n" + helpers + "\n" + exit_handler + "\n" + candidate.replace("/run/mayak-release-", shell_dir + "/fixture-")
                script += "\nVERIFY_KIND=candidate\n"
                if fail_verify:
                    script += "FAIL_VERIFY=1\n"
                if fail_cleanup:
                    script += "FAIL_DROPDB=1\n"
                script += 'candidate_check "$candidate_api" ' + dump_file.as_posix() + '\n'
                script += "service_stopped=1; printf 'production-stop\\n' >>\"$log\"\n"
                result = subprocess.run([shutil.which("bash"), "-c", script], capture_output=True,
                                        text=True, encoding="utf-8", errors="replace", timeout=30)
                self.assertTrue((case_dir / "events.log").exists(), result.stderr + result.stdout)
                events = (case_dir / "events.log").read_text().splitlines()
                if fail_verify or fail_cleanup:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("dropdb", events)
                    self.assertNotIn("production-stop", events)
                    if fail_verify:
                        self.assertEqual(events.count("verify:candidate"), 1)
                        self.assertNotIn("verify:old", events)
                    if fail_cleanup:
                        self.assertEqual(events.count("verify:candidate"), 1)
                        self.assertEqual(events.count("verify:old"), 1)
                        self.assertIn("note:Fixture cleanup failed; inspect the retained fixture name before any retry.", events)
                else:
                    self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
                    self.assertEqual(events.count("verify:candidate"), 1)
                    self.assertEqual(events.count("verify:old"), 1, repr(events))
                    self.assertLess(events.index("verify:candidate"), events.index("verify:old"))
                    self.assertLess(events.index("verify:old"), events.index("dropdb"))
                    self.assertLess(events.index("dropdb"), events.index("production-stop"))


if __name__ == "__main__":
    unittest.main()
