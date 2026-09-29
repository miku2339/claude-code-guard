import importlib.util
import io
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from unittest import mock


RESOURCES = pathlib.Path(__file__).parents[1] / "Resources"
GUARD_SPEC = importlib.util.spec_from_file_location("guard", RESOURCES / "guard.py")
guard = importlib.util.module_from_spec(GUARD_SPEC)
assert GUARD_SPEC.loader is not None
sys.modules["guard"] = guard
GUARD_SPEC.loader.exec_module(guard)
CLI_SPEC = importlib.util.spec_from_file_location("cli_guard", RESOURCES / "cli_guard.py")
cli_guard = importlib.util.module_from_spec(CLI_SPEC)
assert CLI_SPEC.loader is not None
CLI_SPEC.loader.exec_module(cli_guard)


def completed(returncode=0, output=b""):
    return subprocess.CompletedProcess([], returncode, b"", output)


def passing_checks():
    return [guard.check(check_id, check_id, "pass", "verified") for check_id in sorted(cli_guard.REQUIRED_LAUNCH_CHECK_IDS)]


class ProtectionTests(unittest.TestCase):
    def test_resource_metadata_has_portable_paths_and_hashes(self):
        expected = cli_guard.load_protection_metadata()
        self.assertIsNotNone(expected)
        self.assertEqual(set(expected), set(cli_guard.PROTECTED_PATHS))
        metadata = json.loads(cli_guard.PROTECTION_PATH.read_text())
        for item in metadata["templates"].values():
            self.assertTrue(item["path"].startswith("~/"))
            self.assertNotIn(str(pathlib.Path.home()), item["path"])
            self.assertRegex(item["sha256"], r"^[0-9a-f]{64}$")

    def test_file_digest_uses_temporary_fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "fixture"
            path.write_bytes(b"verified template")
            path.chmod(0o700)
            self.assertEqual(
                cli_guard.secure_file_digest(path, True),
                "cbabf67a6bd271b1aa139121a1a833ae597704434f6497ed5630e393914d44d5",
            )

    def test_changed_or_group_writable_protected_file_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            files = {name: root / name for name in cli_guard.PROTECTED_PATHS}
            hashes = {}
            for name, path in files.items():
                path.write_text(name)
                path.chmod(0o700 if name in cli_guard.EXECUTABLE_TEMPLATES else 0o600)
                hashes[name] = cli_guard.secure_file_digest(path, name in cli_guard.EXECUTABLE_TEMPLATES)
            with mock.patch.object(cli_guard, "PROTECTED_PATHS", files), mock.patch.object(cli_guard, "load_protection_metadata", return_value=hashes), mock.patch.object(cli_guard.browser_entry, "broker_is_ready", return_value=True):
                self.assertEqual(cli_guard.verify_process_guard()["status"], "pass")
                files["launcher"].write_text("changed")
                self.assertEqual(cli_guard.verify_process_guard()["status"], "fail")
                files["launcher"].write_text("launcher")
                files["launcher"].chmod(0o720)
                self.assertEqual(cli_guard.verify_process_guard()["status"], "fail")


class InstalledCLITests(unittest.TestCase):
    def test_signed_binary_inside_versions_is_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            home = pathlib.Path(directory)
            versions = home / "versions"
            versions.mkdir()
            binary = versions / "2.1.274"
            binary.write_bytes(b"binary")
            binary.chmod(0o700)
            link = home / "claude"
            link.symlink_to(binary)
            signature = b"Identifier=com.anthropic.claude-code\nTeamIdentifier=Q6L2SF6YDW\n"
            with mock.patch.object(cli_guard, "CLI_SYMLINK", link), mock.patch.object(cli_guard, "CLI_VERSIONS_ROOT", versions), mock.patch.object(guard, "run_command", side_effect=[completed(), completed(output=signature)]):
                result, verified, target = cli_guard.verify_installed_cli()
            self.assertEqual(result["status"], "pass")
            self.assertTrue(verified)
            self.assertEqual(target, binary.resolve())
            versions.chmod(0o720)
            with mock.patch.object(cli_guard, "CLI_SYMLINK", link), mock.patch.object(cli_guard, "CLI_VERSIONS_ROOT", versions):
                self.assertEqual(cli_guard.verify_installed_cli()[0]["status"], "fail")

    def test_outside_target_or_bad_signature_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            home = pathlib.Path(directory)
            versions = home / "versions"
            versions.mkdir()
            outside = home / "outside"
            outside.write_bytes(b"binary")
            outside.chmod(0o700)
            link = home / "claude"
            link.symlink_to(outside)
            with mock.patch.object(cli_guard, "CLI_SYMLINK", link), mock.patch.object(cli_guard, "CLI_VERSIONS_ROOT", versions):
                self.assertEqual(cli_guard.verify_installed_cli()[0]["status"], "fail")

            binary = versions / "2.1.274"
            binary.write_bytes(b"binary")
            binary.chmod(0o700)
            link.unlink()
            link.symlink_to(binary)
            bad = b"Identifier=example.invalid\nTeamIdentifier=WRONG\n"
            with mock.patch.object(cli_guard, "CLI_SYMLINK", link), mock.patch.object(cli_guard, "CLI_VERSIONS_ROOT", versions), mock.patch.object(guard, "run_command", side_effect=[completed(), completed(output=bad)]):
                self.assertEqual(cli_guard.verify_installed_cli()[0]["status"], "fail")


class GateAndLaunchTests(unittest.TestCase):
    def test_unknown_exit_blocks_without_exec(self):
        checks = passing_checks()
        checks[next(index for index, item in enumerate(checks) if item["id"] == "proxy_exit")] = guard.check("proxy_exit", "代理出口", "unknown", "沒有出口資料。")
        result = {"checks": checks, "canLaunch": True}
        with mock.patch.object(os, "execve") as execute, redirect_stderr(io.StringIO()) as output:
            status = cli_guard.launch(result, True, {"TZ": "Asia/Tokyo", "LANG": "ja_JP.UTF-8", "LC_ALL": "ja_JP.UTF-8"}, pathlib.Path("/tmp"))
        self.assertNotEqual(status, 0)
        execute.assert_not_called()
        self.assertIn("代理出口", output.getvalue())

    def test_hosting_acceptance_is_bound_to_risk_snapshot(self):
        payload = {
            "status": "ok",
            "203.0.113.7": {
                "detections": {**{name: False for name in guard.RISK_FLAGS}, "hosting": True, "risk": 30, "confidence": 99},
                "network": {"type": "Hosting", "provider": "Example"},
                "location": {"country_code": "JP", "timezone": "Asia/Tokyo"},
            },
        }
        snapshot = guard.validated_reputation(payload, "203.0.113.7")
        _result, acknowledgement = guard.reputation_decision(snapshot, 1000, None)
        self.assertTrue(guard.reputation_decision(snapshot, 1000, acknowledgement["snapshotKey"])[1]["accepted"])
        snapshot["detections"]["risk"] = 31
        self.assertFalse(guard.reputation_decision(snapshot, 1000, acknowledgement["snapshotKey"])[1]["accepted"])

    def test_project_with_spaces_execs_exact_launcher_and_valid_environment(self):
        result = {"checks": passing_checks(), "canLaunch": True}
        settings = {"TZ": "Asia/Tokyo", "LANG": "ja_JP.UTF-8", "LC_ALL": "ja_JP.UTF-8"}
        local_cli = (guard.check("installed_cli", "CLI", "pass", "ok"), True, pathlib.Path("/verified"))
        local_guard = guard.check("process_guard", "guard", "pass", "ok")
        with tempfile.TemporaryDirectory(prefix="Claude project ") as directory, mock.patch.dict(os.environ, {"EXISTING_AUTH_REFERENCE": "preserved"}, clear=True), mock.patch.object(cli_guard, "verify_installed_cli", return_value=local_cli), mock.patch.object(cli_guard, "verify_process_guard", return_value=local_guard), mock.patch.object(os, "chdir") as change_directory, mock.patch.object(os, "execve", side_effect=OSError) as execute, redirect_stderr(io.StringIO()):
            status = cli_guard.launch(result, True, settings, pathlib.Path(directory))
        self.assertNotEqual(status, 0)
        change_directory.assert_called_once_with(pathlib.Path(directory))
        path, arguments, environment = execute.call_args.args
        self.assertEqual(path, str(cli_guard.CLI_LAUNCHER))
        self.assertEqual(arguments, ["claude"])
        self.assertEqual(environment["EXISTING_AUTH_REFERENCE"], "preserved")
        self.assertEqual(environment["BROWSER"], str(cli_guard.BROWSER_ENTRY))
        self.assertEqual({name: environment[name] for name in settings}, settings)

    def test_local_integrity_change_before_exec_is_rejected(self):
        result = {"checks": passing_checks(), "canLaunch": True}
        settings = {"TZ": "Asia/Tokyo", "LANG": "ja_JP.UTF-8", "LC_ALL": "ja_JP.UTF-8"}
        changed = (guard.check("installed_cli", "已安裝官方 CLI", "fail", "symlink 已改變。"), False, None)
        with mock.patch.object(cli_guard, "verify_installed_cli", return_value=changed), mock.patch.object(cli_guard, "verify_process_guard", return_value=guard.check("process_guard", "guard", "pass", "ok")), mock.patch.object(os, "execve") as execute, redirect_stderr(io.StringIO()) as output:
            status = cli_guard.launch(result, True, settings, pathlib.Path("/tmp"))
        self.assertNotEqual(status, 0)
        execute.assert_not_called()
        self.assertIn("symlink 已改變", output.getvalue())

        unchanged = (guard.check("installed_cli", "CLI", "pass", "ok"), True, pathlib.Path("/verified"))
        changed_guard = guard.check("process_guard", "CLI 程序保護", "fail", "wrapper 已改變。")
        with mock.patch.object(cli_guard, "verify_installed_cli", return_value=unchanged), mock.patch.object(cli_guard, "verify_process_guard", return_value=changed_guard), mock.patch.object(os, "execve") as execute, redirect_stderr(io.StringIO()) as output:
            status = cli_guard.launch(result, True, settings, pathlib.Path("/tmp"))
        self.assertNotEqual(status, 0)
        execute.assert_not_called()
        self.assertIn("wrapper 已改變", output.getvalue())

    def test_launch_settings_are_derived_from_verified_exit(self):
        timezone_check, language_check, settings = cli_guard.launch_setting_checks({"country": "JP", "timeZone": "Asia/Tokyo"})
        self.assertEqual(timezone_check["status"], "pass")
        self.assertEqual(language_check["status"], "pass")
        self.assertEqual(settings, {"TZ": "Asia/Tokyo", "LANG": "ja_JP.UTF-8", "LC_ALL": "ja_JP.UTF-8"})
        self.assertEqual(cli_guard.locale_from_language("zh-Hant-TW"), "zh_TW.UTF-8")
        self.assertEqual(cli_guard.launch_setting_checks(None)[0]["status"], "unknown")


class ResponseTests(unittest.TestCase):
    def test_invalid_process_guard_skips_sandbox_probe(self):
        acknowledgement = {"eligible": False, "snapshotKey": "", "accepted": False, "detail": ""}
        with mock.patch.object(cli_guard, "verify_installed_cli", return_value=(guard.check("installed_cli", "CLI", "pass", "ok"), True, pathlib.Path("/verified"))), mock.patch.object(cli_guard, "verify_process_guard", return_value=guard.check("process_guard", "guard", "fail", "changed")), mock.patch.object(guard, "cloudflare_trace", return_value=(guard.check("proxy_exit", "exit", "pass", "ok"), {"ip": "1.1.1.1", "country": "JP"})), mock.patch.object(guard, "ipwho_check", return_value=(guard.check("exit_location", "location", "pass", "ok"), {"ip": "1.1.1.1", "country": "JP", "timeZone": "Asia/Tokyo", "utcOffset": 32400})), mock.patch.object(guard, "proxycheck_check", return_value=(guard.check("exit_reputation", "reputation", "pass", "ok"), acknowledgement)), mock.patch.object(guard, "sandbox_check") as sandbox_probe:
            result, _verified, _binary, _settings = cli_guard.perform_check()
        sandbox_probe.assert_not_called()
        sandbox_result = next(item for item in result["checks"] if item["id"] == "network_sandbox")
        self.assertEqual(sandbox_result["status"], "unknown")
        self.assertIn("已跳過", sandbox_result["detail"])

    def test_response_schema_and_no_webrtc_claim(self):
        acknowledgement = {"eligible": False, "snapshotKey": "", "accepted": False, "detail": ""}
        with mock.patch.object(cli_guard, "verify_installed_cli", return_value=(guard.check("installed_cli", "CLI", "pass", "ok"), True, pathlib.Path("/verified"))), mock.patch.object(cli_guard, "verify_process_guard", return_value=guard.check("process_guard", "guard", "pass", "ok")), mock.patch.object(guard, "cloudflare_trace", return_value=(guard.check("proxy_exit", "exit", "pass", "ok"), {"ip": "1.1.1.1", "country": "JP"})), mock.patch.object(guard, "ipwho_check", return_value=(guard.check("exit_location", "location", "pass", "ok"), {"ip": "1.1.1.1", "country": "JP", "timeZone": "Asia/Tokyo", "utcOffset": 32400})), mock.patch.object(guard, "proxycheck_check", return_value=(guard.check("exit_reputation", "reputation", "pass", "ok"), acknowledgement)), mock.patch.object(guard, "sandbox_check", return_value=guard.check("network_sandbox", "sandbox", "pass", "ok")):
            result, verified, _binary, settings = cli_guard.perform_check()
        self.assertTrue(verified)
        self.assertTrue(result["canLaunch"])
        self.assertEqual(result["target"], "cli")
        self.assertEqual(result["permissions"], [])
        self.assertEqual(set(result), {"checkedAt", "canLaunch", "checks", "permissions", "hostingAcknowledgement", "exitContext", "target"})
        self.assertNotIn("webrtc", json.dumps(result).lower())
        self.assertIsNotNone(settings)


if __name__ == "__main__":
    unittest.main()
