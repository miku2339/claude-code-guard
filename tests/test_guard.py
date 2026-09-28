import errno
import importlib.util
import io
import json
import math
import pathlib
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from unittest import mock


GUARD_PATH = pathlib.Path(__file__).parents[1] / "Resources/guard.py"
SPEC = importlib.util.spec_from_file_location("desktop_guard", GUARD_PATH)
guard = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(guard)


def proxy_payload(**overrides):
    detections = {name: False for name in guard.RISK_FLAGS}
    detections.update({"risk": 10, "confidence": 99})
    detections.update(overrides)
    return {"status": "ok", "203.0.113.7": {
        "detections": detections,
        "network": {"type": "Residential", "provider": "Test provider"},
        "location": {"country_code": "JP", "timezone": "Asia/Tokyo"},
    }}


def launch_checks(overrides=None):
    overrides = overrides or {}
    return [
        {"id": check_id, "title": check_id, "status": overrides.get(check_id, "pass"), "detail": "verified"}
        for check_id in sorted(guard.REQUIRED_LAUNCH_CHECK_IDS)
    ]


class ProxyCheckTests(unittest.TestCase):
    def test_malformed_risk_is_unknown(self):
        for risk in (True, "10", math.nan, -1, 101):
            status, _ = guard.evaluate_proxycheck(proxy_payload(risk=risk), "203.0.113.7")
            self.assertEqual(status, "unknown")

    def test_missing_or_non_boolean_detection_is_unknown(self):
        payload = proxy_payload()
        del payload["203.0.113.7"]["detections"]["vpn"]
        self.assertEqual(guard.evaluate_proxycheck(payload, "203.0.113.7")[0], "unknown")
        self.assertEqual(guard.evaluate_proxycheck(proxy_payload(hosting=1), "203.0.113.7")[0], "unknown")

    def test_detection_or_high_risk_fails(self):
        self.assertEqual(guard.evaluate_proxycheck(proxy_payload(hosting=True), "203.0.113.7")[0], "fail")
        self.assertEqual(guard.evaluate_proxycheck(proxy_payload(risk=25.1), "203.0.113.7")[0], "fail")

    def test_exact_ip_and_clean_result_pass(self):
        payload = proxy_payload()
        self.assertEqual(guard.evaluate_proxycheck(payload, "203.0.113.8")[0], "unknown")
        self.assertEqual(guard.evaluate_proxycheck(payload, "203.0.113.7")[0], "pass")

    def test_complete_metadata_is_required(self):
        for section, field in (("detections", "confidence"), ("network", "provider"), ("location", "timezone")):
            payload = proxy_payload()
            del payload["203.0.113.7"][section][field]
            self.assertEqual(guard.evaluate_proxycheck(payload, "203.0.113.7")[0], "unknown")
        for value in (False, math.nan, 101):
            self.assertEqual(guard.evaluate_proxycheck(proxy_payload(confidence=value), "203.0.113.7")[0], "unknown")

    def test_reputation_must_match_current_geography(self):
        payload = proxy_payload()
        context = {"ip": "203.0.113.7", "country": "US", "timeZone": "America/New_York"}
        self.assertIsNone(guard.validated_reputation(payload, context["ip"], context))

    def test_acknowledgement_is_bound_to_exact_hosting_snapshot(self):
        snapshot = guard.validated_reputation(proxy_payload(hosting=True, risk=33), "203.0.113.7")
        result, ack = guard.reputation_decision(snapshot, 1000, None)
        self.assertEqual(result["status"], "fail")
        self.assertTrue(ack["eligible"])
        self.assertFalse(ack["accepted"])
        result, accepted = guard.reputation_decision(snapshot, 1000, ack["snapshotKey"])
        self.assertEqual(result["status"], "pass")
        self.assertTrue(accepted["accepted"])
        self.assertFalse(guard.reputation_decision(snapshot, 1001, ack["snapshotKey"])[1]["accepted"])
        snapshot["detections"]["risk"] = 34
        self.assertFalse(guard.reputation_decision(snapshot, 1000, ack["snapshotKey"])[1]["accepted"])

    def test_other_risks_cannot_be_acknowledged(self):
        for flag in (name for name in guard.RISK_FLAGS if name != "hosting"):
            snapshot = guard.validated_reputation(proxy_payload(hosting=True, **{flag: True}), "203.0.113.7")
            result, ack = guard.reputation_decision(snapshot, 1000, "forged")
            self.assertEqual(result["status"], "fail")
            self.assertFalse(ack["eligible"])
            self.assertFalse(ack["accepted"])


class EnvironmentTests(unittest.TestCase):
    def test_regions_and_ukrainian_subdivision(self):
        self.assertEqual(guard.supported_region("JP", None)[0], "pass")
        self.assertEqual(guard.supported_region("US", None)[0], "pass")
        self.assertEqual(guard.supported_region("HK", None)[0], "fail")
        self.assertEqual(guard.supported_region("UA", None)[0], "unknown")
        self.assertEqual(guard.supported_region("UA", "Kherson Oblast")[0], "fail")
        self.assertEqual(guard.supported_region("UA", "Kyiv")[0], "pass")

    def test_current_ip_country_and_offset_must_match(self):
        value = {"ip": "1.1.1.1", "success": True, "country_code": "JP", "region": "Tokyo",
                 "timezone": {"id": "Asia/Tokyo", "offset": 32400}}
        context = {"ip": "1.1.1.1", "country": "JP"}
        with mock.patch.object(guard, "curl_bytes", return_value=json.dumps(value).encode()):
            self.assertEqual(guard.ipwho_check(context)[0]["status"], "pass")
            self.assertEqual(guard.ipwho_check({**context, "ip": "8.8.8.8"})[0]["status"], "fail")
            self.assertEqual(guard.ipwho_check({**context, "country": "US"})[0]["status"], "fail")
        value["timezone"]["offset"] = 0
        with mock.patch.object(guard, "curl_bytes", return_value=json.dumps(value).encode()):
            self.assertEqual(guard.ipwho_check(context)[0]["status"], "fail")

    def test_languages_use_ordered_exit_locale(self):
        with mock.patch.object(guard, "defaults_value", side_effect=['(\n    "ja-JP",\n    ja\n)', 'ja_JP']):
            self.assertEqual(guard.language_check({"country": "JP"})["status"], "pass")
        with mock.patch.object(guard, "defaults_value", side_effect=['(\n    "en-US",\n    en\n)', 'en_US']):
            self.assertEqual(guard.language_check({"country": "JP"})["status"], "fail")
        with mock.patch.object(guard, "defaults_value", side_effect=['(\n    "zh-Hant-TW",\n    "zh-Hant"\n)', 'zh_Hant_TW']):
            self.assertEqual(guard.language_check({"country": "TW"})["status"], "pass")


class ReputationCacheTests(unittest.TestCase):
    def test_cache_expiry_context_permissions_and_symlink(self):
        context = {"ip": "203.0.113.7", "country": "JP", "timeZone": "Asia/Tokyo", "utcOffset": 32400}
        now = time.time()
        value = {"schema": 1, "fetchedAt": now, "context": context, "payload": proxy_payload(hosting=True)}
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "reputation.json"
            with mock.patch.object(guard, "CACHE_PATH", path):
                guard.write_reputation_cache(value)
                self.assertIsNotNone(guard.read_reputation_cache(context, now))
                self.assertIsNone(guard.read_reputation_cache(context, now + 1800))
                self.assertIsNone(guard.read_reputation_cache(context, now - 1))
                self.assertIsNone(guard.read_reputation_cache({**context, "country": "US"}, now))
                path.chmod(0o644)
                self.assertIsNone(guard.read_reputation_cache(context, now))
                target = pathlib.Path(directory) / "target"
                path.rename(target)
                target.chmod(0o600)
                path.symlink_to(target)
                self.assertIsNone(guard.read_reputation_cache(context, now))


class GateTests(unittest.TestCase):
    def test_unknown_and_fail_never_launch(self):
        self.assertFalse(guard.compute_can_launch(launch_checks({"tcc_authorization": "unknown"}), True))
        self.assertFalse(guard.compute_can_launch(launch_checks({"os_firewall": "fail"}), True))
        self.assertFalse(guard.compute_can_launch(launch_checks(), False))
        self.assertTrue(guard.compute_can_launch(launch_checks(), True))

    def test_firewall_without_evidence_blocks(self):
        self.assertEqual(guard.evaluate_firewall()["status"], "unknown")

    def test_empty_missing_duplicate_or_invalid_checks_block(self):
        self.assertFalse(guard.compute_can_launch([], True))
        missing = launch_checks()[:-1]
        self.assertFalse(guard.compute_can_launch(missing, True))
        duplicated = launch_checks() + [launch_checks()[0]]
        self.assertFalse(guard.compute_can_launch(duplicated, True))
        invalid = launch_checks()
        invalid[0] = {**invalid[0], "status": "PASS"}
        self.assertFalse(guard.compute_can_launch(invalid, True))

    def test_frontend_canlaunch_injection_cannot_start_process(self):
        result = {"checkedAt": "2026-01-01T00:00:00Z", "canLaunch": True,
                  "checks": launch_checks({"tcc_authorization": "unknown"}), "permissions": []}
        with mock.patch.object(guard.subprocess, "Popen") as popen, redirect_stdout(io.StringIO()) as output:
            self.assertNotEqual(guard.launch(result, True), 0)
        popen.assert_not_called()
        self.assertFalse(result["canLaunch"])
        self.assertFalse(__import__("json").loads(output.getvalue())["canLaunch"])

    def test_launch_transport_is_explicit(self):
        environment = guard.launch_environment("Asia/Tokyo")
        for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
            self.assertEqual(environment[name], guard.PROXY_URL)
        self.assertEqual(environment["NO_PROXY"], "")
        self.assertEqual(environment["no_proxy"], "")
        self.assertEqual(environment["TZ"], "Asia/Tokyo")
        command = guard.launch_command(pathlib.Path("/Applications/Claude.app/Contents/MacOS/Claude"))
        self.assertIn("--proxy-server=http://127.0.0.1:17897", command)
        self.assertIn("--force-webrtc-ip-handling-policy=disable_non_proxied_udp", command)
        self.assertIn("--disable-quic", command)


class ProbeTests(unittest.TestCase):
    def test_probe_requires_verified_eperm_and_proxy(self):
        blocked = {name: {"outcome": "denied", "errno": errno.EPERM} for name in ("ipv4", "ipv6", "udp")}
        blocked["proxy"] = {"outcome": "connected"}
        self.assertEqual(guard.evaluate_probe_results(blocked)[0], "pass")

        allowed = dict(blocked)
        allowed["ipv4"] = {"outcome": "connected"}
        self.assertEqual(guard.evaluate_probe_results(allowed)[0], "fail")

        ambiguous = dict(blocked)
        ambiguous["udp"] = {"outcome": "error", "errno": errno.ECONNREFUSED}
        self.assertEqual(guard.evaluate_probe_results(ambiguous)[0], "unknown")


if __name__ == "__main__":
    unittest.main()
