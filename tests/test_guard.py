import errno
import importlib.util
import io
import math
import pathlib
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
    detections.update({"risk": 10})
    detections.update(overrides)
    return {"status": "ok", "203.0.113.7": {"detections": detections}}


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
        environment = guard.launch_environment()
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
