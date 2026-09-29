import importlib.util
import io
import pathlib
import os
import socket
import struct
import plistlib
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr
from unittest import mock


SOURCE = pathlib.Path(__file__).parents[1] / "Resources/browser_entry.py"
SPEC = importlib.util.spec_from_file_location("browser_entry", SOURCE)
browser_entry = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(browser_entry)


class BrowserEntryTests(unittest.TestCase):
    def test_official_login_endpoints(self):
        for host, path in browser_entry.LOGIN_ENDPOINTS:
            self.assertTrue(browser_entry.valid_login_url(f"https://{host}{path}?state=example&code_challenge=a%2Bb"))

    def test_foreign_host_credentials_port_and_fragment_are_rejected(self):
        for url in (
            "https://claude.com.attacker.test/cai/oauth/authorize?state=example",
            "https://user@claude.com/cai/oauth/authorize?state=example",
            "https://claude.com:443/cai/oauth/authorize?state=example",
            "https://claude.com/cai/oauth/authorize?state=example#fragment",
            "http://claude.com/cai/oauth/authorize?state=example",
            "https://claude.com/cai/oauth/authorize?state=example\n",
            "https://claude.com/cai/oauth/authorize",
            "https://claude.com/redirect?state=example",
        ):
            with self.subTest(url=url):
                self.assertFalse(browser_entry.valid_login_url(url))

    def test_invalid_arguments_never_open_a_browser(self):
        with mock.patch.object(browser_entry, "verified_browser") as verify, mock.patch.object(subprocess, "run") as run, redirect_stderr(io.StringIO()):
            self.assertEqual(browser_entry.main([]), 64)
            self.assertEqual(browser_entry.main(["https://attacker.test"]), 64)
            self.assertEqual(browser_entry.main(["--args", "value"]), 64)
        verify.assert_not_called()
        run.assert_not_called()

    def test_exact_url_is_forwarded_without_shell_or_fallback(self):
        url = "https://claude.com/cai/oauth/authorize?state=example&code_challenge=a%2Bb"
        with mock.patch.object(browser_entry, "verified_browser", return_value=True), mock.patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as run:
            self.assertEqual(browser_entry.open_login_url(url), 0)
        self.assertEqual(run.call_args.args[0], ["/usr/bin/open", "-n", "-a", str(browser_entry.BROWSER_APP), "--args", "--login-url", url])
        self.assertNotIn("shell", run.call_args.kwargs)

    def test_missing_browser_blocks_without_logging_login_url(self):
        url = "https://claude.com/cai/oauth/authorize?state=example"
        with mock.patch.object(browser_entry, "verified_browser", return_value=False), mock.patch.object(subprocess, "run") as run, redirect_stderr(io.StringIO()) as output:
            self.assertEqual(browser_entry.open_login_url(url), 69)
        run.assert_not_called()
        self.assertNotIn(url, output.getvalue())

    def test_cli_only_sends_the_original_url_to_the_local_broker(self):
        url = "https://claude.com/cai/oauth/authorize?state=example"
        with mock.patch.object(browser_entry, "broker_request", return_value=b"0") as request, mock.patch.object(subprocess, "run") as run:
            self.assertEqual(browser_entry.main([url]), 0)
        request.assert_called_once_with(url.encode("utf-8"))
        run.assert_not_called()

    def test_unavailable_broker_has_no_direct_browser_fallback(self):
        url = "https://claude.com/cai/oauth/authorize?state=example"
        with mock.patch.object(browser_entry, "broker_request", return_value=None), mock.patch.object(subprocess, "run") as run, redirect_stderr(io.StringIO()) as output:
            self.assertEqual(browser_entry.main([url]), 69)
        run.assert_not_called()
        self.assertNotIn(url, output.getvalue())

    def test_broker_rejects_other_users_and_oversized_frames(self):
        for uid, frame, expected in (
            (os.getuid() + 1, b"", b"69"),
            (os.getuid(), struct.pack("!I", browser_entry.MAX_URL_BYTES + 1), b"64"),
        ):
            client, server = socket.socketpair()
            try:
                client.sendall(frame)
                with mock.patch.object(browser_entry, "peer_uid", return_value=uid), mock.patch.object(browser_entry, "open_login_url") as open_url:
                    browser_entry.handle_request(server, b"hash")
                self.assertEqual(client.recv(128), expected)
                open_url.assert_not_called()
            finally:
                client.close()
                server.close()

    def test_broker_validates_the_url_before_launching(self):
        for value, expected in (("https://attacker.test", b"64"), ("https://claude.com/cai/oauth/authorize?state=example", b"0")):
            client, server = socket.socketpair()
            try:
                payload = value.encode("utf-8")
                client.sendall(struct.pack("!I", len(payload)) + payload)
                with mock.patch.object(browser_entry, "peer_uid", return_value=os.getuid()), mock.patch.object(browser_entry, "verified_browser", return_value=True), mock.patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as run:
                    browser_entry.handle_request(server, b"hash")
                self.assertEqual(client.recv(128), expected)
                self.assertEqual(run.call_count, 0 if expected == b"64" else 1)
            finally:
                client.close()
                server.close()

    def test_probe_checks_the_running_broker_version_without_opening_a_browser(self):
        with mock.patch.object(browser_entry, "broker_request", return_value=b"READY:stale"):
            self.assertFalse(browser_entry.broker_is_ready())

    def test_resigned_browser_is_rejected_even_with_a_valid_bundle_signature(self):
        with tempfile.TemporaryDirectory() as directory:
            app = pathlib.Path(directory) / "Browser.app"
            (app / "Contents").mkdir(parents=True)
            (app / "Contents/Info.plist").write_bytes(plistlib.dumps({"CFBundleIdentifier": "local.claudechrome.launcher"}))
            for digest, expected in (("0" * 40, False), (browser_entry.EXPECTED_BROWSER_CDHASH, True)):
                results = [subprocess.CompletedProcess([], 0), subprocess.CompletedProcess([], 0, stderr=f"CDHash={digest}\n".encode("ascii"))]
                with mock.patch.object(browser_entry, "BROWSER_APP", app), mock.patch.object(subprocess, "run", side_effect=results):
                    self.assertEqual(browser_entry.verified_browser(), expected)



if __name__ == "__main__":
    unittest.main()
