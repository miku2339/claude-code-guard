#!/usr/bin/python3 -I
"""將原生 CLI 的官方登入連結交予 Claude Chrome。"""

from __future__ import annotations

import ctypes
import fcntl
import hashlib
import os
import pathlib
import plistlib
import socket
import stat
import struct
import subprocess
import sys
from urllib.parse import urlsplit


BROWSER_APP = pathlib.Path("/Applications/Claude Chrome.app")
EXPECTED_BROWSER_CDHASH = "dc78d796250716ae84c6c8fc4a64148d3997ef2e"
BROKER_SOCKET = pathlib.Path.home() / ".local/share/claude-network-guard/claude-code-browser.sock"
MAX_URL_BYTES = 16_384
LOGIN_ENDPOINTS = frozenset({
    ("claude.com", "/cai/oauth/authorize"),
    ("platform.claude.com", "/oauth/authorize"),
})


def valid_login_url(value: str) -> bool:
    if not 0 < len(value) <= 16_384 or any(ord(character) <= 32 or ord(character) == 127 for character in value):
        return False
    try:
        parsed = urlsplit(value)
        return (
            parsed.scheme == "https"
            and parsed.username is None
            and parsed.password is None
            and parsed.port is None
            and parsed.netloc.lower() == parsed.hostname
            and (parsed.hostname, parsed.path) in LOGIN_ENDPOINTS
            and bool(parsed.query)
            and not parsed.fragment
        )
    except ValueError:
        return False


def verified_browser() -> bool:
    try:
        if BROWSER_APP.is_symlink() or not BROWSER_APP.is_dir():
            return False
        with (BROWSER_APP / "Contents/Info.plist").open("rb") as source:
            info = plistlib.load(source)
        if info.get("CFBundleIdentifier") != "local.claudechrome.launcher":
            return False
        result = subprocess.run(
            ["/usr/bin/codesign", "--verify", "--deep", "--strict", str(BROWSER_APP)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=20, check=False,
        )
        if result.returncode != 0:
            return False
        identity = subprocess.run(
            ["/usr/bin/codesign", "-dvvv", str(BROWSER_APP)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            timeout=20, check=False,
        )
        hashes = [line.removeprefix(b"CDHash=") for line in identity.stderr.splitlines() if line.startswith(b"CDHash=")]
        return identity.returncode == 0 and hashes == [EXPECTED_BROWSER_CDHASH.encode("ascii")]
    except (OSError, ValueError, plistlib.InvalidFileException, subprocess.TimeoutExpired):
        return False


def open_login_url(value: str) -> int:
    if not valid_login_url(value):
        return 64
    if not verified_browser():
        return 69
    try:
        result = subprocess.run(
            ["/usr/bin/open", "-n", "-a", str(BROWSER_APP), "--args", "--login-url", value],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=20, check=False,
        )
        if result.returncode == 0:
            return 0
    except (OSError, subprocess.TimeoutExpired):
        pass
    return 69


def private_path(path: pathlib.Path, kind: str, mode: int) -> bool:
    try:
        metadata = path.lstat()
        type_check = stat.S_ISDIR if kind == "directory" else stat.S_ISSOCK
        return type_check(metadata.st_mode) and metadata.st_uid == os.getuid() and stat.S_IMODE(metadata.st_mode) == mode
    except OSError:
        return False


def read_exact(connection: socket.socket, length: int) -> bytes:
    value = bytearray()
    while len(value) < length:
        chunk = connection.recv(length - len(value))
        if not chunk:
            raise ValueError("incomplete frame")
        value.extend(chunk)
    return bytes(value)


def peer_uid(connection: socket.socket) -> int | None:
    try:
        library = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
        uid, gid = ctypes.c_uint(), ctypes.c_uint()
        if library.getpeereid(connection.fileno(), ctypes.byref(uid), ctypes.byref(gid)) == 0:
            return uid.value
    except (OSError, AttributeError):
        pass
    return None


def broker_request(payload: bytes, timeout: float = 45) -> bytes | None:
    if not private_path(BROKER_SOCKET.parent, "directory", 0o700) or not private_path(BROKER_SOCKET, "socket", 0o600):
        return None
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(timeout)
            connection.connect(str(BROKER_SOCKET))
            if peer_uid(connection) != os.getuid():
                return None
            connection.sendall(struct.pack("!I", len(payload)) + payload)
            return read_exact(connection, 70) if not payload else connection.recv(2)
    except (OSError, ValueError):
        return None


def broker_is_ready() -> bool:
    try:
        digest = hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest().encode("ascii")
        return broker_request(b"", timeout=2) == b"READY:" + digest
    except OSError:
        return False


def handle_request(connection: socket.socket, digest: bytes) -> None:
    if peer_uid(connection) != os.getuid():
        connection.sendall(b"69")
        return
    length = struct.unpack("!I", read_exact(connection, 4))[0]
    if length == 0:
        connection.sendall(b"READY:" + digest)
    elif length > MAX_URL_BYTES:
        connection.sendall(b"64")
    else:
        value = read_exact(connection, length).decode("utf-8")
        connection.sendall(str(open_login_url(value)).encode("ascii"))


def serve_broker() -> int:
    if not private_path(BROKER_SOCKET.parent, "directory", 0o700):
        return 69
    os.umask(0o077)
    descriptor = os.open(str(BROKER_SOCKET) + ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o600:
            return 69
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if BROKER_SOCKET.exists() or BROKER_SOCKET.is_symlink():
            if not private_path(BROKER_SOCKET, "socket", 0o600):
                return 69
            BROKER_SOCKET.unlink()
        digest = hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest().encode("ascii")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(BROKER_SOCKET))
            BROKER_SOCKET.chmod(0o600)
            if not private_path(BROKER_SOCKET, "socket", 0o600):
                return 69
            listener.listen(4)
            while True:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(5)
                    try:
                        handle_request(connection, digest)
                    except (OSError, ValueError, UnicodeError):
                        pass
    except (OSError, ValueError):
        return 69
    finally:
        os.close(descriptor)


def main(arguments: list[str] | None = None) -> int:
    values = sys.argv[1:] if arguments is None else arguments
    if values == ["--broker"]:
        return serve_broker()
    if len(values) != 1 or not valid_login_url(values[0]):
        print("登入瀏覽器：只接受官方 Claude Code 登入連結。", file=sys.stderr)
        return 64
    response = broker_request(values[0].encode("utf-8"))
    if response == b"0":
        return 0
    print("登入瀏覽器：本機登入通道或 Claude Chrome 無法確認。", file=sys.stderr)
    return 69


if __name__ == "__main__":
    raise SystemExit(main())
