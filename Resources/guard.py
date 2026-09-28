#!/usr/bin/env python3
"""claude-code-guard 的唯讀安全預檢。"""

from __future__ import annotations

import argparse
import datetime as dt
import errno
import ipaddress
import json
import math
import os
import pathlib
import plistlib
import re
import socket
import subprocess
import sys
from typing import Any


EXPECTED_BUNDLE_ID = "com.anthropic.claudefordesktop"
EXPECTED_TEAM_ID = "Q6L2SF6YDW"
EXPECTED_VERSION = "2.9939.4"
EXPECTED_COUNTRY = "JP"
EXPECTED_TIME_ZONE = "Asia/Tokyo"
PROXY_URL = "http://127.0.0.1:17897"
STAGED_APP = pathlib.Path.home() / "Library/Application Support/Claude Desktop Guard/Staging/Claude.app"
INSTALLED_APP = pathlib.Path("/Applications/Claude.app")
SANDBOX_PROFILE = pathlib.Path.home() / ".local/share/claude-network-guard/claude-proxy-only.sb"
RISK_FLAGS = ("hosting", "proxy", "vpn", "tor", "compromised", "scraper", "anonymous")
REQUIRED_LAUNCH_CHECK_IDS = frozenset({
    "installed_app",
    "proxy_exit",
    "exit_location",
    "exit_reputation",
    "system_timezone",
    "app_language",
    "network_sandbox",
    "os_firewall",
    "tcc_authorization",
})
VALID_CHECK_STATUSES = frozenset({"pass", "fail", "unknown", "info"})
USAGE_LABELS = {
    "NSAppleEventsUsageDescription": "控制其他 App",
    "NSAudioCaptureUsageDescription": "擷取音訊",
    "NSBluetoothAlwaysUsageDescription": "藍牙",
    "NSBluetoothPeripheralUsageDescription": "藍牙周邊",
    "NSCameraUsageDescription": "相機",
    "NSDesktopFolderUsageDescription": "桌面資料夾",
    "NSDocumentsFolderUsageDescription": "文件資料夾",
    "NSDownloadsFolderUsageDescription": "下載資料夾",
    "NSLocalNetworkUsageDescription": "本機網絡",
    "NSMicrophoneUsageDescription": "咪高峰",
    "NSSpeechRecognitionUsageDescription": "語音辨識",
}
ENTITLEMENT_LABELS = {
    "com.apple.security.automation.apple-events": "Apple Events 自動化",
    "com.apple.security.device.audio-input": "音訊輸入",
    "com.apple.security.device.bluetooth": "藍牙裝置",
    "com.apple.security.device.camera": "相機裝置",
    "com.apple.security.device.print": "列印",
    "com.apple.security.device.usb": "USB 裝置",
    "com.apple.security.personal-information.location": "位置",
    "com.apple.security.personal-information.photos-library": "相片圖庫",
    "com.apple.security.virtualization": "虛擬化",
}


def check(check_id: str, title: str, status: str, detail: str) -> dict[str, str]:
    return {"id": check_id, "title": title, "status": status, "detail": detail}


def run_command(arguments: list[str], timeout: float = 10) -> subprocess.CompletedProcess[bytes] | None:
    try:
        return subprocess.run(arguments, capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None


def read_info_plist(app: pathlib.Path) -> dict[str, Any] | None:
    try:
        with (app / "Contents/Info.plist").open("rb") as handle:
            value = plistlib.load(handle)
        return value if isinstance(value, dict) else None
    except (OSError, plistlib.InvalidFileException):
        return None


def verify_app_identity(app: pathlib.Path, check_id: str, title: str, missing_status: str) -> tuple[dict[str, str], bool]:
    if not app.exists():
        return check(check_id, title, missing_status, f"未找到 {app}。"), False
    if not app.is_dir() or app.is_symlink():
        return check(check_id, title, "fail", "App 路徑不是正常目錄。"), False

    info = read_info_plist(app)
    if info is None:
        return check(check_id, title, "unknown", "無法讀取 Info.plist。"), False
    identity = (
        info.get("CFBundleIdentifier"),
        info.get("CFBundleShortVersionString"),
    )
    if identity != (EXPECTED_BUNDLE_ID, EXPECTED_VERSION):
        return check(check_id, title, "fail", "Bundle ID 或版本與已核實目標不符。"), False

    verify = run_command(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(app)], timeout=20)
    display = run_command(["/usr/bin/codesign", "-d", "--verbose=4", str(app)], timeout=10)
    assess = run_command(["/usr/sbin/spctl", "--assess", "--type", "execute", str(app)], timeout=20)
    if verify is None or display is None or assess is None:
        return check(check_id, title, "unknown", "簽署或 Gatekeeper 檢查未能完成。"), False
    if verify.returncode != 0 or assess.returncode != 0:
        return check(check_id, title, "fail", "codesign 或 Gatekeeper 未接受此 App。"), False

    metadata = (display.stdout + display.stderr).decode("utf-8", "replace")
    identifier = re.search(r"^Identifier=(.+)$", metadata, re.MULTILINE)
    team = re.search(r"^TeamIdentifier=(.+)$", metadata, re.MULTILINE)
    if not identifier or not team:
        return check(check_id, title, "unknown", "簽署資料缺少 Identifier 或 TeamIdentifier。"), False
    if identifier.group(1).strip() != EXPECTED_BUNDLE_ID or team.group(1).strip() != EXPECTED_TEAM_ID:
        return check(check_id, title, "fail", "簽署身分與 Anthropic Team 或 Bundle 不符。"), False
    return check(
        check_id,
        title,
        "pass",
        f"已核實版本 {EXPECTED_VERSION}、Team {EXPECTED_TEAM_ID}、codesign 及 Gatekeeper。",
    ), True


def curl_bytes(url: str) -> bytes | None:
    environment = os.environ.copy()
    for name in ("http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "no_proxy"):
        environment.pop(name, None)
    arguments = [
        "/usr/bin/curl", "-q", "--proxy", PROXY_URL, "--noproxy", "", "--proto", "=https",
        "--connect-timeout", "4", "--max-time", "8", "--max-filesize", "65536",
        "--fail", "--silent", "--show-error", url,
    ]
    try:
        result = subprocess.run(arguments, capture_output=True, timeout=10, check=False, env=environment)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0 or not result.stdout or len(result.stdout) > 65_536:
        return None
    return result.stdout


def cloudflare_trace() -> tuple[dict[str, str], str | None]:
    raw = curl_bytes("https://www.cloudflare.com/cdn-cgi/trace")
    if raw is None:
        return check("proxy_exit", "代理出口", "unknown", "經 127.0.0.1:17897 查詢 Cloudflare Trace 失敗。"), None
    try:
        fields = dict(line.split("=", 1) for line in raw.decode("utf-8").splitlines() if "=" in line)
        address = str(ipaddress.ip_address(fields["ip"]))
        country = fields["loc"]
    except (UnicodeError, KeyError, ValueError):
        return check("proxy_exit", "代理出口", "unknown", "Cloudflare Trace 回應格式不完整。"), None
    if country != EXPECTED_COUNTRY:
        return check("proxy_exit", "代理出口", "fail", f"出口國家為 {country}；保守出口門檻目前只接受日本。"), address
    return check("proxy_exit", "代理出口", "pass", f"Cloudflare Trace 顯示日本出口 {address}。"), address


def ipwho_check(expected_ip: str | None) -> tuple[dict[str, str], dict[str, Any] | None]:
    if expected_ip is None:
        return check("exit_location", "出口位置", "unknown", "缺少可供獨立比對的出口 IP。"), None
    raw = curl_bytes(f"https://ipwho.is/{expected_ip}?fields=ip,success,country_code,timezone")
    if raw is None:
        return check("exit_location", "出口位置", "unknown", "經指定代理查詢 ipwho.is 失敗。"), None
    try:
        value = json.loads(raw)
        zone = value["timezone"]
        valid = (
            isinstance(value, dict) and value.get("success") is True
            and str(ipaddress.ip_address(value["ip"])) == expected_ip
            and isinstance(zone, dict) and isinstance(zone.get("id"), str)
            and isinstance(value.get("country_code"), str)
        )
    except (json.JSONDecodeError, KeyError, TypeError, ValueError):
        valid = False
        value = None
    if not valid:
        return check("exit_location", "出口位置", "unknown", "ipwho.is 回應無法完整驗證或 IP 不匹配。"), None
    country = value["country_code"]
    zone_id = value["timezone"]["id"]
    if country != EXPECTED_COUNTRY or zone_id != EXPECTED_TIME_ZONE:
        return check(
            "exit_location", "出口位置", "fail",
            f"ipwho.is 顯示 {country}／{zone_id}，未達日本 {EXPECTED_TIME_ZONE} 保守出口門檻。",
        ), value
    return check("exit_location", "出口位置", "pass", "ipwho.is 獨立確認相同 IP、日本及 Asia/Tokyo。"), value


def evaluate_proxycheck(payload: Any, expected_ip: str) -> tuple[str, str]:
    if not isinstance(payload, dict) or payload.get("status") not in ("ok", "warning"):
        return "unknown", "ProxyCheck 回應狀態無法驗證。"
    if expected_ip not in payload or not isinstance(payload[expected_ip], dict):
        return "unknown", "ProxyCheck 回應未包含完全匹配的出口 IP。"
    detections = payload[expected_ip].get("detections")
    if not isinstance(detections, dict):
        return "unknown", "ProxyCheck 回應缺少 detections。"
    for name in RISK_FLAGS:
        if type(detections.get(name)) is not bool:
            return "unknown", f"ProxyCheck 欄位 {name} 缺漏或不是布林值。"
    risk = detections.get("risk")
    if isinstance(risk, bool) or not isinstance(risk, (int, float)) or not math.isfinite(risk) or not 0 <= risk <= 100:
        return "unknown", "ProxyCheck risk 缺漏或超出 0 至 100。"
    positive = [name for name in RISK_FLAGS if detections[name]]
    if positive or risk > 25:
        reason = "、".join(positive) if positive else "未命中布林風險項"
        return "fail", f"保守出口門檻未通過：{reason}；risk {risk:g}/100（上限 25）。"
    return "pass", f"保守出口門檻通過：七項偵測均為 false，risk {risk:g}/100。"


def proxycheck_check(expected_ip: str | None) -> dict[str, str]:
    if expected_ip is None:
        return check("exit_reputation", "出口信譽", "unknown", "缺少已獨立核實的出口 IP。")
    raw = curl_bytes(f"https://proxycheck.io/v3/{expected_ip}?ver=24-June-2026")
    if raw is None:
        return check("exit_reputation", "出口信譽", "unknown", "經指定代理查詢 ProxyCheck v3 失敗。")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return check("exit_reputation", "出口信譽", "unknown", "ProxyCheck 回應不是有效 JSON。")
    status, detail = evaluate_proxycheck(payload, expected_ip)
    return check("exit_reputation", "出口信譽", status, detail)


def system_time_zone_check() -> dict[str, str]:
    try:
        target = pathlib.Path("/etc/localtime").resolve(strict=True)
    except OSError:
        return check("system_timezone", "系統時區", "unknown", "無法讀取 /etc/localtime。")
    if target.as_posix().endswith("/Asia/Tokyo"):
        return check("system_timezone", "系統時區", "pass", "系統時區為 Asia/Tokyo。")
    return check("system_timezone", "系統時區", "fail", f"系統時區不是 Asia/Tokyo（目前 {target.name}）。")


def defaults_value(key: str) -> str | None:
    result = run_command(["/usr/bin/defaults", "read", EXPECTED_BUNDLE_ID, key], timeout=4)
    if result is None or result.returncode != 0:
        return None
    return result.stdout.decode("utf-8", "replace").strip()


def language_check() -> dict[str, str]:
    languages = defaults_value("AppleLanguages")
    locale = defaults_value("AppleLocale")
    if languages is None or locale is None:
        return check("app_language", "App 語言與地區", "unknown", "App 的 AppleLanguages 或 AppleLocale 尚未設定。")
    quoted = re.findall(r'"([^"\\]+)"', languages)
    if quoted:
        first_language = quoted[0]
    else:
        candidates = [item.strip(" ,()\t\r\n") for item in languages.splitlines() if item.strip(" ,()\t\r\n")]
        first_language = candidates[0] if candidates else ""
    locale = locale.strip('"').split("@", 1)[0]
    if (first_language == "en" or first_language.startswith("en-")) and locale == "en_US":
        return check("app_language", "App 語言與地區", "pass", f"首選語言 {first_language}，地區 en_US。")
    return check("app_language", "App 語言與地區", "fail", "App 首選語言須為英文，AppleLocale 須為 en_US。")


def socket_probe(kind: str) -> dict[str, Any]:
    configurations = {
        "ipv4": (socket.AF_INET, socket.SOCK_STREAM, ("1.1.1.1", 443)),
        "ipv6": (socket.AF_INET6, socket.SOCK_STREAM, ("2606:4700:4700::1111", 443, 0, 0)),
        "udp": (socket.AF_INET, socket.SOCK_DGRAM, ("1.1.1.1", 443)),
        "proxy": (socket.AF_INET, socket.SOCK_STREAM, ("127.0.0.1", 17897)),
    }
    family, socket_type, address = configurations[kind]
    sock = socket.socket(family, socket_type)
    sock.settimeout(2)
    try:
        sock.connect(address)
        return {"kind": kind, "outcome": "connected"}
    except OSError as error:
        return {"kind": kind, "outcome": "denied" if error.errno == errno.EPERM else "error", "errno": error.errno}
    finally:
        sock.close()


def evaluate_probe_results(results: dict[str, Any]) -> tuple[str, str]:
    for name in ("ipv4", "ipv6", "udp"):
        result = results.get(name)
        if not isinstance(result, dict):
            return "unknown", f"缺少 {name} 沙箱探測結果。"
        if result.get("outcome") == "connected":
            return "fail", f"沙箱容許 {name} 直接連線。"
        if result.get("outcome") != "denied" or result.get("errno") != errno.EPERM:
            return "unknown", f"{name} 未獲可核實的 EPERM 拒絕結果。"
    proxy = results.get("proxy")
    if not isinstance(proxy, dict) or proxy.get("outcome") != "connected":
        return "unknown", "沙箱內未能連接指定本機代理 127.0.0.1:17897。"
    return "pass", "沙箱實測拒絕 IPv4、IPv6、UDP 直連（EPERM），並可連接指定本機代理。"


def sandbox_check() -> dict[str, str]:
    if not SANDBOX_PROFILE.is_file() or SANDBOX_PROFILE.is_symlink():
        return check("network_sandbox", "網絡沙箱", "unknown", "找不到可信的代理專用 sandbox profile。")
    results: dict[str, Any] = {}
    for kind in ("ipv4", "ipv6", "udp", "proxy"):
        command = ["/usr/bin/sandbox-exec", "-f", str(SANDBOX_PROFILE), sys.executable, str(pathlib.Path(__file__).resolve()), "--probe", kind]
        process = run_command(command, timeout=5)
        if process is None or process.returncode != 0:
            results[kind] = None
            continue
        try:
            results[kind] = json.loads(process.stdout)
        except json.JSONDecodeError:
            results[kind] = None
    status, detail = evaluate_probe_results(results)
    return check("network_sandbox", "網絡沙箱", status, detail)


def evaluate_firewall() -> dict[str, str]:
    """自建系統層防護尚未實作，不能靠外部輸入解鎖。"""
    return check(
        "os_firewall", "系統防火牆規則", "unknown",
        "尚未取得自建系統層防護及官方 Claude 規則的可信讀回證據；代理 wrapper 不能阻止其他啟動方式。",
    )


def permission_inventory(app: pathlib.Path | None) -> tuple[list[dict[str, str]], dict[str, str]]:
    if app is None:
        return [], check("tcc_authorization", "macOS 權限狀態", "unknown", "未有可核實的官方 App 供讀取權限申報。")
    info = read_info_plist(app)
    if info is None:
        return [], check("tcc_authorization", "macOS 權限狀態", "unknown", "無法讀取官方 App 的權限申報。")
    permissions: list[dict[str, str]] = []
    for key, label in USAGE_LABELS.items():
        declaration = info.get(key)
        if isinstance(declaration, str) and declaration.strip():
            permissions.append({"name": label, "detail": f"Info.plist：{declaration.strip()}（安裝包申報，不代表已授權）"})

    entitlements = run_command(["/usr/bin/codesign", "-d", "--entitlements", ":-", str(app)], timeout=10)
    if entitlements is not None and entitlements.returncode == 0:
        try:
            plist_start = entitlements.stdout.find(b"<?xml")
            values = plistlib.loads(entitlements.stdout[plist_start:]) if plist_start >= 0 else {}
        except plistlib.InvalidFileException:
            values = {}
        for key, label in ENTITLEMENT_LABELS.items():
            if values.get(key) is True and not any(item["name"] == label for item in permissions):
                permissions.append({"name": label, "detail": "codesign entitlement 已申報（安裝包申報，不代表已授權）"})
    return permissions, check(
        "tcc_authorization", "macOS 權限狀態", "unknown",
        "TCC 授權尚無可核實讀回；不讀取或繞過受保護的 TCC 資料庫。安裝包申報不代表已授權。",
    )


def compute_can_launch(checks: Any, installed_verified: bool) -> bool:
    if not installed_verified or not isinstance(checks, list) or not checks:
        return False
    seen: set[str] = set()
    statuses: dict[str, str] = {}
    for item in checks:
        if not isinstance(item, dict) or set(item) != {"id", "title", "status", "detail"}:
            return False
        if not all(isinstance(item[name], str) and item[name] for name in ("id", "title", "status", "detail")):
            return False
        if item["status"] not in VALID_CHECK_STATUSES or item["id"] in seen:
            return False
        seen.add(item["id"])
        statuses[item["id"]] = item["status"]
    if not REQUIRED_LAUNCH_CHECK_IDS.issubset(seen):
        return False
    if any(status not in ("pass", "info") for status in statuses.values()):
        return False
    return all(statuses[check_id] == "pass" for check_id in REQUIRED_LAUNCH_CHECK_IDS)


def launch_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        environment[name] = PROXY_URL
    environment["NO_PROXY"] = ""
    environment["no_proxy"] = ""
    environment["TZ"] = EXPECTED_TIME_ZONE
    return environment


def launch_command(binary: pathlib.Path) -> list[str]:
    return [
        "/usr/bin/sandbox-exec", "-f", str(SANDBOX_PROFILE), str(binary),
        f"--proxy-server={PROXY_URL}",
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        "--disable-quic",
    ]


def perform_check() -> tuple[dict[str, Any], bool]:
    checks: list[dict[str, str]] = []
    staged_check, staged_verified = verify_app_identity(STAGED_APP, "staged_app", "暫存安裝包", "info")
    installed_check, installed_verified = verify_app_identity(INSTALLED_APP, "installed_app", "已安裝官方 App", "info")
    checks.extend((staged_check, installed_check))

    trace_check, exit_ip = cloudflare_trace()
    location_check, _ = ipwho_check(exit_ip)
    checks.extend((trace_check, location_check, proxycheck_check(exit_ip)))
    checks.extend((system_time_zone_check(), language_check(), sandbox_check(), evaluate_firewall()))

    inventory_app = INSTALLED_APP if installed_verified else STAGED_APP if staged_verified else None
    permissions, tcc_check = permission_inventory(inventory_app)
    checks.append(tcc_check)
    can_launch = compute_can_launch(checks, installed_verified)
    result = {
        "checkedAt": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "canLaunch": can_launch,
        "checks": checks,
        "permissions": permissions,
    }
    return result, installed_verified


def launch(result: dict[str, Any], installed_verified: bool) -> int:
    authorized = compute_can_launch(result.get("checks"), installed_verified)
    result["canLaunch"] = authorized
    if not authorized:
        print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
        return 2
    info = read_info_plist(INSTALLED_APP)
    executable = info.get("CFBundleExecutable") if info else None
    if not isinstance(executable, str) or not executable or "/" in executable:
        result["canLaunch"] = False
        result["checks"].append(check("launch_target", "啟動目標", "unknown", "無法核實官方 App 的執行檔。"))
        print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
        return 2
    binary = INSTALLED_APP / "Contents/MacOS" / executable
    try:
        subprocess.Popen(
            launch_command(binary),
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True, env=launch_environment(),
        )
    except OSError:
        result["canLaunch"] = False
        result["checks"].append(check("launch_target", "啟動目標", "unknown", "sandbox-exec 未能啟動官方 App。"))
        print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
        return 2
    print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(add_help=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check", action="store_true")
    group.add_argument("--launch", action="store_true")
    group.add_argument("--probe", choices=("ipv4", "ipv6", "udp", "proxy"))
    arguments = parser.parse_args()
    if arguments.probe:
        print(json.dumps(socket_probe(arguments.probe), separators=(",", ":")))
        return 0
    result, installed_verified = perform_check()
    if arguments.check:
        print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
        return 0
    return launch(result, installed_verified)


if __name__ == "__main__":
    raise SystemExit(main())
