#!/usr/bin/env python3
"""claude-code-guard 的唯讀安全預檢。"""

from __future__ import annotations

import argparse
import datetime as dt
import errno
import hashlib
import ipaddress
import json
import math
import os
import pathlib
import plistlib
import re
import socket
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


EXPECTED_BUNDLE_ID = "com.anthropic.claudefordesktop"
EXPECTED_TEAM_ID = "Q6L2SF6YDW"
EXPECTED_VERSION = "2.9939.4"
PROXY_URL = "http://127.0.0.1:17897"
POLICY_PATH = pathlib.Path(__file__).with_name("EnvironmentPolicy.json")
CACHE_PATH = pathlib.Path.home() / "Library/Application Support/Claude Desktop Guard/reputation.json"
REPUTATION_MAX_AGE = 1800
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


def load_policy() -> dict[str, Any]:
    try:
        value = json.loads(POLICY_PATH.read_text())
        if value.get("schema") == 1 and isinstance(value.get("countries"), dict):
            return value
    except (OSError, ValueError, AttributeError):
        pass
    return {"countries": {}}


def supported_region(country: str, region: Any) -> tuple[str, str]:
    policy = load_policy()
    if not policy["countries"]:
        return "unknown", "支援地區資料無法讀取。"
    if country not in policy["countries"]:
        return "fail", f"{country} 不在目前 Claude.ai 支援地區快照。"
    if country == "UA":
        excluded = policy.get("ukraineExcludedRegions")
        if not isinstance(region, str) or not region.strip() or not isinstance(excluded, list) or not excluded:
            return "unknown", "烏克蘭出口缺少可核實的分區資料。"
        if any(name.casefold() in region.casefold() for name in excluded):
            return "fail", f"出口分區 {region} 不在支援範圍。"
    return "pass", f"{country} 符合 {policy.get('checkedAt', '未知日期')} 的支援地區快照。"


def cloudflare_trace() -> tuple[dict[str, str], dict[str, str] | None]:
    raw = curl_bytes("https://www.cloudflare.com/cdn-cgi/trace")
    if raw is None:
        return check("proxy_exit", "代理出口", "unknown", "經 127.0.0.1:17897 查詢 Cloudflare Trace 失敗。"), None
    try:
        fields = dict(line.split("=", 1) for line in raw.decode("utf-8").splitlines() if "=" in line)
        address = ipaddress.ip_address(fields["ip"])
        country = fields["loc"]
        if not address.is_global or not re.fullmatch(r"[A-Z]{2}", country):
            raise ValueError("public exit")
    except (UnicodeError, KeyError, ValueError):
        return check("proxy_exit", "代理出口", "unknown", "Cloudflare Trace 未提供完整公網 IP／國家。"), None
    context = {"ip": str(address), "country": country}
    return check("proxy_exit", "代理出口", "pass", f"Cloudflare Trace：{country}，{address}。"), context


def ipwho_check(exit_context: dict[str, str] | None) -> tuple[dict[str, str], dict[str, Any] | None]:
    if exit_context is None:
        return check("exit_location", "出口及支援地區", "unknown", "缺少可供獨立比對的出口資料。"), None
    raw = curl_bytes("https://ipwho.is/?fields=ip,success,country_code,region,timezone")
    if raw is None:
        return check("exit_location", "出口及支援地區", "unknown", "經指定代理查詢 ipwho.is 失敗。"), None
    try:
        value = json.loads(raw)
        address = ipaddress.ip_address(value["ip"])
        country = value["country_code"]
        zone_id = value["timezone"]["id"]
        offset = value["timezone"]["offset"]
        if value.get("success") is not True or not address.is_global or not re.fullmatch(r"[A-Z]{2}", country):
            raise ValueError("geography")
        if type(offset) is not int or not isinstance(zone_id, str):
            raise ValueError("timezone")
        zone = ZoneInfo(zone_id)
        expected_offset = int(dt.datetime.now(zone).utcoffset().total_seconds())
    except (json.JSONDecodeError, KeyError, TypeError, ValueError, AttributeError, ZoneInfoNotFoundError):
        return check("exit_location", "出口及支援地區", "unknown", "ipwho.is 回應缺少完整公網 IP、國家、時區或 UTC offset。"), None
    if str(address) != exit_context["ip"] or country != exit_context["country"]:
        return check("exit_location", "出口及支援地區", "fail", "Cloudflare 與 ipwho.is 的即時出口 IP／國家不一致。"), None
    if offset != expected_offset:
        return check("exit_location", "出口及支援地區", "fail", f"出口 UTC offset {offset} 與 {zone_id} 目前應有的 {expected_offset} 不符。"), None
    status, detail = supported_region(country, value.get("region"))
    context = {"ip": str(address), "country": country, "timeZone": zone_id, "utcOffset": offset}
    return check("exit_location", "出口及支援地區", status, f"相同出口 IP；{detail} 時區 {zone_id}。"), context if status == "pass" else None


def validated_reputation(payload: Any, expected_ip: str, context: dict[str, Any] | None = None) -> dict[str, Any] | None:
    try:
        if not isinstance(payload, dict) or payload.get("status") not in ("ok", "warning"):
            return None
        record = payload[expected_ip]
        detections = record["detections"]
        if any(type(detections.get(name)) is not bool for name in RISK_FLAGS):
            return None
        for name in ("risk", "confidence"):
            score = detections[name]
            if isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score) or not 0 <= score <= 100:
                return None
        network = record["network"]
        country = record["location"]["country_code"]
        zone_id = record["location"]["timezone"]
        if not all(isinstance(network.get(name), str) and network[name].strip() for name in ("type", "provider")):
            return None
        if not isinstance(country, str) or not re.fullmatch(r"[A-Z]{2}", country) or not isinstance(zone_id, str):
            return None
        ZoneInfo(zone_id)
        if context and (expected_ip != context["ip"] or country != context["country"] or zone_id != context["timeZone"]):
            return None
        return {"ip": expected_ip, "country": country, "timeZone": zone_id,
                "networkType": network["type"][:64], "provider": network["provider"][:128],
                "detections": {name: detections[name] for name in (*RISK_FLAGS, "risk", "confidence")}}
    except (KeyError, TypeError, ValueError, AttributeError, ZoneInfoNotFoundError):
        return None


def evaluate_proxycheck(payload: Any, expected_ip: str) -> tuple[str, str]:
    snapshot = validated_reputation(payload, expected_ip)
    if snapshot is None:
        return "unknown", "ProxyCheck 資料不完整，無法核實出口信譽。"
    detections = snapshot["detections"]
    positive = [name for name in RISK_FLAGS if detections[name]]
    risk = detections["risk"]
    if positive or risk > 25:
        reason = "、".join(positive) if positive else "分數超出門檻"
        return "fail", f"{reason}；risk {risk:g}/100（上限 25）。"
    return "pass", f"七項偵測均為 false，risk {risk:g}/100。"


def read_reputation_cache(context: dict[str, Any], now: float) -> dict[str, Any] | None:
    try:
        with os.fdopen(os.open(CACHE_PATH, os.O_RDONLY | os.O_NOFOLLOW), "r") as handle:
            metadata = os.fstat(handle.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o600 or not 0 < metadata.st_size <= 65536:
                return None
            value = json.load(handle)
        fetched = value["fetchedAt"]
        if isinstance(fetched, bool) or not isinstance(fetched, (int, float)) or not math.isfinite(fetched) or not 0 <= now - fetched < REPUTATION_MAX_AGE:
            return None
        if value.get("schema") != 1 or value.get("context") != context or validated_reputation(value.get("payload"), context["ip"], context) is None:
            return None
        return value
    except (OSError, ValueError, KeyError, TypeError):
        return None


def write_reputation_cache(value: dict[str, Any]) -> None:
    temporary = None
    try:
        CACHE_PATH.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        parent = CACHE_PATH.parent.lstat()
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid() or parent.st_mode & 0o022:
            return
        if CACHE_PATH.is_symlink():
            return
        with tempfile.NamedTemporaryFile(mode="w", prefix=".reputation-", dir=CACHE_PATH.parent, delete=False) as handle:
            temporary = pathlib.Path(handle.name)
            json.dump(value, handle, ensure_ascii=False, separators=(",", ":"))
        os.replace(temporary, CACHE_PATH)
    except OSError:
        pass
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def reputation_decision(snapshot: dict[str, Any], fetched_at: float, acceptance: str | None) -> tuple[dict[str, str], dict[str, Any]]:
    flags = snapshot["detections"]
    positive = [name for name in RISK_FLAGS if flags[name]]
    risk = flags["risk"]
    eligible = flags["hosting"] and all(flags[name] is False for name in RISK_FLAGS if name != "hosting")
    snapshot_key = hashlib.sha256(json.dumps({**snapshot, "checkedAt": fetched_at}, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    accepted = eligible and acceptance == snapshot_key
    detail = f"{snapshot['ip']} · {snapshot['provider']} · risk {risk:g}/100"
    acknowledgement = {"eligible": eligible, "snapshotKey": snapshot_key if eligible else "", "accepted": accepted, "detail": detail}
    if accepted:
        return check("exit_reputation", "出口風險確認", "pass", f"已確認承擔此機房出口及風險分數；{detail}。其他檢查仍須通過。"), acknowledgement
    if positive or risk > 25:
        reason = "、".join(positive) if positive else "分數超出門檻"
        return check("exit_reputation", "出口信譽", "fail", f"{reason}；{detail}（預設上限 25）。"), acknowledgement
    return check("exit_reputation", "出口信譽", "pass", f"七項偵測均為 false；{detail}。"), acknowledgement


def proxycheck_check(context: dict[str, Any] | None, acceptance: str | None = None) -> tuple[dict[str, str], dict[str, Any]]:
    empty_ack = {"eligible": False, "snapshotKey": "", "accepted": False, "detail": ""}
    if context is None:
        return check("exit_reputation", "出口信譽", "unknown", "缺少一致且受支援的即時出口資料。"), empty_ack
    now = time.time()
    cached = read_reputation_cache(context, now)
    if cached is None:
        raw = curl_bytes(f"https://proxycheck.io/v3/{context['ip']}?ver=24-June-2026")
        try:
            payload = json.loads(raw) if raw else None
        except (json.JSONDecodeError, UnicodeError):
            payload = None
        if validated_reputation(payload, context["ip"], context) is None:
            return check("exit_reputation", "出口信譽", "unknown", "ProxyCheck 資料缺漏或 IP／國家／時區不一致；無法接受風險。"), empty_ack
        cached = {"schema": 1, "context": context, "fetchedAt": now, "payload": payload}
        write_reputation_cache(cached)
    snapshot = validated_reputation(cached["payload"], context["ip"], context)
    return reputation_decision(snapshot, cached["fetchedAt"], acceptance)


def system_time_zone_check(context: dict[str, Any] | None) -> dict[str, str]:
    if context is None:
        return check("system_timezone", "系統時區與出口", "unknown", "缺少已核實的出口時區。")
    try:
        target = pathlib.Path("/etc/localtime").resolve(strict=True)
        zone_id = context["timeZone"]
        zone = ZoneInfo(zone_id)
    except (OSError, KeyError, ValueError, ZoneInfoNotFoundError):
        return check("system_timezone", "系統時區與出口", "unknown", "無法核實系統／出口時區。")
    if target.as_posix().endswith("/" + zone_id):
        return check("system_timezone", "系統時區與出口", "pass", f"系統與出口均為 {zone_id}，UTC offset {int(dt.datetime.now(zone).utcoffset().total_seconds())} 秒。")
    return check("system_timezone", "系統時區與出口", "fail", f"系統為 {target.name}；出口要求 {zone_id}。")


def defaults_value(key: str) -> str | None:
    result = run_command(["/usr/bin/defaults", "read", EXPECTED_BUNDLE_ID, key], timeout=4)
    if result is None or result.returncode != 0:
        return None
    return result.stdout.decode("utf-8", "replace").strip()


def language_check(context: dict[str, Any] | None) -> dict[str, str]:
    country = context.get("country") if context else None
    expected = load_policy()["countries"].get(country, {}).get("languages")
    if not isinstance(expected, list) or len(expected) != 2 or not all(isinstance(item, str) for item in expected):
        return check("app_language", "App 語言與出口", "unknown", "無法按出口國家確定預期語言。")
    languages = defaults_value("AppleLanguages")
    locale = defaults_value("AppleLocale")
    if languages is None or locale is None:
        return check("app_language", "App 語言與出口", "unknown", f"未設定 App 語言；{country} 出口預期 {'、'.join(expected)}。")
    actual = [item.strip(' ,()"\t\r\n') for item in languages.splitlines() if item.strip(' ,()"\t\r\n')]
    locale = locale.strip('"').split("@", 1)[0].replace("_", "-")
    if actual == expected and locale == expected[0]:
        return check("app_language", "App 語言與出口", "pass", f"App 設定為 {'、'.join(actual)}，符合 {country} 出口；這是偏好設定讀回。")
    return check("app_language", "App 語言與出口", "fail", f"App 現為 {'、'.join(actual)}／{locale}；{country} 出口預期 {'、'.join(expected)}／{expected[0]}。")


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


def launch_environment(time_zone: str) -> dict[str, str]:
    environment = os.environ.copy()
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        environment[name] = PROXY_URL
    environment["NO_PROXY"] = ""
    environment["no_proxy"] = ""
    environment["TZ"] = time_zone
    return environment


def launch_command(binary: pathlib.Path) -> list[str]:
    return [
        "/usr/bin/sandbox-exec", "-f", str(SANDBOX_PROFILE), str(binary),
        f"--proxy-server={PROXY_URL}",
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        "--disable-quic",
    ]


def perform_check(acceptance: str | None = None) -> tuple[dict[str, Any], bool]:
    checks: list[dict[str, str]] = []
    staged_check, staged_verified = verify_app_identity(STAGED_APP, "staged_app", "暫存安裝包", "info")
    installed_check, installed_verified = verify_app_identity(INSTALLED_APP, "installed_app", "已安裝官方 App", "info")
    checks.extend((staged_check, installed_check))

    trace_check, trace_context = cloudflare_trace()
    location_check, exit_context = ipwho_check(trace_context)
    reputation_check, acknowledgement = proxycheck_check(exit_context, acceptance)
    checks.extend((trace_check, location_check, reputation_check))
    checks.extend((system_time_zone_check(exit_context), language_check(exit_context), sandbox_check(), evaluate_firewall()))
    checks.append(check("browser_baseline", "WebRTC 與瀏覽器指紋", "info", "尚未在官方桌面 App 內量測。Chrome 的 Canvas、WebGL、navigator 及 STUN 結果不能代表此 App；目前沙箱探測亦只涵蓋探測程序。"))

    inventory_app = INSTALLED_APP if installed_verified else STAGED_APP if staged_verified else None
    permissions, tcc_check = permission_inventory(inventory_app)
    checks.append(tcc_check)
    can_launch = compute_can_launch(checks, installed_verified)
    result = {
        "checkedAt": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "canLaunch": can_launch,
        "checks": checks,
        "permissions": permissions,
        "hostingAcknowledgement": acknowledgement,
        "exitContext": exit_context,
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
        time_zone = result["exitContext"]["timeZone"]
        ZoneInfo(time_zone)
    except (KeyError, TypeError, ValueError, ZoneInfoNotFoundError):
        result["canLaunch"] = False
        result["checks"].append(check("launch_timezone", "啟動時區", "unknown", "缺少已核實的出口時區。"))
        print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
        return 2
    try:
        subprocess.Popen(
            launch_command(binary),
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True, env=launch_environment(time_zone),
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
    parser.add_argument("--accept-hosting-snapshot")
    arguments = parser.parse_args()
    if arguments.probe:
        print(json.dumps(socket_probe(arguments.probe), separators=(",", ":")))
        return 0
    result, installed_verified = perform_check(arguments.accept_hosting_snapshot)
    if arguments.check:
        print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
        return 0
    return launch(result, installed_verified)


if __name__ == "__main__":
    raise SystemExit(main())
