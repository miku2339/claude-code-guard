#!/usr/bin/env python3
"""官方 Claude Code CLI 的唯讀啟動前檢查。"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import stat
import sys
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

RESOURCE_DIRECTORY = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(RESOURCE_DIRECTORY))
import guard
import browser_entry


EXPECTED_IDENTIFIER = "com.anthropic.claude-code"
EXPECTED_TEAM_ID = "Q6L2SF6YDW"
PROTECTION_PATH = pathlib.Path(__file__).with_name("CLIProtection.json")
CLI_LAUNCHER = pathlib.Path.home() / "bin/claude"
CLI_SYMLINK = pathlib.Path.home() / ".local/bin/claude"
CLI_VERSIONS_ROOT = pathlib.Path.home() / ".local/share/claude/versions"
PROCESS_WRAPPER = pathlib.Path.home() / ".local/share/claude-network-guard/claude-process-wrapper.zsh"
SANDBOX_PROFILE = pathlib.Path.home() / ".local/share/claude-network-guard/claude-proxy-only.sb"
BROWSER_ENTRY = pathlib.Path.home() / ".local/share/claude-network-guard/claude-code-browser.py"
BROWSER_AGENT = pathlib.Path.home() / "Library/LaunchAgents/local.claude-code-guard.browser-broker.plist"
PROTECTED_PATHS = {
    "launcher": CLI_LAUNCHER,
    "processWrapper": PROCESS_WRAPPER,
    "sandboxProfile": SANDBOX_PROFILE,
    "loginBrowser": BROWSER_ENTRY,
    "loginBrowserAgent": BROWSER_AGENT,
}
EXECUTABLE_TEMPLATES = frozenset({"launcher", "processWrapper", "loginBrowser"})
REQUIRED_LAUNCH_CHECK_IDS = frozenset({
    "installed_cli",
    "process_guard",
    "proxy_exit",
    "exit_location",
    "exit_reputation",
    "cli_timezone",
    "cli_language",
    "network_sandbox",
})


def load_protection_metadata() -> dict[str, str] | None:
    try:
        value = json.loads(PROTECTION_PATH.read_text(encoding="utf-8"))
        templates = value["templates"]
        if value.get("schema") != 1 or set(templates) != set(PROTECTED_PATHS):
            return None
        hashes: dict[str, str] = {}
        for name, expected_path in PROTECTED_PATHS.items():
            item = templates[name]
            if item.get("path") != "~" + expected_path.as_posix().removeprefix(pathlib.Path.home().as_posix()):
                return None
            digest = item.get("sha256")
            if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                return None
            hashes[name] = digest
        return hashes
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return None


def secure_file_digest(path: pathlib.Path, executable: bool) -> str | None:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return None
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_mode & 0o022
            or not 0 < metadata.st_size <= 65_536
            or executable and not metadata.st_mode & stat.S_IXUSR
        ):
            return None
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 65_536):
            digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None
    finally:
        os.close(descriptor)


def verify_process_guard() -> dict[str, str]:
    expected = load_protection_metadata()
    if expected is None:
        return guard.check("process_guard", "CLI 程序保護", "unknown", "無法讀取可信的保護模板資料。")
    for name, path in PROTECTED_PATHS.items():
        digest = secure_file_digest(path, name in EXECUTABLE_TEMPLATES)
        if digest is None:
            return guard.check("process_guard", "CLI 程序保護", "fail", f"{name} 不是由目前使用者持有的安全一般檔案。")
        if digest != expected[name]:
            return guard.check("process_guard", "CLI 程序保護", "fail", f"{name} 與已核實模板不一致。")
    if not browser_entry.broker_is_ready():
        return guard.check("process_guard", "CLI 程序保護", "fail", "本機登入通道未啟動或版本不一致。")
    return guard.check("process_guard", "CLI 程序保護", "pass", "啟動器、程序 wrapper、sandbox profile 及 Claude Chrome 登入入口均符合已核實模板及檔案權限。")


def signing_identity(binary: pathlib.Path) -> tuple[str, str] | None:
    verify = guard.run_command(["/usr/bin/codesign", "--verify", "--strict", str(binary)], timeout=20)
    display = guard.run_command(["/usr/bin/codesign", "-d", "--verbose=4", str(binary)], timeout=10)
    if verify is None or display is None or verify.returncode != 0 or display.returncode != 0:
        return None
    output = (display.stdout + display.stderr).decode("utf-8", "replace")
    identifier = re.search(r"^Identifier=(.+)$", output, re.MULTILINE)
    team = re.search(r"^TeamIdentifier=(.+)$", output, re.MULTILINE)
    if identifier is None or team is None:
        return None
    return identifier.group(1).strip(), team.group(1).strip()


def verify_installed_cli() -> tuple[dict[str, str], bool, pathlib.Path | None]:
    try:
        link_metadata = CLI_SYMLINK.lstat()
        versions_metadata = CLI_VERSIONS_ROOT.lstat()
        if (
            not stat.S_ISDIR(versions_metadata.st_mode)
            or versions_metadata.st_uid != os.getuid()
            or versions_metadata.st_mode & 0o022
        ):
            raise ValueError("unsafe versions directory")
        versions_root = CLI_VERSIONS_ROOT.resolve(strict=True)
        binary = CLI_SYMLINK.resolve(strict=True)
        binary.relative_to(versions_root)
        descriptor = os.open(binary, os.O_RDONLY | os.O_NOFOLLOW)
    except (OSError, ValueError):
        return guard.check("installed_cli", "已安裝官方 CLI", "fail", "CLI symlink 未安全指向官方版本目錄。"), False, None
    try:
        binary_metadata = os.fstat(descriptor)
        valid_file = (
            stat.S_ISLNK(link_metadata.st_mode)
            and link_metadata.st_uid == os.getuid()
            and not link_metadata.st_mode & 0o022
            and stat.S_ISREG(binary_metadata.st_mode)
            and binary_metadata.st_uid == os.getuid()
            and not binary_metadata.st_mode & 0o022
            and bool(binary_metadata.st_mode & stat.S_IXUSR)
        )
    finally:
        os.close(descriptor)
    if not valid_file:
        return guard.check("installed_cli", "已安裝官方 CLI", "fail", "CLI 目標不是安全且可執行的一般檔案。"), False, None
    identity = signing_identity(binary)
    if identity is None:
        return guard.check("installed_cli", "已安裝官方 CLI", "unknown", "無法完成 CLI 嚴格簽章核實。"), False, None
    if identity != (EXPECTED_IDENTIFIER, EXPECTED_TEAM_ID):
        return guard.check("installed_cli", "已安裝官方 CLI", "fail", "CLI 簽章 Identifier 或 Team 與 Anthropic 不符。"), False, None
    return guard.check("installed_cli", "已安裝官方 CLI", "pass", f"已核實官方 CLI {binary.name} 的嚴格簽章與 Team。"), True, binary


def locale_from_language(language: str) -> str | None:
    if not re.fullmatch(r"[A-Za-z]{2,3}(?:-[A-Za-z]{4})?(?:-[A-Za-z]{2}|-[0-9]{3})?", language):
        return None
    parts = language.split("-")
    locale_parts = [parts[0].lower()]
    region = next((part for part in parts[1:] if len(part) == 2 or part.isdigit()), None)
    if region is not None:
        locale_parts.append(region.upper())
    return "_".join(locale_parts) + ".UTF-8"


def launch_setting_checks(exit_context: dict[str, Any] | None) -> tuple[dict[str, str], dict[str, str], dict[str, str] | None]:
    if exit_context is None:
        return (
            guard.check("cli_timezone", "CLI 時區啟動設定", "unknown", "缺少已核實的出口時區。"),
            guard.check("cli_language", "CLI 語言啟動設定", "unknown", "缺少已核實的出口國家。"),
            None,
        )
    time_zone = exit_context.get("timeZone")
    try:
        if not isinstance(time_zone, str):
            raise ValueError("timezone")
        ZoneInfo(time_zone)
        timezone_check = guard.check("cli_timezone", "CLI 時區啟動設定", "pass", f"啟動設定：TZ={time_zone}。")
    except (ValueError, ZoneInfoNotFoundError):
        return (
            guard.check("cli_timezone", "CLI 時區啟動設定", "unknown", "出口時區不能轉換為安全啟動設定。"),
            guard.check("cli_language", "CLI 語言啟動設定", "unknown", "缺少可配對的安全時區啟動設定。"),
            None,
        )
    try:
        country = exit_context["country"]
        languages = guard.load_policy()["countries"][country]["languages"]
        if not isinstance(languages, list) or len(languages) != 2 or not all(isinstance(item, str) for item in languages):
            raise ValueError("languages")
        locale = locale_from_language(languages[0])
        if locale is None:
            raise ValueError("locale")
    except (KeyError, TypeError, ValueError):
        return (
            timezone_check,
            guard.check("cli_language", "CLI 語言啟動設定", "unknown", "支援地區語言不能轉換為安全啟動設定。"),
            None,
        )
    settings = {"TZ": time_zone, "LANG": locale, "LC_ALL": locale}
    return (
        timezone_check,
        guard.check("cli_language", "CLI 語言啟動設定", "pass", f"啟動設定：LANG={locale}、LC_ALL={locale}。"),
        settings,
    )


def compute_can_launch(checks: Any, installed_verified: bool) -> bool:
    if not installed_verified or not isinstance(checks, list):
        return False
    statuses: dict[str, str] = {}
    for item in checks:
        if not isinstance(item, dict) or set(item) != {"id", "title", "status", "detail"}:
            return False
        if item.get("id") in statuses or item.get("status") not in guard.VALID_CHECK_STATUSES:
            return False
        if not all(isinstance(item.get(field), str) and item[field] for field in ("id", "title", "status", "detail")):
            return False
        statuses[item["id"]] = item["status"]
    return set(statuses) == REQUIRED_LAUNCH_CHECK_IDS and all(statuses[item] == "pass" for item in REQUIRED_LAUNCH_CHECK_IDS)


def perform_check(acceptance: str | None = None) -> tuple[dict[str, Any], bool, pathlib.Path | None, dict[str, str] | None]:
    installed_check, installed_verified, binary = verify_installed_cli()
    process_check = verify_process_guard()
    trace_check, trace_context = guard.cloudflare_trace()
    location_check, exit_context = guard.ipwho_check(trace_context)
    reputation_check, acknowledgement = guard.proxycheck_check(exit_context, acceptance)
    timezone_check, language_check, settings = launch_setting_checks(exit_context)
    sandbox_check = (
        guard.sandbox_check()
        if process_check["status"] == "pass"
        else guard.check("network_sandbox", "網絡沙箱", "unknown", "CLI 保護設定未通過，已跳過網絡沙箱直連探測。")
    )
    checks = [
        installed_check,
        process_check,
        trace_check,
        location_check,
        reputation_check,
        timezone_check,
        language_check,
        sandbox_check,
    ]
    result = {
        "checkedAt": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "canLaunch": compute_can_launch(checks, installed_verified),
        "checks": checks,
        "permissions": [],
        "hostingAcknowledgement": acknowledgement,
        "exitContext": exit_context,
        "target": "cli",
    }
    return result, installed_verified, binary, settings


def launch_environment(settings: dict[str, str]) -> dict[str, str]:
    if set(settings) != {"TZ", "LANG", "LC_ALL"}:
        raise ValueError("invalid launch settings")
    environment = os.environ.copy()
    environment.update(settings)
    environment["BROWSER"] = str(BROWSER_ENTRY)
    return environment


def print_blockers(result: dict[str, Any]) -> None:
    checks = result.get("checks")
    if not isinstance(checks, list):
        print("啟動檢查：檢查結果無效。", file=sys.stderr)
        return
    for item in checks:
        if isinstance(item, dict) and item.get("id") in REQUIRED_LAUNCH_CHECK_IDS and item.get("status") != "pass":
            print(f"{item.get('title', '啟動檢查')}：{item.get('detail', '未通過。')}", file=sys.stderr)


def launch(
    result: dict[str, Any],
    installed_verified: bool,
    settings: dict[str, str] | None,
    project: pathlib.Path,
) -> int:
    authorized = compute_can_launch(result.get("checks"), installed_verified)
    result["canLaunch"] = authorized
    if not authorized or settings is None:
        print_blockers(result)
        return 2
    if not project.is_absolute() or not project.is_dir() or not os.access(project, os.X_OK):
        print("啟動項目：必須是可進入的絕對目錄。", file=sys.stderr)
        return 2
    installed_check, currently_verified, _binary = verify_installed_cli()
    process_check = verify_process_guard()
    if not currently_verified or installed_check["status"] != "pass" or process_check["status"] != "pass":
        for item in (installed_check, process_check):
            if item["status"] != "pass":
                print(f"{item['title']}：{item['detail']}", file=sys.stderr)
        return 2
    try:
        environment = launch_environment(settings)
        os.chdir(project)
        os.execve(str(CLI_LAUNCHER), ["claude"], environment)
    except (OSError, ValueError):
        print("CLI 啟動：無法啟動已核實的 CLI。", file=sys.stderr)
        return 2
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--launch", action="store_true")
    parser.add_argument("--project", type=pathlib.Path)
    parser.add_argument("--accept-hosting-snapshot")
    arguments = parser.parse_args()
    if arguments.check and arguments.project is not None:
        parser.error("--project 只可配合 --launch")
    if arguments.launch and arguments.project is None:
        parser.error("--launch 需要 --project ABSOLUTE")

    result, installed_verified, _binary, settings = perform_check(arguments.accept_hosting_snapshot)
    if arguments.check:
        print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
        return 0
    return launch(result, installed_verified, settings, arguments.project)


if __name__ == "__main__":
    raise SystemExit(main())
