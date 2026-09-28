import AppKit
import Foundation
import WebKit

private let appName = "claude-code-guard"
private let maximumProcessOutputBytes = 1_048_576
private let requiredLaunchCheckIDs: Set<String> = [
    "installed_app",
    "proxy_exit",
    "exit_location",
    "exit_reputation",
    "system_timezone",
    "app_language",
    "network_sandbox",
    "os_firewall",
    "tcc_authorization",
]

private enum CheckStatus: String, Decodable {
    case pass
    case fail
    case unknown
    case info
}

private struct GuardCheck: Decodable {
    let id: String
    let title: String
    let status: CheckStatus
    let detail: String
}

private struct GuardPermission: Decodable {
    let name: String
    let detail: String
}

private struct HostingAcknowledgement: Decodable {
    let eligible: Bool
    let snapshotKey: String
    let accepted: Bool
    let detail: String
}

private struct GuardResponse: Decodable {
    let checkedAt: String
    let canLaunch: Bool
    let checks: [GuardCheck]
    let permissions: [GuardPermission]
    let hostingAcknowledgement: HostingAcknowledgement?

    init(
        checkedAt: String,
        canLaunch: Bool,
        checks: [GuardCheck],
        permissions: [GuardPermission],
        hostingAcknowledgement: HostingAcknowledgement? = nil
    ) {
        self.checkedAt = checkedAt
        self.canLaunch = canLaunch
        self.checks = checks
        self.permissions = permissions
        self.hostingAcknowledgement = hostingAcknowledgement
    }
}

private struct CommandResult {
    let exitCode: Int32
    let standardOutput: Data
    let standardError: Data
    let outputWasTruncated: Bool
    let errorWasTruncated: Bool
    let launchError: String?
}

private final class BoundedDataCollector: @unchecked Sendable {
    private let limit: Int
    private let lock = NSLock()
    private var storage = Data()
    private var didTruncate = false

    init(limit: Int) {
        self.limit = limit
    }

    func append(_ data: Data) {
        lock.lock()
        defer { lock.unlock() }

        let remaining = max(0, limit - storage.count)
        if data.count > remaining {
            didTruncate = true
        }
        if remaining > 0 {
            storage.append(data.prefix(remaining))
        }
    }

    func snapshot() -> (data: Data, truncated: Bool) {
        lock.lock()
        defer { lock.unlock() }
        return (storage, didTruncate)
    }
}

private enum GuardRunner {
    static func run(arguments: [String], completion: @escaping (CommandResult) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async {
            guard let resourcesURL = Bundle.main.resourceURL else {
                complete(
                    CommandResult(
                        exitCode: -1,
                        standardOutput: Data(),
                        standardError: Data(),
                        outputWasTruncated: false,
                        errorWasTruncated: false,
                        launchError: "找不到應用程式資源。"
                    ),
                    with: completion
                )
                return
            }

            let scriptURL = resourcesURL.appendingPathComponent("guard.py", isDirectory: false)
            guard FileManager.default.isReadableFile(atPath: scriptURL.path) else {
                complete(
                    CommandResult(
                        exitCode: -1,
                        standardOutput: Data(),
                        standardError: Data(),
                        outputWasTruncated: false,
                        errorWasTruncated: false,
                        launchError: "找不到檢查程式 guard.py。"
                    ),
                    with: completion
                )
                return
            }

            let process = Process()
            let outputPipe = Pipe()
            let errorPipe = Pipe()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
            process.arguments = [scriptURL.path] + arguments
            process.currentDirectoryURL = resourcesURL
            process.standardInput = FileHandle.nullDevice
            process.standardOutput = outputPipe
            process.standardError = errorPipe

            do {
                try process.run()
            } catch {
                complete(
                    CommandResult(
                        exitCode: -1,
                        standardOutput: Data(),
                        standardError: Data(),
                        outputWasTruncated: false,
                        errorWasTruncated: false,
                        launchError: "檢查程式無法執行。"
                    ),
                    with: completion
                )
                return
            }

            let outputCollector = BoundedDataCollector(limit: maximumProcessOutputBytes)
            let errorCollector = BoundedDataCollector(limit: maximumProcessOutputBytes)
            let readers = DispatchGroup()

            readers.enter()
            DispatchQueue.global(qos: .utility).async {
                drain(outputPipe.fileHandleForReading, into: outputCollector)
                readers.leave()
            }
            readers.enter()
            DispatchQueue.global(qos: .utility).async {
                drain(errorPipe.fileHandleForReading, into: errorCollector)
                readers.leave()
            }

            process.waitUntilExit()
            readers.wait()
            let output = outputCollector.snapshot()
            let error = errorCollector.snapshot()
            complete(
                CommandResult(
                    exitCode: process.terminationStatus,
                    standardOutput: output.data,
                    standardError: error.data,
                    outputWasTruncated: output.truncated,
                    errorWasTruncated: error.truncated,
                    launchError: nil
                ),
                with: completion
            )
        }
    }

    private static func drain(_ handle: FileHandle, into collector: BoundedDataCollector) {
        while true {
            do {
                guard let data = try handle.read(upToCount: 16_384), !data.isEmpty else { return }
                collector.append(data)
            } catch {
                return
            }
        }
    }

    private static func complete(_ result: CommandResult, with completion: @escaping (CommandResult) -> Void) {
        DispatchQueue.main.async {
            completion(result)
        }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate, WKScriptMessageHandler, WKNavigationDelegate {
    private var window: NSWindow!
    private var webView: WKWebView!
    private var pageURL: URL!
    private var pageReady = false
    private var lastResponse: GuardResponse?
    private var lastPayload: [String: Any] = [:]
    private var hostingSnapshotKey: String?
    private var isBusy = false
    private var errorMessage: String?
    private var didLaunch = false
    private var expiryTimer: Timer?
#if UI_RENDER_TEST
    private var isTesting = false
#endif

    func applicationDidFinishLaunching(_ notification: Notification) {
        let menu = NSMenu()
        let item = NSMenuItem()
        let appMenu = NSMenu(title: appName)
        appMenu.addItem(withTitle: "結束 \(appName)", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        item.submenu = appMenu
        menu.addItem(item)
        NSApp.mainMenu = menu
        guard let resourcesURL = Bundle.main.resourceURL else { return }
        configureWindow(resourcesURL: resourcesURL)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }

    func applicationWillTerminate(_ notification: Notification) {
        expiryTimer?.invalidate()
        webView.configuration.userContentController.removeScriptMessageHandler(forName: "guard")
    }

    private func configureWindow(resourcesURL: URL) {
        pageURL = resourcesURL.appendingPathComponent("Guard.html").standardizedFileURL
        let available = NSScreen.main?.visibleFrame.size ?? NSSize(width: 900, height: 1050)
        window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: min(900, available.width - 40), height: min(1050, available.height - 60)),
            styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false
        )
        window.title = appName
        window.isReleasedWhenClosed = false
        window.contentMinSize = NSSize(width: 500, height: 600)
        window.backgroundColor = NSColor(red: 247 / 255, green: 240 / 255, blue: 229 / 255, alpha: 1)
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .nonPersistent()
        configuration.userContentController.add(self, name: "guard")
        webView = WKWebView(frame: window.contentView!.bounds, configuration: configuration)
        webView.autoresizingMask = [.width, .height]
        webView.navigationDelegate = self
        window.contentView = webView
        window.center()
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        webView.loadFileURL(pageURL, allowingReadAccessTo: resourcesURL)
    }

    private func isTrustedPage(_ url: URL?) -> Bool {
        guard let url, url.isFileURL else { return false }
        return url.standardizedFileURL == pageURL
    }

    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        decisionHandler(navigationAction.targetFrame?.isMainFrame == true && isTrustedPage(navigationAction.request.url) ? .allow : .cancel)
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        showPageFailure()
    }

    func webViewWebContentProcessDidTerminate(_ webView: WKWebView) {
        pageReady = false
        lastResponse = nil
        lastPayload = [:]
        hostingSnapshotKey = nil
        expiryTimer?.invalidate()
        showPageFailure()
    }

    private func showPageFailure() {
        let alert = NSAlert()
        alert.messageText = "介面未能載入"
        alert.informativeText = "請重新開啟 claude-code-guard。"
        alert.beginSheetModal(for: window)
    }

    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        guard message.name == "guard", message.frameInfo.isMainFrame,
              isTrustedPage(message.frameInfo.request.url),
              let body = message.body as? [String: Any], let action = body["action"] as? String else { return }
        if action == "ready" {
            guard !pageReady else { publishState(); return }
            pageReady = true
#if UI_RENDER_TEST
            if isTesting { publishState(); return }
#endif
            performCheck()
            return
        }
        guard pageReady, !isBusy else { return }
        switch action {
        case "check": performCheck()
        case "launch": launchClaude()
        case "risk":
            guard let accepted = body["accepted"] as? Bool,
                  let acknowledgement = lastResponse?.hostingAcknowledgement,
                  acknowledgement.eligible, !acknowledgement.snapshotKey.isEmpty else { return }
            hostingSnapshotKey = accepted ? acknowledgement.snapshotKey : nil
            performCheck()
        default: break
        }
    }

    private func acceptedHostingSnapshotKey(for response: GuardResponse?) -> String? {
        guard let acknowledgement = response?.hostingAcknowledgement,
              acknowledgement.eligible, acknowledgement.accepted,
              !acknowledgement.snapshotKey.isEmpty,
              hostingSnapshotKey == acknowledgement.snapshotKey else { return nil }
        return acknowledgement.snapshotKey
    }

    private func readResponse(_ result: CommandResult) -> Bool {
        guard result.launchError == nil, result.exitCode == 0, !result.outputWasTruncated,
              let response = try? JSONDecoder().decode(GuardResponse.self, from: result.standardOutput),
              let payload = try? JSONSerialization.jsonObject(with: result.standardOutput) as? [String: Any] else {
            lastResponse = nil
            lastPayload = [:]
            hostingSnapshotKey = nil
            errorMessage = failureSummary(for: result, fallback: "未能取得有效檢查結果。")
            return false
        }
        lastResponse = response
        lastPayload = payload
        if acceptedHostingSnapshotKey(for: response) == nil { hostingSnapshotKey = nil }
        errorMessage = nil
        return true
    }

    private func performCheck() {
        guard !isBusy else { return }
        var arguments = ["--check"]
        if let hostingSnapshotKey { arguments += ["--accept-hosting-snapshot", hostingSnapshotKey] }
        lastResponse = nil
        lastPayload = [:]
        errorMessage = nil
        didLaunch = false
        isBusy = true
        expiryTimer?.invalidate()
        publishState()
        GuardRunner.run(arguments: arguments) { [weak self] result in
            guard let self else { return }
            self.isBusy = false
            _ = self.readResponse(result)
            self.publishState()
            self.scheduleExpiry()
        }
    }

    private func launchClaude() {
        guard !isBusy, !didLaunch, responseAllowsLaunch(lastResponse) else { return }
        var arguments = ["--launch"]
        if let key = acceptedHostingSnapshotKey(for: lastResponse) { arguments += ["--accept-hosting-snapshot", key] }
        isBusy = true
        expiryTimer?.invalidate()
        publishState()
        GuardRunner.run(arguments: arguments) { [weak self] result in
            guard let self else { return }
            self.isBusy = false
            if self.readResponse(result), self.responseAllowsLaunch(self.lastResponse) {
                self.didLaunch = true
                self.publishState()
            } else {
                self.performCheck()
            }
        }
    }

    private func publishState() {
        guard pageReady else { return }
        var blockers = lastResponse.map { blockingItems(for: $0).map(\.title) } ?? []
        if let response = lastResponse, !isResponseFresh(response) { blockers.append("檢查結果已過期，請重新檢查") }
        var state: [String: Any] = [
            "busy": isBusy,
            "canLaunch": !isBusy && !didLaunch && responseAllowsLaunch(lastResponse),
            "launched": didLaunch,
            "blockers": blockers,
            "riskAccepted": acceptedHostingSnapshotKey(for: lastResponse) != nil,
            "response": lastPayload,
        ]
        if let errorMessage { state["error"] = errorMessage }
        webView.callAsyncJavaScript("window.guardUI.update(state)", arguments: ["state": state], in: nil, in: .page) { _ in }
    }

    private func scheduleExpiry() {
        expiryTimer?.invalidate()
        guard responseAllowsLaunch(lastResponse) else { return }
        expiryTimer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] timer in
            guard let self else { timer.invalidate(); return }
            if !self.responseAllowsLaunch(self.lastResponse) {
                timer.invalidate()
                self.publishState()
            }
        }
    }

    private func blockingItems(for response: GuardResponse) -> [GuardCheck] {
        var items = response.checks.filter(isBlockingCheck)
        let presentIDs = Set(response.checks.map(\.id))

        for id in requiredLaunchCheckIDs.subtracting(presentIDs).sorted() {
            items.append(
                GuardCheck(
                    id: "missing_\(id)",
                    title: "缺少必需檢查（\(id)）",
                    status: .unknown,
                    detail: "檢查結果未包含此必需項目，不能判定為已通過。"
                )
            )
        }

        let duplicateIDs = Dictionary(grouping: response.checks, by: \.id)
            .filter { !$0.key.isEmpty && $0.value.count > 1 }
            .keys
            .sorted()
        if !duplicateIDs.isEmpty {
            items.append(
                GuardCheck(
                    id: "invalid_duplicate_ids",
                    title: "檢查資料格式有誤",
                    status: .unknown,
                    detail: "發現重複檢查 ID：\(duplicateIDs.joined(separator: "、"))。"
                )
            )
        }

        let invalidFieldCount = response.checks.filter {
            $0.id.isEmpty || $0.title.isEmpty || $0.detail.isEmpty
        }.count
        if invalidFieldCount > 0 {
            items.append(
                GuardCheck(
                    id: "invalid_empty_fields",
                    title: "檢查資料不完整",
                    status: .unknown,
                    detail: "\(invalidFieldCount) 項檢查缺少 ID、名稱或詳情。"
                )
            )
        }

        if !response.canLaunch && items.isEmpty {
            items.append(
                GuardCheck(
                    id: "launch_not_approved",
                    title: "檢查程式未批准啟動",
                    status: .fail,
                    detail: "所有列出的必需項目均顯示通過，但檢查結果仍拒絕啟動。請重新檢查。"
                )
            )
        }
        return items
    }

    private func isBlockingCheck(_ check: GuardCheck) -> Bool {
        if requiredLaunchCheckIDs.contains(check.id) {
            return check.status != .pass
        }
        return check.status == .fail || check.status == .unknown
    }

    private func responseAllowsLaunch(_ response: GuardResponse?) -> Bool {
        guard let response, response.canLaunch, !response.checks.isEmpty, isResponseFresh(response) else {
            return false
        }
        if response.hostingAcknowledgement?.eligible == true,
           acceptedHostingSnapshotKey(for: response) == nil {
            return false
        }

        var statuses: [String: CheckStatus] = [:]
        for check in response.checks {
            guard !check.id.isEmpty,
                  !check.title.isEmpty,
                  !check.detail.isEmpty,
                  statuses[check.id] == nil,
                  check.status == .pass || check.status == .info
            else { return false }
            statuses[check.id] = check.status
        }

        guard requiredLaunchCheckIDs.isSubset(of: Set(statuses.keys)) else { return false }
        return requiredLaunchCheckIDs.allSatisfy { statuses[$0] == .pass }
    }

    private func isResponseFresh(_ response: GuardResponse) -> Bool {
        guard let date = checkedDate(from: response.checkedAt) else { return false }
        let age = Date().timeIntervalSince(date)
        return age >= -5 && age <= 60
    }

    private func checkedDate(from value: String) -> Date? {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = formatter.date(from: value) {
            return date
        }
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.date(from: value)
    }

    private func failureSummary(for result: CommandResult, fallback: String) -> String {
        if let launchError = result.launchError {
            return launchError
        }
        guard !result.standardError.isEmpty else {
            return result.errorWasTruncated ? "\(fallback) 錯誤訊息過長。" : fallback
        }

        var text = String(decoding: result.standardError, as: UTF8.self)
        let sensitivePatterns = [
            "(?i)(password|passwd|token|secret|api[_-]?key|authorization)\\s*[:=]\\s*[^\\s,;]+",
            "(?i)bearer\\s+[^\\s,;]+",
        ]
        for pattern in sensitivePatterns {
            text = text.replacingOccurrences(
                of: pattern,
                with: "[敏感資料已隱藏]",
                options: .regularExpression
            )
        }
        text = text
            .replacingOccurrences(of: "[\\r\\n\\t]+", with: " ", options: .regularExpression)
            .replacingOccurrences(of: "\\s{2,}", with: " ", options: .regularExpression)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        if text.count > 360 {
            text = String(text.prefix(360)) + "…"
        }
        return text.isEmpty ? fallback : "\(fallback) \(text)"
    }
}

let application = NSApplication.shared
let delegate = AppDelegate()
application.delegate = delegate
application.run()
