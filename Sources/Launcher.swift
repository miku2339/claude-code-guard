import AppKit
import Foundation

private let appName = "Claude 啟動檢查"
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

private struct GuardResponse: Decodable {
    let checkedAt: String
    let canLaunch: Bool
    let checks: [GuardCheck]
    let permissions: [GuardPermission]
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

final class AppDelegate: NSObject, NSApplicationDelegate {
    private var window: NSWindow!
    private let statusText = NSTextView()
    private let checksStack = NSStackView()
    private let permissionsStack = NSStackView()
    private let recheckButton = NSButton(title: "重新檢查", target: nil, action: nil)
    private let launchButton = NSButton(title: "啟動 Claude", target: nil, action: nil)
    private var lastResponse: GuardResponse?
    private var isBusy = false
    private var expiryTimer: Timer?

    func applicationDidFinishLaunching(_ notification: Notification) {
        configureMenu()
        configureWindow()
        performCheck()
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }

    func applicationWillTerminate(_ notification: Notification) {
        expiryTimer?.invalidate()
    }

    private func configureMenu() {
        let mainMenu = NSMenu()
        let appMenuItem = NSMenuItem()
        mainMenu.addItem(appMenuItem)
        let appMenu = NSMenu(title: appName)
        appMenu.addItem(
            withTitle: "結束 \(appName)",
            action: #selector(NSApplication.terminate(_:)),
            keyEquivalent: "q"
        )
        appMenuItem.submenu = appMenu
        NSApp.mainMenu = mainMenu
    }

    private func configureWindow() {
        window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 560, height: 640),
            styleMask: [.titled, .closable, .miniaturizable],
            backing: .buffered,
            defer: false
        )
        window.title = appName
        window.isReleasedWhenClosed = false
        window.center()
        window.contentMinSize = NSSize(width: 500, height: 520)

        let root = NSStackView()
        root.orientation = .vertical
        root.alignment = .leading
        root.spacing = 18
        root.edgeInsets = NSEdgeInsets(top: 24, left: 24, bottom: 20, right: 24)
        root.translatesAutoresizingMaskIntoConstraints = false

        let heading = makeHeading()
        root.addArrangedSubview(heading)

        configureStatusText()
        root.addArrangedSubview(statusText)

        let scrollView = makeResultsScrollView()
        root.addArrangedSubview(scrollView)

        let buttonRow = makeButtonRow()
        root.addArrangedSubview(buttonRow)

        guard let contentView = window.contentView else { return }
        contentView.addSubview(root)
        NSLayoutConstraint.activate([
            root.leadingAnchor.constraint(equalTo: contentView.leadingAnchor),
            root.trailingAnchor.constraint(equalTo: contentView.trailingAnchor),
            root.topAnchor.constraint(equalTo: contentView.topAnchor),
            root.bottomAnchor.constraint(equalTo: contentView.bottomAnchor),
            heading.widthAnchor.constraint(equalTo: root.widthAnchor, constant: -48),
            statusText.widthAnchor.constraint(equalTo: heading.widthAnchor),
            scrollView.widthAnchor.constraint(equalTo: heading.widthAnchor),
            buttonRow.widthAnchor.constraint(equalTo: heading.widthAnchor),
        ])

        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    private func makeHeading() -> NSView {
        let icon = NSImageView()
        icon.image = NSImage(systemSymbolName: "checkmark.shield", accessibilityDescription: "安全檢查")
        icon.symbolConfiguration = NSImage.SymbolConfiguration(pointSize: 28, weight: .medium)
        icon.contentTintColor = .controlAccentColor
        icon.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            icon.widthAnchor.constraint(equalToConstant: 36),
            icon.heightAnchor.constraint(equalToConstant: 36),
        ])

        let title = NSTextField(labelWithString: "先檢查，再啟動")
        title.font = .systemFont(ofSize: 24, weight: .semibold)
        let subtitle = NSTextField(wrappingLabelWithString: "Alpha · 啟動防護尚未就緒")
        subtitle.textColor = .secondaryLabelColor
        subtitle.font = .systemFont(ofSize: 13)

        let text = NSStackView(views: [title, subtitle])
        text.orientation = .vertical
        text.alignment = .leading
        text.spacing = 4

        let row = NSStackView(views: [icon, text])
        row.orientation = .horizontal
        row.alignment = .top
        row.spacing = 12
        return row
    }

    private func configureStatusText() {
        statusText.isEditable = false
        statusText.isSelectable = true
        statusText.drawsBackground = false
        statusText.textContainerInset = NSSize(width: 0, height: 2)
        statusText.font = .systemFont(ofSize: 13)
        statusText.textColor = .secondaryLabelColor
        statusText.string = "正在檢查…"
        statusText.translatesAutoresizingMaskIntoConstraints = false
        statusText.heightAnchor.constraint(greaterThanOrEqualToConstant: 36).isActive = true
    }

    private func makeResultsScrollView() -> NSScrollView {
        checksStack.orientation = .vertical
        checksStack.alignment = .leading
        checksStack.spacing = 8
        permissionsStack.orientation = .vertical
        permissionsStack.alignment = .leading
        permissionsStack.spacing = 8

        let checksTitle = makeSectionTitle("檢查結果")
        let permissionsTitle = makeSectionTitle("權限資料")
        let contentStack = NSStackView(views: [checksTitle, checksStack, permissionsTitle, permissionsStack])
        contentStack.orientation = .vertical
        contentStack.alignment = .leading
        contentStack.spacing = 10
        contentStack.setCustomSpacing(18, after: checksStack)
        contentStack.translatesAutoresizingMaskIntoConstraints = false

        let documentView = NSView()
        documentView.translatesAutoresizingMaskIntoConstraints = false
        documentView.addSubview(contentStack)

        let scrollView = NSScrollView()
        scrollView.drawsBackground = false
        scrollView.hasVerticalScroller = true
        scrollView.autohidesScrollers = true
        scrollView.borderType = .noBorder
        scrollView.documentView = documentView
        scrollView.translatesAutoresizingMaskIntoConstraints = false
        scrollView.setContentHuggingPriority(.defaultLow, for: .vertical)
        scrollView.setContentCompressionResistancePriority(.defaultLow, for: .vertical)

        NSLayoutConstraint.activate([
            documentView.widthAnchor.constraint(equalTo: scrollView.contentView.widthAnchor),
            contentStack.leadingAnchor.constraint(equalTo: documentView.leadingAnchor),
            contentStack.trailingAnchor.constraint(equalTo: documentView.trailingAnchor, constant: -8),
            contentStack.topAnchor.constraint(equalTo: documentView.topAnchor),
            contentStack.bottomAnchor.constraint(equalTo: documentView.bottomAnchor),
            checksTitle.widthAnchor.constraint(equalTo: contentStack.widthAnchor, constant: -8),
            checksStack.widthAnchor.constraint(equalTo: contentStack.widthAnchor, constant: -8),
            permissionsTitle.widthAnchor.constraint(equalTo: contentStack.widthAnchor, constant: -8),
            permissionsStack.widthAnchor.constraint(equalTo: contentStack.widthAnchor, constant: -8),
        ])

        return scrollView
    }

    private func makeSectionTitle(_ value: String) -> NSTextField {
        let label = NSTextField(labelWithString: value)
        label.font = .systemFont(ofSize: 14, weight: .semibold)
        return label
    }

    private func makeButtonRow() -> NSStackView {
        recheckButton.target = self
        recheckButton.action = #selector(recheck(_:))
        recheckButton.bezelStyle = .rounded

        launchButton.target = self
        launchButton.action = #selector(launchClaude(_:))
        launchButton.bezelStyle = .rounded
        launchButton.keyEquivalent = "\r"
        launchButton.isEnabled = false

        let spacer = NSView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        let row = NSStackView(views: [spacer, recheckButton, launchButton])
        row.orientation = .horizontal
        row.alignment = .centerY
        row.spacing = 10
        return row
    }

    @objc private func recheck(_ sender: Any?) {
        performCheck()
    }

    @objc private func launchClaude(_ sender: Any?) {
        guard responseAllowsLaunch(lastResponse), !isBusy else {
            refreshLaunchAvailability()
            return
        }

        setBusy(true)
        setStatus("正在再次核實並啟動 Claude…", color: .secondaryLabelColor)
        GuardRunner.run(arguments: ["--launch"]) { [weak self] result in
            guard let self else { return }
            if result.exitCode == 0,
               result.launchError == nil,
               !result.standardOutput.isEmpty,
               !result.outputWasTruncated,
               let response = try? JSONDecoder().decode(GuardResponse.self, from: result.standardOutput),
               self.responseAllowsLaunch(response) {
                self.lastResponse = response
                self.render(response)
                self.isBusy = false
                self.recheckButton.isEnabled = true
                self.launchButton.isEnabled = false
                self.setStatus("Claude 已通過檢查並啟動。", color: .systemGreen)
                return
            }

            let summary = self.failureSummary(for: result, fallback: "啟動失敗。")
            self.setBusy(false)
            self.performCheck(contextMessage: "\(summary) 已重新檢查。")
        }
    }

    private func performCheck(contextMessage: String? = nil) {
        guard !isBusy else { return }
        lastResponse = nil
        setBusy(true)
        setStatus("正在檢查…", color: .secondaryLabelColor)
        showPlaceholder("正在讀取檢查結果…", in: checksStack)
        showPlaceholder("正在讀取權限資料…", in: permissionsStack)

        GuardRunner.run(arguments: ["--check"]) { [weak self] result in
            guard let self else { return }
            self.setBusy(false)

            guard result.launchError == nil,
                  result.exitCode == 0,
                  !result.standardOutput.isEmpty,
                  !result.outputWasTruncated,
                  let response = try? JSONDecoder().decode(GuardResponse.self, from: result.standardOutput)
            else {
                self.lastResponse = nil
                self.showPlaceholder("未能取得有效檢查結果。", in: self.checksStack)
                self.showPlaceholder("權限資料不可用。", in: self.permissionsStack)
                self.setStatus(self.failureSummary(for: result, fallback: "檢查失敗。"), color: .systemRed)
                self.refreshLaunchAvailability()
                return
            }

            self.lastResponse = response
            self.render(response)
            let prefix = contextMessage.map { "\($0)\n" } ?? ""
            if self.responseAllowsLaunch(response) {
                self.setStatus("\(prefix)所有啟動條件已通過。檢查結果 60 秒內有效。", color: .systemGreen)
            } else if self.checkedDate(from: response.checkedAt) == nil {
                self.setStatus("\(prefix)檢查時間無效，請重新檢查。", color: .systemRed)
            } else if self.isResponseFresh(response) == false {
                self.setStatus("\(prefix)檢查結果已過期，請重新檢查。", color: .systemOrange)
            } else {
                self.setStatus("\(prefix)尚有項目未通過，暫時不能啟動 Claude。", color: .systemRed)
            }
            self.refreshLaunchAvailability()
        }
    }

    private func setBusy(_ busy: Bool) {
        isBusy = busy
        recheckButton.isEnabled = !busy
        refreshLaunchAvailability()
    }

    private func setStatus(_ message: String, color: NSColor) {
        statusText.string = message
        statusText.textColor = color
    }

    private func render(_ response: GuardResponse) {
        clear(checksStack)
        if response.checks.isEmpty {
            showPlaceholder("沒有檢查項目。", in: checksStack)
        } else {
            for check in response.checks {
                checksStack.addArrangedSubview(makeCheckRow(check))
            }
        }

        clear(permissionsStack)
        if response.permissions.isEmpty {
            showPlaceholder("沒有額外權限資料。", in: permissionsStack)
        } else {
            for permission in response.permissions {
                permissionsStack.addArrangedSubview(makePermissionRow(permission))
            }
        }
    }

    private func makeCheckRow(_ check: GuardCheck) -> NSView {
        let symbol = NSTextField(labelWithString: statusPresentation(check.status).symbol)
        symbol.font = .systemFont(ofSize: 15, weight: .semibold)
        symbol.textColor = statusPresentation(check.status).color
        symbol.alignment = .center
        symbol.translatesAutoresizingMaskIntoConstraints = false
        symbol.widthAnchor.constraint(equalToConstant: 20).isActive = true

        let title = NSTextField(wrappingLabelWithString: check.title)
        title.font = .systemFont(ofSize: 13, weight: .medium)
        let detail = NSTextField(wrappingLabelWithString: check.detail)
        detail.font = .systemFont(ofSize: 12)
        detail.textColor = .secondaryLabelColor
        let text = NSStackView(views: [title, detail])
        text.orientation = .vertical
        text.alignment = .leading
        text.spacing = 2

        let row = NSStackView(views: [symbol, text])
        row.orientation = .horizontal
        row.alignment = .top
        row.spacing = 8
        row.edgeInsets = NSEdgeInsets(top: 9, left: 10, bottom: 9, right: 10)
        row.wantsLayer = true
        row.layer?.cornerRadius = 8
        row.layer?.backgroundColor = NSColor.controlBackgroundColor.cgColor
        row.translatesAutoresizingMaskIntoConstraints = false
        row.widthAnchor.constraint(equalTo: checksStack.widthAnchor).isActive = true
        return row
    }

    private func makePermissionRow(_ permission: GuardPermission) -> NSView {
        let name = NSTextField(wrappingLabelWithString: permission.name)
        name.font = .systemFont(ofSize: 12, weight: .medium)
        let detail = NSTextField(wrappingLabelWithString: permission.detail)
        detail.font = .systemFont(ofSize: 12)
        detail.textColor = .secondaryLabelColor
        let row = NSStackView(views: [name, detail])
        row.orientation = .vertical
        row.alignment = .leading
        row.spacing = 2
        row.edgeInsets = NSEdgeInsets(top: 8, left: 10, bottom: 8, right: 10)
        row.wantsLayer = true
        row.layer?.cornerRadius = 8
        row.layer?.backgroundColor = NSColor.controlBackgroundColor.cgColor
        row.translatesAutoresizingMaskIntoConstraints = false
        row.widthAnchor.constraint(equalTo: permissionsStack.widthAnchor).isActive = true
        return row
    }

    private func showPlaceholder(_ value: String, in stack: NSStackView) {
        clear(stack)
        let label = NSTextField(wrappingLabelWithString: value)
        label.font = .systemFont(ofSize: 12)
        label.textColor = .secondaryLabelColor
        stack.addArrangedSubview(label)
    }

    private func clear(_ stack: NSStackView) {
        for view in stack.arrangedSubviews {
            stack.removeArrangedSubview(view)
            view.removeFromSuperview()
        }
    }

    private func statusPresentation(_ status: CheckStatus) -> (symbol: String, color: NSColor) {
        switch status {
        case .pass:
            return ("✓", .systemGreen)
        case .fail:
            return ("×", .systemRed)
        case .unknown:
            return ("?", .systemOrange)
        case .info:
            return ("i", .secondaryLabelColor)
        }
    }

    private func responseAllowsLaunch(_ response: GuardResponse?) -> Bool {
        guard let response, response.canLaunch, !response.checks.isEmpty, isResponseFresh(response) else {
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

    private func refreshLaunchAvailability() {
        launchButton.isEnabled = !isBusy && responseAllowsLaunch(lastResponse)
        expiryTimer?.invalidate()
        guard launchButton.isEnabled else { return }
        expiryTimer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] timer in
            guard let self else {
                timer.invalidate()
                return
            }
            if !self.responseAllowsLaunch(self.lastResponse) {
                timer.invalidate()
                self.launchButton.isEnabled = false
                self.setStatus("檢查結果已過期，請重新檢查。", color: .systemOrange)
            }
        }
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
application.setActivationPolicy(.regular)
application.run()
