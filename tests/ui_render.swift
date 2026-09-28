import AppKit
import WebKit

@main
private enum UIRenderRegressionMain {
    static func main() throws {
        _ = NSApplication.shared
        precondition(Thread.isMainThread)
        let resources = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
        let fixture = CommandLine.arguments.count > 2 ? URL(fileURLWithPath: CommandLine.arguments[2]) : nil
        let snapshot = CommandLine.arguments.count > 3 ? URL(fileURLWithPath: CommandLine.arguments[3]) : nil
        try AppDelegate().runRenderRegressionHarness(resourcesURL: resources, fixtureURL: fixture, snapshotURL: snapshot)
        print("PASS: local WebKit page, native launch gate, expiry, risk binding, and safe text rendering")
    }
}

extension AppDelegate {
    private func waitForUI(_ condition: () -> Bool) {
        let deadline = Date().addingTimeInterval(20)
        while !condition() && Date() < deadline {
            RunLoop.current.run(until: Date().addingTimeInterval(0.01))
        }
        precondition(condition(), "Timed out waiting for WebKit")
    }

    @discardableResult
    private func evaluateUI(_ script: String) -> Any? {
        var finished = false
        var value: Any?
        var failure: Error?
        webView.evaluateJavaScript(script) { result, error in
            value = result
            failure = error
            finished = true
        }
        waitForUI { finished }
        precondition(failure == nil, "JavaScript error: \(String(describing: failure))")
        return value
    }

    private func assertUI(_ expression: String) {
        precondition(evaluateUI(expression) as? Bool == true, expression)
    }

    func runRenderRegressionHarness(resourcesURL: URL, fixtureURL: URL?, snapshotURL: URL?) throws {
        isTesting = true
        configureWindow(resourcesURL: resourcesURL)
        waitForUI { self.pageReady }
        precondition(!isTrustedPage(URL(string: "https://example.com/")))
        precondition(!isTrustedPage(resourcesURL.appendingPathComponent("Other.html")))
        assertUI("document.querySelector('.logo').complete && document.querySelector('.logo').naturalWidth > 0")
        assertUI("getComputedStyle(document.body).backgroundColor === 'rgb(247, 240, 229)'")
        assertUI("document.querySelector('#environment-checks').children.length === 6")
        assertUI("document.querySelector('#desktop-checks').children.length === 4")
        assertUI("document.querySelector('#continue-button').disabled")
        assertUI("document.querySelector('#continue-button').textContent === '開啟 Claude Code'")
        assertUI("!document.querySelector('#risk-acceptance-checkbox').checked")

        var checks = requiredLaunchCheckIDs.sorted().map {
            ["id": $0, "title": $0, "status": "pass", "detail": "已核實"]
        }
        var payload: [String: Any] = [
            "checkedAt": ISO8601DateFormatter().string(from: Date()), "canLaunch": true,
            "checks": checks, "permissions": [],
            "exitContext": ["country": "JP", "ip": "203.0.113.10", "timeZone": "Asia/Tokyo"],
        ]
        func load(_ value: [String: Any]) throws {
            let data = try JSONSerialization.data(withJSONObject: value)
            let result = CommandResult(exitCode: 0, standardOutput: data, standardError: Data(), outputWasTruncated: false, errorWasTruncated: false, launchError: nil)
            precondition(readResponse(result))
            publishState()
        }
        try load(payload)
        precondition(responseAllowsLaunch(lastResponse))
        assertUI("!document.querySelector('#continue-button').disabled")
        assertUI("document.querySelector('#webrtc-detail').textContent.includes('203.0.113.10')")
        assertUI("document.querySelector('#webrtc-status').textContent === '未量測'")

        assertUI("window.guardUI.update({busy: true}); document.querySelector('#continue-button').disabled")
        _ = evaluateUI("window.webkit.messageHandlers.guard.postMessage({action: 'ready'}); true")
        assertUI("!document.querySelector('#continue-button').disabled")

        // A required informational result still blocks, regardless of the backend boolean.
        let installedIndex = checks.firstIndex { $0["id"] == "installed_app" }!
        checks[installedIndex]["status"] = "info"
        checks[installedIndex]["detail"] = "<img src=x onerror=alert(1)>"
        payload["checks"] = checks
        try load(payload)
        precondition(!responseAllowsLaunch(lastResponse))
        assertUI("document.querySelector('#continue-button').disabled")
        assertUI("document.querySelector('#official-app-detail').children.length === 0")
        assertUI("document.querySelector('#overall-detail').textContent.includes('installed_app')")
        checks[installedIndex]["status"] = "pass"
        payload["checks"] = checks

        var acknowledgement: [String: Any] = ["eligible": true, "snapshotKey": "first", "accepted": true, "detail": "目前機房出口"]
        payload["hostingAcknowledgement"] = acknowledgement
        try load(payload)
        precondition(!responseAllowsLaunch(lastResponse))
        assertUI("!document.querySelector('#risk-acceptance-checkbox').checked")
        hostingSnapshotKey = "first"
        try load(payload)
        precondition(responseAllowsLaunch(lastResponse))
        assertUI("document.querySelector('#risk-acceptance-checkbox').checked")
        assertUI("document.querySelector('#reputation-status').textContent === '已確認風險'")
        acknowledgement["snapshotKey"] = "changed"
        payload["hostingAcknowledgement"] = acknowledgement
        try load(payload)
        precondition(hostingSnapshotKey == nil && !responseAllowsLaunch(lastResponse))
        assertUI("!document.querySelector('#risk-acceptance-checkbox').checked")

        payload.removeValue(forKey: "hostingAcknowledgement")
        payload["checkedAt"] = ISO8601DateFormatter().string(from: Date().addingTimeInterval(-61))
        try load(payload)
        precondition(!responseAllowsLaunch(lastResponse))
        assertUI("document.querySelector('#continue-button').disabled")
        assertUI("document.querySelector('#overall-detail').textContent.includes('過期')")
        payload["checkedAt"] = ISO8601DateFormatter().string(from: Date())
        payload["checks"] = checks + [checks[0]]
        try load(payload)
        precondition(!responseAllowsLaunch(lastResponse))
        assertUI("document.querySelector('#overall-detail').textContent.includes('格式')")
        payload["checks"] = Array(checks.dropFirst())
        try load(payload)
        precondition(!responseAllowsLaunch(lastResponse))
        assertUI("document.querySelector('#overall-detail').textContent.includes('缺少')")

        let malformed = CommandResult(exitCode: 0, standardOutput: Data("{}".utf8), standardError: Data(), outputWasTruncated: false, errorWasTruncated: false, launchError: nil)
        precondition(!readResponse(malformed))
        publishState()
        assertUI("document.querySelector('#continue-button').disabled && document.querySelector('#risk-acceptance').hidden")

        if let fixtureURL {
            let fixture = try JSONSerialization.jsonObject(with: Data(contentsOf: fixtureURL)) as! [String: Any]
            try load(fixture)
            assertUI("document.querySelector('#continue-button').disabled")
            assertUI("!document.querySelector('#risk-acceptance-checkbox').checked")
        }
        if let snapshotURL {
            let height = evaluateUI("document.documentElement.scrollHeight") as! Double
            window.setContentSize(NSSize(width: 900, height: height))
            _ = evaluateUI("document.body.offsetHeight")
            // Allow layout and image compositing before capturing the app-owned web view.
            RunLoop.current.run(until: Date().addingTimeInterval(0.2))
            var finished = false
            webView.takeSnapshot(with: nil) { image, error in
                precondition(error == nil && image != nil)
                let representation = NSBitmapImageRep(data: image!.tiffRepresentation!)!
                try! representation.representation(using: .png, properties: [:])!.write(to: snapshotURL)
                finished = true
            }
            waitForUI { finished }
        }
        webView.configuration.userContentController.removeScriptMessageHandler(forName: "guard")
        window.close()
    }
}
