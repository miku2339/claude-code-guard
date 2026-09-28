import AppKit

@main
private enum UIRenderRegressionMain {
    static func main() {
        _ = NSApplication.shared
        precondition(Thread.isMainThread)
        AppDelegate().runRenderRegressionHarness()
        print("PASS: checks and permissions rendered twice")
    }
}
