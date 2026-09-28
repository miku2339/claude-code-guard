#!/bin/zsh
set -eu

readonly PROJECT_DIR="${0:A:h:h}"
readonly TEMP_DIR="$(mktemp -d /tmp/claude-ui-render.XXXXXX)"

cleanup() {
  /usr/bin/find "$TEMP_DIR" -depth -delete 2>/dev/null || true
}
trap cleanup EXIT

/usr/bin/sed '/^let application = NSApplication.shared$/,$d' \
  "$PROJECT_DIR/Sources/Launcher.swift" > "$TEMP_DIR/Launcher.swift"

/usr/bin/swiftc -D UI_RENDER_TEST -parse-as-library \
  -target arm64-apple-macos13.0 -framework AppKit \
  "$TEMP_DIR/Launcher.swift" "$PROJECT_DIR/tests/ui_render.swift" \
  -o "$TEMP_DIR/ui-render-test"

"$TEMP_DIR/ui-render-test"
