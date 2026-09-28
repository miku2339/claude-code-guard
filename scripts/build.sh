#!/bin/zsh
set -eu

readonly PROJECT_DIR="${0:A:h:h}"
readonly SOURCE_FILE="$PROJECT_DIR/Sources/Launcher.swift"
readonly RESOURCE_DIR="$PROJECT_DIR/Resources"
readonly DIST_DIR="$PROJECT_DIR/dist"
readonly OUTPUT_APP="$DIST_DIR/claude-code-guard.app"
readonly BACKUP_APP="$DIST_DIR/claude-code-guard.app.latest-backup"
readonly STAGING_DIR="$(mktemp -d "${TMPDIR:-/tmp}/claude-code-guard-build.XXXXXX")"
readonly STAGING_APP="$STAGING_DIR/claude-code-guard.app"
readonly EXECUTABLE_NAME="ClaudeCodeGuard"

cleanup() {
  /usr/bin/find "$STAGING_DIR" -depth -delete 2>/dev/null || true
}
trap cleanup EXIT

if [[ ! -f "$SOURCE_FILE" || -L "$SOURCE_FILE" ]]; then
  print -u2 '缺少 Sources/Launcher.swift。'
  exit 66
fi
if [[ ! -f "$RESOURCE_DIR/Info.plist" || -L "$RESOURCE_DIR/Info.plist" ]]; then
  print -u2 '缺少 Resources/Info.plist。'
  exit 66
fi

/bin/mkdir -p "$DIST_DIR" "$STAGING_APP/Contents/MacOS" "$STAGING_APP/Contents/Resources"
/bin/cp "$RESOURCE_DIR/Info.plist" "$STAGING_APP/Contents/Info.plist"
/bin/cp "$PROJECT_DIR/LICENSE" "$STAGING_APP/Contents/Resources/LICENSE"

if [[ ! -f "$RESOURCE_DIR/guard.py" || -L "$RESOURCE_DIR/guard.py" ]]; then
  print -u2 '缺少有效的 Resources/guard.py。'
  exit 66
fi
/bin/cp "$RESOURCE_DIR/guard.py" "$STAGING_APP/Contents/Resources/guard.py"
/bin/cp "$RESOURCE_DIR/EnvironmentPolicy.json" "$STAGING_APP/Contents/Resources/EnvironmentPolicy.json"

for asset in Guard.html Guard.css Guard.js Logo.png; do
  /bin/cp "$RESOURCE_DIR/$asset" "$STAGING_APP/Contents/Resources/$asset"
done

/usr/bin/swiftc -O -target arm64-apple-macos13.0 -framework AppKit -framework WebKit \
  "$SOURCE_FILE" \
  -o "$STAGING_APP/Contents/MacOS/$EXECUTABLE_NAME"

/usr/bin/plutil -lint "$STAGING_APP/Contents/Info.plist"

if [[ -e "$BACKUP_APP" ]]; then
  /usr/bin/find "$BACKUP_APP" -depth -delete
fi
if [[ -e "$OUTPUT_APP" ]]; then
  /bin/mv "$OUTPUT_APP" "$BACKUP_APP"
fi
/bin/mv "$STAGING_APP" "$OUTPUT_APP"

/usr/bin/xattr -cr "$OUTPUT_APP"
/usr/bin/codesign --force --sign - --timestamp=none "$OUTPUT_APP"
/usr/bin/xattr -cr "$OUTPUT_APP"
/usr/bin/codesign --verify --deep --strict "$OUTPUT_APP"
/usr/bin/file "$OUTPUT_APP/Contents/MacOS/$EXECUTABLE_NAME"
print "已建置：$OUTPUT_APP"
