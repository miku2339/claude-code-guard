#!/bin/zsh
set -eu

readonly PROJECT_DIR="${0:A:h:h}"
readonly MODE="${1:-run}"
readonly TARGET_APP='/Applications/CodeGuard.app'
readonly LEGACY_APP='/Applications/claude-code-guard.app'
readonly BUNDLE_ID='local.claude.desktop-guard'
readonly BACKUP_APP="$PROJECT_DIR/dist/CodeGuard.app.latest-backup"
readonly TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/CodeGuard-install.XXXXXX")"

cleanup() {
  /usr/bin/find "$TEMP_DIR" -depth -delete 2>/dev/null || true
}
trap cleanup EXIT

case "$MODE" in
  run|--verify|--logs|--debug) ;;
  *) print -u2 '用法：./script/build_and_run.sh [--verify|--logs|--debug]'; exit 64 ;;
esac

for candidate in "$TARGET_APP" "$LEGACY_APP"; do
  if [[ -e "$candidate" ]]; then
    if [[ -L "$candidate" || "$(/usr/bin/plutil -extract CFBundleIdentifier raw "$candidate/Contents/Info.plist")" != "$BUNDLE_ID" ]]; then
      print -u2 "已有其他應用程式：$candidate"
      exit 73
    fi
  fi
done

CODEGUARD_OUTPUT_DIR="$TEMP_DIR/dist" /bin/zsh "$PROJECT_DIR/scripts/build.sh"
readonly BUILT_APP="$TEMP_DIR/dist/CodeGuard.app"
/usr/bin/codesign --verify --deep --strict "$BUILT_APP"

/usr/bin/pkill -TERM -x CodeGuard 2>/dev/null || true
/usr/bin/pkill -TERM -x ClaudeCodeGuard 2>/dev/null || true
for attempt in {1..30}; do
  if ! /usr/bin/pgrep -x 'CodeGuard|ClaudeCodeGuard' >/dev/null; then break; fi
  /bin/sleep 0.1
done
if /usr/bin/pgrep -x 'CodeGuard|ClaudeCodeGuard' >/dev/null; then
  print -u2 '現有 CodeGuard 尚未結束。'
  exit 75
fi

/bin/mkdir -p "$PROJECT_DIR/dist"
if [[ -e "$TARGET_APP" || -e "$LEGACY_APP" ]]; then
  if [[ -e "$BACKUP_APP" ]]; then /usr/bin/find "$BACKUP_APP" -depth -delete; fi
  if [[ -e "$TARGET_APP" ]]; then
    /usr/bin/ditto --norsrc --noextattr "$TARGET_APP" "$BACKUP_APP"
  else
    /usr/bin/ditto --norsrc --noextattr "$LEGACY_APP" "$BACKUP_APP"
  fi
fi
if [[ -e "$TARGET_APP" ]]; then /usr/bin/find "$TARGET_APP" -depth -delete; fi
/usr/bin/ditto --norsrc --noextattr "$BUILT_APP" "$TARGET_APP"
/usr/bin/codesign --verify --deep --strict "$TARGET_APP"
if [[ -e "$LEGACY_APP" ]]; then /usr/bin/find "$LEGACY_APP" -depth -delete; fi

case "$MODE" in
  --debug) /usr/bin/lldb "$TARGET_APP/Contents/MacOS/CodeGuard" ;;
  --logs)
    /usr/bin/open "$TARGET_APP"
    /usr/bin/log stream --info --style compact --predicate 'process == "CodeGuard"'
    ;;
  *)
    /usr/bin/open "$TARGET_APP"
    if [[ "$MODE" == '--verify' ]]; then
      /bin/sleep 1
      /usr/bin/pgrep -x CodeGuard >/dev/null
      print 'CodeGuard 已安裝及啟動。'
    fi
    ;;
esac
