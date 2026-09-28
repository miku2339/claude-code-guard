# Claude Desktop Guard

> **ALPHA — 診斷式啟動閘門原型**

Claude Desktop Guard 是獨立的 macOS 原型，在提供啟動官方 Claude Desktop 前，檢查一組範圍明確的本機條件。現時系統會**刻意保持鎖定**：自建系統防火牆尚未實作或部署，macOS TCC 授權亦未能核實，因此目前版本不會啟用「啟動 Claude」按鈕。

本專案獨立於 Anthropic。目前提供環境診斷；系統層網絡封鎖仍未完成。

[English](README.md)

## 目前檢查

- 按目前釘選的官方身分核實暫存及已安裝 App：bundle ID `com.anthropic.claudefordesktop`、Team ID `Q6L2SF6YDW`、版本 `2.9939.4`、嚴格程式碼簽章及 Gatekeeper 評估。
- 要求設定於 `127.0.0.1:17897` 的 HTTP loopback proxy，並檢查其公開出口位於日本、時區顯示 `Asia/Tokyo`，以及 App 採用所選的英文偏好設定。
- 透過 Cloudflare Trace 及 ipwho.is 交叉核對公開出口。
- 套用本專案自訂的保守 ProxyCheck 規則：`hosting`、`proxy`、`vpn`、`tor`、`compromised`、`scraper` 或 `anonymous` 任一標記成立，或 risk 高於 25，均會鎖定啟動。這是本機自訂政策，並非 Anthropic 官方允許名單或批准結果。
- 在指定 `sandbox-exec` profile 內探測 IPv4、IPv6、UDP 及 loopback proxy。結果只涵蓋受保護的 CLI 探測程序，不代表 Claude Desktop 已經實測或受到完整限制。
- 從官方 App 的 `Info.plist` 及程式碼簽章 entitlement 列出權限申報。權限申報不代表 macOS 已經授權；目前 TCC 授權狀態仍屬未知。
- 任一必要項目失敗或未知都會鎖定啟動；檢查結果 60 秒後失效。

## 目前安全邊界

啟動器會以本機 `sandbox-exec` profile 直接啟動已核實的 Claude 執行檔。這只涵蓋經此受保護路徑啟動的程序。直接開啟官方 App、Finder、Dock、Launch Services、URL scheme、login item 及官方 updater 均不受本原型控制。

自建 Network Extension 防火牆仍在規劃，尚未實作、簽署、批准、安裝或測試。受 macOS 支援的部署需要付費 Apple Developer Team、合適的 Developer ID 簽署與 provisioning、Network Extension 及 System Extension entitlement、公證，以及用戶批准 System Extension 和 Network Filter。本專案不需要亦不建議關閉 System Integrity Protection。

## 建置

需求：

- Apple silicon Mac，macOS 13 或以上
- 包含 `/usr/bin/swiftc` 的 Command Line Tools
- AppKit
- `/usr/bin/python3`

建置本機 App：

```sh
./scripts/build.sh
```

腳本會編譯 arm64 AppKit App，並把 ad-hoc 簽署的結果放於 `dist/Claude 啟動檢查.app`。此 ad-hoc 簽章只供本機啟動閘門使用，不能提供 Network Extension 防火牆所需的受限制 entitlement。

執行測試：

```sh
python3 -B -m unittest discover -s tests -v
```

## 本機設定

目前原型預期：

- 官方暫存 App：`$HOME/Library/Application Support/Claude Desktop Guard/Staging/Claude.app`
- 官方已安裝 App：`/Applications/Claude.app`
- Sandbox profile：`$HOME/.local/share/claude-network-guard/claude-proxy-only.sb`
- HTTP proxy：`127.0.0.1:17897`

這些 home-relative 路徑只描述本機設定；本儲存庫不包含相關私人用戶資料。

## 私隱

網絡檢查會向三個外部服務披露 proxy 所觀察到的公開出口 IP：Cloudflare、ipwho.is 及 ProxyCheck。這些服務可能按各自政策處理請求。

Guard 不會收集或傳送 Claude 帳戶、API key、驗證 token 或聊天內容。本源碼儲存庫亦不包含官方 Claude App 或其下載快取。

## 限制

- 目前沒有已實作的 OS 層規則，強制每個 Claude Desktop 啟動方式或 helper 程序只經 `127.0.0.1:17897`。
- Sandbox 探測只為其受保護探測程序提供診斷證據，並非 Desktop 全域強制的證明。
- 目前未能讀回 TCC 授權，故狀態維持未知並鎖定啟動。
- App 身分及版本已釘選；官方 App 更新後需要重新審核。
- 外部地理位置及信譽服務可能無法使用、互相矛盾或判斷錯誤；未知結果會鎖定啟動。
- 日本出口 IP 不能證明居住地、帳戶資格、合約合規或任何服務使用許可。正常運作仍取決於官方 App 的要求及用戶本身資格。

## 授權

[MIT](LICENSE)
