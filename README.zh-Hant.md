# claude-code-guard

> **ALPHA — 診斷式啟動閘門原型**

claude-code-guard 是獨立的 macOS 原型，在提供啟動官方 Claude Desktop 前，檢查一組範圍明確的本機條件。現時系統會**刻意保持鎖定**：自建系統防火牆尚未實作或部署，macOS TCC 授權亦未能核實，因此目前版本不會啟用「啟動 Claude」按鈕。

本專案獨立於 Anthropic。目前提供環境診斷；系統層網絡封鎖仍未完成。

[English](README.md)

## 目前檢查

- 按目前釘選的官方身分核實暫存及已安裝 App：bundle ID `com.anthropic.claudefordesktop`、Team ID `Q6L2SF6YDW`、版本 `2.9939.4`、嚴格程式碼簽章及 Gatekeeper 評估。
- 要求設定於 `127.0.0.1:17897` 的 HTTP loopback proxy。Cloudflare Trace 與 ipwho.is 必須回報相同即時公網 IP／國家，並符合 2026-09-29 的 185 個 Claude.ai 支援國家快照。烏克蘭被排除分區仍會封鎖，缺少分區資料則為未知。
- 核對出口時區與 UTC offset、系統時區，以及與 [Claude Chrome](https://github.com/miku233333/claude-chrome) 相同的國家語言順序。日本預期 `Asia/Tokyo` 與 `ja-JP,ja`。`EnvironmentPolicy.json` 內置地區快照及 macOS Foundation 語言對照；App 偏好設定讀回不代表已量測官方 App 的執行時數值。
- 採用與 Claude Chrome 相同的 ProxyCheck 門檻：七項風險布林值、risk／confidence、供應商及一致地理資料須齊全。任一風險成立或 risk 高於 25，預設均未通過。只有 `hosting` 為 true、其餘六項明確為 false 的完整快照，才可確認承擔機房出口及風險分數。確認預設未選、只存本次 App 記憶體，綁定 IP、地區、時區、供應商、分數、風險與評估時間；不接受缺漏、矛盾或其他風險。這是本機政策，並非 Anthropic 批准結果。
- 相同出口及地理資料的有效信譽回應會私下快取最多 30 分鐘；快照更新或改變即清除之前的確認。每次檢查仍會經兩個服務重新觀察目前出口。
- 在指定 `sandbox-exec` profile 內探測 IPv4、IPv6、UDP 及 loopback proxy。結果只涵蓋受保護的 CLI 探測程序，不代表 Claude Desktop 已經實測或受到完整限制。
- 從官方 App 的 `Info.plist` 及程式碼簽章 entitlement 列出權限申報。權限申報不代表 macOS 已經授權；目前 TCC 授權狀態仍屬未知。
- 沿用 Claude Chrome 的環境檢查卡片；頂部列出未通過項目，桌面防護與權限可展開查看。WebRTC、Canvas、WebGL 等瀏覽器項目明示尚未在官方桌面 App 內量測，不把 Chrome 結果當成桌面 App 證據。
- 任一必要項目失敗或未知都會鎖定啟動；檢查結果 60 秒後失效。

## 目前安全邊界

目前鎖定的啟動路徑會使用本機 `sandbox-exec` profile，限制經該路徑啟動的程序。直接開啟官方 App、Finder、Dock、Launch Services、URL scheme、login item 及官方 updater 均不受本原型控制。

自建 Network Extension 防火牆仍在規劃，尚未實作、簽署、批准、安裝或測試。受 macOS 支援的部署需要付費 Apple Developer Team、合適的 Developer ID 簽署與 provisioning、Network Extension 及 System Extension entitlement、公證，以及用戶批准 System Extension 和 Network Filter。本專案不需要亦不建議關閉 System Integrity Protection。

## 系統防火牆完成路徑

1. 加入 `NEFilterDataProvider` System Extension，按已核實的 Claude 主程序及 helper 簽章辨識流量，只允許指定本機代理；代理本身固定出口且沒有直連後備路徑。Content Filter 只作放行／封鎖，代理設定仍須由啟動器提供。
2. 加入經簽章驗證的狀態通道，讀回已載入政策、有效程序身分及實際封鎖探測結果。網絡檢查與相機、咪高峰等權限審核須各自呈現。
3. 由獲授權的開發者團隊提供 Developer ID、對應 provisioning profile 及公證成品，在 SIP 開啟的 Mac 安裝並完成系統批准。一般 Content Filter entitlement 可由付費團隊啟用，免費 Personal Team 不具備所需能力。
4. 實測代理中斷、provider 異常、睡眠喚醒、重啟、更新及各種直接啟動方式的新舊連線。Shell 子程序、系統代送 DNS 及 Cowork VM 須另行驗證流量歸屬，未覆蓋前不能宣稱全域防護。

參考：[Apple Content Filter](https://developer.apple.com/documentation/networkextension/nefilterdataprovider)、[Developer ID Network Extension](https://developer.apple.com/forums/thread/737894)、[Network Extension 簽章資格](https://developer.apple.com/forums/thread/814047)。

## 建置

需求：

- Apple silicon Mac，macOS 13 或以上
- 包含 `/usr/bin/swiftc` 的 Command Line Tools
- AppKit 及 WebKit
- `/usr/bin/python3`

建置本機 App：

```sh
./scripts/build.sh
```

腳本會編譯 arm64 AppKit／WKWebView App，並把 ad-hoc 簽署的結果放於 `dist/claude-code-guard.app`。此 ad-hoc 簽章只供本機啟動閘門使用，不能提供 Network Extension 防火牆所需的受限制 entitlement。

執行測試：

```sh
python3 -B -m unittest discover -s tests -v
./scripts/test-ui.sh
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

Guard 不會收集或傳送 Claude 帳戶、API key、驗證 token 或聊天內容。本機信譽快取包含出口 IP 及供應商回應，檔案權限為 `0600`。本源碼儲存庫不包含該快取、官方 Claude App 或其下載快取。

## 限制

- 目前沒有已實作的 OS 層規則，強制每個 Claude Desktop 啟動方式或 helper 程序只經 `127.0.0.1:17897`。
- Sandbox 探測只為其受保護探測程序提供診斷證據，並非 Desktop 全域強制的證明。
- 目前未能讀回 TCC 授權，故狀態維持未知並鎖定啟動。
- App 身分及版本已釘選；官方 App 更新後需要重新審核。
- 外部地理位置及信譽服務可能無法使用、互相矛盾或判斷錯誤；未知結果會鎖定啟動。
- 日本出口 IP 不能證明居住地、帳戶資格、合約合規或任何服務使用許可。正常運作仍取決於官方 App 的要求及用戶本身資格。

## 授權

[MIT](LICENSE)
