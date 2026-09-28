# CodeGuard

獨立的 macOS 桌面啟動器：檢查連線環境、選擇專案，再於 Apple「終端機」執行已安裝的官方 Claude Code CLI。

[English](README.md)

## 使用

1. 開啟 CodeGuard，查看每項檢查及未通過原因。
2. 選擇專案資料夾。
3. 通過檢查後，按「在終端機開啟 Claude Code」。終端機會重新檢查，通過才執行 CLI。
4. 登入、對話及工具批准均在原生 CLI 進行。

機房出口預設不通過。僅當完整信譽資料顯示只有 `hosting` 風險時，可由使用者確認承擔該出口及分數風險。此確認預設未選、只保存在 App 本輪記憶體，綁定本次 IP、地區、供應商、風險及查詢時間；出口或快照改變會失效。

## 檢查範圍

- **官方 CLI**：原生安裝 symlink 須指向使用者的版本目錄；核對檔案權限、嚴格程式碼簽章、`com.anthropic.claude-code` 及 Anthropic Team。
- **保護入口**：核對本機 launcher、process wrapper 及 sandbox profile 的擁有人、權限和模板 SHA-256。
- **出口**：Cloudflare 與 ipwho.is 須觀察到相同公網 IP／國家；使用 2026-09-29 的 185 個 Claude.ai 支援地區快照，並處理被排除的烏克蘭分區。
- **IP 信譽**：ProxyCheck 七項布林風險、risk／confidence、供應商與地理資料須齊全一致。任一風險或 risk > 25 預設阻擋。
- **時區／語言**：按核實出口產生 `TZ`、`LANG`、`LC_ALL` 啟動設定；不更改 Mac 系統設定。這是 CLI 的啟動環境，並非帳戶資格或所在地證明。
- **網絡探測**：在已核實 profile 下確認 IPv4、IPv6、UDP 直連受拒及指定代理可連線。結果只涵蓋該受控啟動路徑。
- **WebRTC／瀏覽器指紋**：純 CLI 不含這些瀏覽器介面，因此標示不適用；另行開啟的登入瀏覽器須獨立保護。

未知、缺漏、重複或未通過的必要檢查均阻止啟動。GUI 結果 60 秒後失效；終端機啟動時重新檢查，執行前再次核對 CLI 與保護檔案。

## 權限與資料

CodeGuard 不請求輔助使用、螢幕錄製、咪高峰、相機、自動化或完整磁碟存取。透過系統資料夾選擇器及 Launch Services 開啟終端機，無 Apple Events 控制。

這不代表 CLI 被限制只能讀所選專案：CLI 仍以目前使用者身分執行，能依自身批准設定讀寫檔案及執行命令。請保留 CLI 的權限提示。

- 不接管 Claude 登入、不讀取或轉送 token，不收集 CLI 輸入輸出或對話。
- 環境查詢經指定代理使用 Cloudflare、ipwho.is 及 ProxyCheck，這些服務會看到出口 IP。
- 信譽快取最多 30 分鐘，檔案權限 `0600`；每次檢查仍重新觀察出口。
- 每次交接只建立一份 `0700` 暫存 `.command`，以獨立參數保留專案路徑，執行時刪除自身。

## 官方使用邊界

CodeGuard 執行使用者已安裝、未修改的 Claude Code，不包含官方 binary、SDK 聊天介面、訂閱轉送服務或自家 OAuth 登入。所有內置驗證方式由原生 CLI 保留，用戶使用自己的帳戶及官方登入流程。

Anthropic 對產品中執行 Claude Code 訂有 Commercial Terms、原樣 binary、個別驗證及直接計費等條件；第三方不得自行收集或中介 Claude.ai 憑證。本專案沒有取得 Anthropic 背書，亦不宣稱合規認證或保證帳戶安全。使用及分發前須自行符合適用條款。

參考：[官方產品整合及認證規則](https://code.claude.com/docs/en/legal-and-compliance)、[官方網絡設定與 process wrapper](https://code.claude.com/docs/en/network-config)。

## 本機需求

- Apple silicon Mac、macOS 13+、Command Line Tools（`swiftc`、Python 3）。
- 官方原生 CLI：`~/.local/bin/claude` → `~/.local/share/claude/versions/…`。
- 已配置 `~/bin/claude`、`~/.local/share/claude-network-guard/claude-process-wrapper.zsh` 及 `claude-proxy-only.sb`，內容須符合 `Resources/CLIProtection.json`。
- 已有 `127.0.0.1:17897` HTTP 代理；上游須固定且沒有直接連線後備路徑。

目前版本沿用既有本機保護設定，未提供跨機自動配置器。缺少設定時會明確阻擋。

## 建置與驗證

```sh
./scripts/build.sh
./script/build_and_run.sh --verify
python3 -B -m unittest discover -s tests -v
./scripts/test-ui.sh
```

`build.sh` 產生 ad-hoc 簽署的 `dist/CodeGuard.app`；`build_and_run.sh` 更新 `/Applications/CodeGuard.app`，只保留上一版回退副本。Codex 的 Run 按鈕使用同一腳本。

## 防護限制

目前沒有已部署的 Network Extension 系統防火牆。直接執行原始 binary、另一個 Terminal、其他瀏覽器或由其他服務啟動的程序，不能視為受到此入口控制。代理與沙箱探測不等於完整故障情境驗收；網絡／帳戶服務仍可能拒絕連線。

真正系統層防火牆仍需獨立的 `NEFilterDataProvider`、可信政策讀回、獲授權團隊的簽署及公證，以及斷線、崩潰、更新、睡眠與直接啟動的實機驗收。

## 授權

[MIT](LICENSE)。環境檢查頁的基礎樣式沿用 [Claude Chrome](https://github.com/miku233333/claude-chrome) 的 MIT 資源。CodeGuard 使用獨立圖標及產品名稱。
