(() => {
  "use strict";
  const byId = (id) => document.getElementById(id);
  const stateLabels = { pass: "通過", fail: "未通過", unknown: "未確認", info: "資訊", checking: "檢查中" };
  let latest = null;

  function send(action, extra = {}) {
    window.webkit?.messageHandlers?.guard?.postMessage({ action, ...extra });
  }

  function row(id, title, state, detail, label) {
    const article = document.createElement("article");
    article.className = "check-row";
    article.id = `${id}-row`;
    article.dataset.state = state;
    const copy = document.createElement("div");
    const heading = document.createElement("h2");
    heading.textContent = title;
    const description = document.createElement("p");
    description.id = `${id}-detail`;
    description.textContent = detail;
    copy.append(heading, description);
    const badge = document.createElement("span");
    badge.className = "status";
    badge.id = `${id}-status`;
    badge.textContent = label || stateLabels[state] || "未確認";
    article.append(copy, badge);
    return article;
  }

  function render(state) {
    latest = state;
    const response = state.response || {};
    const checks = new Map((response.checks || []).map((check) => [check.id, check]));
    const busy = state.busy === true;
    const context = response.exitContext;
    const get = (id) => checks.get(id) || { status: busy ? "checking" : "unknown", detail: busy ? "正在檢查…" : "尚未取得有效檢查結果。" };
    const exit = get("proxy_exit");
    const location = get("exit_location");
    const networkPass = exit.status === "pass" && location.status === "pass";
    const network = networkPass ? { status: "pass", detail: `${context?.country || ""}・${context?.ip || ""}・地區受支援` } : location.status === "pass" ? exit : location;
    const reputation = get("exit_reputation");
    const accepted = state.riskAccepted === true;
    const timezone = get("system_timezone");
    const language = get("app_language");
    const offset = context?.utcOffset;
    const utc = Number.isInteger(offset) ? `UTC${offset < 0 ? "−" : "+"}${String(Math.floor(Math.abs(offset) / 3600)).padStart(2, "0")}:${String(Math.floor(Math.abs(offset) % 3600 / 60)).padStart(2, "0")}` : "";
    const timezoneDetail = timezone.status === "pass" && context?.timeZone ? `${context.timeZone}・${utc}・與出口一致` : timezone.detail;
    const riskDetail = reputation.detail.replaceAll("hosting", "機房出口").replaceAll("risk ", "ProxyCheck 風險值 ");
    const items = [
      row("network", "網絡出口", network.status, network.detail),
      row("reputation", "IP 信譽", accepted ? "info" : reputation.status, riskDetail, accepted ? "已確認風險" : undefined),
      row("timezone", "出口與系統時區", timezone.status, timezoneDetail),
      row("webrtc", "WebRTC", "info", context?.ip ? `核對出口 ${context.ip}；官方桌面 App 尚未量測額外公網 IP 或非代理 UDP。` : "尚未核實出口 IP；官方桌面 App 尚未量測。", "未量測"),
      row("language", "出口與 App 語言", language.status, language.detail),
      row("fingerprint", "App 環境一致性", "info", "官方桌面 App 的 Canvas、WebGL 與執行環境尚未量測。", "未量測"),
    ];
    byId("environment-checks").replaceChildren(...items);
    const installed = get("installed_app");
    byId("desktop-checks").replaceChildren(
      row("official-app", "官方 Claude App", installed.status === "info" ? "unknown" : installed.status, installed.detail, installed.status === "info" ? "未安裝" : undefined),
      row("firewall", "系統防火牆", get("os_firewall").status, get("os_firewall").detail),
      row("sandbox", "網絡沙箱", get("network_sandbox").status, get("network_sandbox").detail),
      row("permissions", "macOS 權限狀態", get("tcc_authorization").status, get("tcc_authorization").detail),
    );
    const desktopBlockers = [installed, get("os_firewall"), get("network_sandbox"), get("tcc_authorization")].filter((check) => check.status !== "pass").length;
    byId("desktop-summary").textContent = busy ? "桌面防護・檢查中" : `桌面防護・${desktopBlockers ? `${desktopBlockers} 項未通過` : "通過"}`;
    document.querySelector(".summary").dataset.state = busy ? "checking" : state.canLaunch || state.launched ? "pass" : "fail";
    byId("overall-title").textContent = busy ? "正在檢查" : state.error ? "檢查未完成" : state.launched ? "Claude 已啟動" : state.canLaunch ? "環境檢查通過" : "環境檢查未通過";
    byId("overall-detail").textContent = busy ? "請稍候完成所有必要檢查。" : state.error || (state.launched ? "已完成本次啟動檢查。" : state.blockers?.length ? `未通過：${state.blockers.join("、")}。` : state.canLaunch ? "可以開啟 Claude。" : "請重新檢查後再繼續。");
    const acknowledgement = response.hostingAcknowledgement;
    const eligible = acknowledgement?.eligible === true && !!acknowledgement.snapshotKey;
    byId("risk-acceptance").hidden = !eligible;
    byId("risk-acceptance-checkbox").checked = accepted;
    byId("risk-acceptance-checkbox").disabled = busy || !eligible;
    byId("risk-acceptance-status").textContent = (accepted ? "已接受目前機房 IP 風險・" : "") + (acknowledgement?.detail || "");
    byId("continue-button").disabled = busy || state.canLaunch !== true;
    byId("retry-button").disabled = busy;
    byId("permissions-list").replaceChildren(...(response.permissions || []).map((permission) => {
      const item = document.createElement("div");
      item.className = "permission";
      const name = document.createElement("strong");
      name.textContent = permission.name;
      item.append(name, document.createTextNode(permission.detail));
      return item;
    }));
  }

  window.guardUI = Object.freeze({ update: render });
  byId("retry-button").addEventListener("click", () => send("check"));
  byId("continue-button").addEventListener("click", () => { if (latest?.canLaunch && !latest.busy) send("launch"); });
  byId("risk-acceptance-checkbox").addEventListener("change", (event) => send("risk", { accepted: event.target.checked }));
  render({ busy: true, canLaunch: false, blockers: [] });
  send("ready");
})();
