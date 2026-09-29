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
    const choosing = state.projectChoosing === true;
    const context = response.exitContext;
    const get = (id) => checks.get(id) || { status: busy ? "checking" : "unknown", detail: busy ? "正在檢查…" : "尚未取得有效檢查結果。" };
    const exit = get("proxy_exit");
    const location = get("exit_location");
    const networkPass = exit.status === "pass" && location.status === "pass";
    const network = networkPass ? { status: "pass", detail: `${context?.country || ""}・${context?.ip || ""}・地區受支援` } : location.status === "pass" ? exit : location;
    const reputation = get("exit_reputation");
    const accepted = state.riskAccepted === true;
    const timezone = get("cli_timezone");
    const language = get("cli_language");
    const riskDetail = reputation.detail.replaceAll("hosting", "機房出口").replaceAll("risk ", "ProxyCheck 風險值 ");
    const items = [
      row("network", "網絡出口", network.status, network.detail),
      row("reputation", "IP 信譽", accepted ? "info" : reputation.status, riskDetail, accepted ? "已確認風險" : undefined),
      row("timezone", "CLI 啟動時區", timezone.status, timezone.detail),
      row("webrtc", "WebRTC 與瀏覽器指紋", "info", "純 CLI 不含瀏覽器；登入由 Claude Chrome 另行檢查瀏覽器環境。", "不適用"),
      row("language", "CLI 啟動語言", language.status, language.detail),
      row("process", "受保護啟動入口", get("process_guard").status, get("process_guard").detail),
    ];
    byId("environment-checks").replaceChildren(...items);
    const installed = get("installed_cli");
    const sandbox = get("network_sandbox");
    byId("desktop-checks").replaceChildren(
      row("official-cli", "官方 CLI 身分", installed.status, installed.detail),
      row("sandbox", "直連阻擋探測", sandbox.status, sandbox.detail),
    );
    const protectionBlockers = [installed, sandbox].filter((check) => check.status !== "pass").length;
    byId("desktop-summary").textContent = busy ? "CLI 與連線防護・檢查中" : `CLI 與連線防護・${protectionBlockers ? `${protectionBlockers} 項未通過` : "通過"}`;
    document.querySelector(".summary").dataset.state = busy ? "checking" : state.checksPassed || state.launched ? "pass" : "fail";
    byId("overall-title").textContent = busy ? "正在檢查" : state.error ? "檢查未完成" : state.launched ? "已交到終端機" : state.checksPassed ? "啟動檢查通過" : "環境檢查未通過";
    byId("overall-detail").textContent = busy ? "請稍候完成所有必要檢查。" : state.error || (state.launched ? "終端機會再次檢查，再交由 CLI 繼續。" : state.blockers?.length ? `未通過：${state.blockers.join("、")}。` : state.checksPassed ? state.projectPath ? "準備在所選專案啟動。" : "選擇專案資料夾後繼續。" : "請重新檢查後再繼續。");
    byId("project-path").textContent = state.projectPath || "尚未選擇";
    byId("project-button").textContent = state.projectPath ? "更換專案" : "選擇專案";
    byId("project-button").disabled = busy || choosing;
    const acknowledgement = response.hostingAcknowledgement;
    const eligible = acknowledgement?.eligible === true && !!acknowledgement.snapshotKey;
    byId("risk-acceptance").hidden = !eligible;
    byId("risk-acceptance-checkbox").checked = accepted;
    byId("risk-acceptance-checkbox").disabled = busy || choosing || !eligible;
    byId("risk-acceptance-status").textContent = (accepted ? "已接受目前機房 IP 風險・" : "") + (acknowledgement?.detail || "");
    byId("continue-button").disabled = busy || choosing || state.canLaunch !== true;
    byId("retry-button").disabled = busy || choosing;

  }

  window.guardUI = Object.freeze({ update: render });
  byId("project-button").addEventListener("click", () => send("chooseProject"));
  byId("retry-button").addEventListener("click", () => send("check"));
  byId("continue-button").addEventListener("click", () => { if (latest?.canLaunch && !latest.busy) send("launch"); });
  byId("risk-acceptance-checkbox").addEventListener("change", (event) => send("risk", { accepted: event.target.checked }));
  render({ busy: true, canLaunch: false, blockers: [] });
  send("ready");
})();
