(function () {
  "use strict";

  const state = {
    repos: [],
    scans: [],
    githubRepos: [],
    user: null,
  };

  const secretTypes = [
    ["AWS Access Key", "aws"],
    ["GitHub PAT", "github"],
    ["Stripe Key", "stripe"],
    ["MongoDB URI", "mongodb"],
    ["SSH Private Key", "ssh"],
    ["JWT Token", "jwt"],
    ["Slack Token", "slack"],
    ["Twilio Key", "twilio"],
  ];

  function $(id) {
    return document.getElementById(id);
  }

  async function request(path, options = {}) {
    const response = await fetch(path, {
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      ...options,
    });
    const text = await response.text();
    let data = null;
    if (text) {
      try { data = JSON.parse(text); } catch { data = { message: text }; }
    }
    if (!response.ok) {
      throw new Error((data && (data.detail || data.message)) || response.statusText);
    }
    return data || {};
  }

  function toast(message, type = "info") {
    const container = $("toast-container");
    if (!container) return;
    const el = document.createElement("div");
    el.className = `toast ${type}`;
    el.textContent = message;
    container.appendChild(el);
    setTimeout(() => el.remove(), 4200);
  }

  function text(parent, value) {
    parent.textContent = value == null ? "" : String(value);
    return parent;
  }

  function el(tag, className, value) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (value !== undefined) text(node, value);
    return node;
  }

  function timeAgo(iso) {
    if (!iso) return "never";
    const date = new Date(iso);
    if (Number.isNaN(date.getTime())) return "unknown";
    const diff = Math.max(0, (Date.now() - date.getTime()) / 1000);
    if (diff < 60) return "just now";
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 86400)}d ago`;
  }

  function repoStatus(repo) {
    const scan = repo.last_scan;
    if (!scan || !scan.total_findings) return "safe";
    if ((scan.critical || 0) > 0) return "crit";
    return "warn";
  }

  function repoTag(repo) {
    const scan = repo.last_scan;
    if (!scan) return ["safe", "not scanned"];
    if (!scan.total_findings) return ["safe", "clean"];
    if (scan.critical) return ["crit", `${scan.critical} critical`];
    if (scan.high) return ["warn", `${scan.high} high`];
    return ["warn", `${scan.total_findings} finding${scan.total_findings === 1 ? "" : "s"}`];
  }

  function ownerAndName(repo) {
    const name = repo.name || "";
    if (name.includes("/")) {
      const parts = name.split("/");
      return [`${parts.slice(0, -1).join(" / ")} /`, parts[parts.length - 1]];
    }
    try {
      const url = new URL(repo.url || "");
      const parts = url.pathname.replace(/\.git$/, "").split("/").filter(Boolean);
      if (parts.length >= 2) return [`${parts[0]} /`, parts[1]];
    } catch {}
    return ["", name || "repository"];
  }

  function latestScanTime() {
    const latest = state.scans
      .map((scan) => scan.created_at)
      .filter(Boolean)
      .sort()
      .pop();
    return latest ? timeAgo(latest) : "never";
  }

  function totals() {
    const totalFindings = state.scans.reduce((sum, scan) => sum + (scan.total_findings || 0), 0);
    const critical = state.scans.reduce((sum, scan) => sum + (scan.critical || 0), 0);
    const high = state.scans.reduce((sum, scan) => sum + (scan.high || 0), 0);
    const clean = state.repos.filter((repo) => !repo.last_scan || !(repo.last_scan.total_findings || 0)).length;
    return { totalFindings, critical, high, clean };
  }

  function renderMetrics() {
    const t = totals();
    const scanned = state.repos.filter((repo) => repo.last_scan).length;
    const healthyPct = state.repos.length ? Math.round((t.clean / state.repos.length) * 100) : 0;
    text($("metric-repos"), scanned);
    text($("metric-repos-sub"), `${state.repos.length} monitored`);
    text($("metric-findings"), t.totalFindings);
    text($("metric-findings-sub"), `${t.critical} critical`);
    text($("metric-high"), t.high);
    text($("metric-clean"), t.clean);
    text($("metric-clean-sub"), `${healthyPct}% healthy`);
    text($("repo-nav-count"), state.repos.length);
    text($("alert-nav-count"), t.totalFindings);
    text($("last-scan-time"), `last scan: ${latestScanTime()}`);
  }

  function renderRepos() {
    const list = $("repo-list");
    list.innerHTML = "";
    if (!state.repos.length) {
      list.appendChild(el("div", "empty", "No repositories yet. Add one to start monitoring."));
      return;
    }

    state.repos.forEach((repo) => {
      const card = el("article", "repo-card");
      card.dataset.repoId = repo.id;

      card.appendChild(el("div", `repo-status ${repoStatus(repo)}`));

      const name = el("div", "repo-name");
      const [owner, repoName] = ownerAndName(repo);
      const ownerNode = el("span", "", owner);
      name.appendChild(ownerNode);
      name.appendChild(document.createTextNode(` ${repoName}`));
      name.title = repo.url || repo.name || "";
      card.appendChild(name);

      card.appendChild(el("div", "repo-meta", repo.last_scan ? timeAgo(repo.last_scan.created_at) : "not scanned"));

      const [tagClass, tagText] = repoTag(repo);
      card.appendChild(el("div", `repo-tag ${tagClass}`, tagText));

      const actions = el("div", "repo-actions");
      const scan = el("button", "mini-btn", "scan");
      scan.type = "button";
      scan.addEventListener("click", () => scanRepo(repo));
      const details = el("a", "mini-btn", "details");
      details.href = `/repo/${encodeURIComponent(repo.id)}`;
      const remove = el("button", "mini-btn danger", "remove");
      remove.type = "button";
      remove.addEventListener("click", () => removeRepo(repo));
      actions.append(scan, details, remove);
      card.appendChild(actions);

      list.appendChild(card);
    });
  }

  function renderAlerts() {
    const list = $("alert-list");
    list.innerHTML = "";

    const findings = [];
    state.scans.forEach((scan) => {
      (scan.findings || []).forEach((finding) => {
        findings.push({ scan, finding });
      });
    });

    if (!findings.length) {
      list.appendChild(el("div", "empty", "No findings yet. Run a scan to build the audit trail."));
      return;
    }

    findings.slice(0, 12).forEach(({ scan, finding }) => {
      const severity = (finding.severity || "MEDIUM").toUpperCase();
      const color = severity === "CRITICAL" ? "red" : severity === "HIGH" ? "amber" : "green";
      const item = el("article", "alert-item");
      item.appendChild(el("div", `alert-dot ${color}`));
      const msg = el("div", "alert-msg");
      text(msg, `${severity}: ${finding.description || finding.rule_id || "Secret-like value detected"}`);
      const meta = el("small", "", `${scan.repo_name || "repository"} / ${finding.file || "unknown file"}:${finding.line || "?"}`);
      msg.appendChild(meta);
      item.appendChild(msg);
      item.appendChild(el("div", "alert-time", timeAgo(scan.created_at)));
      list.appendChild(item);
    });
  }

  function renderCoverage() {
    const list = $("coverage-list");
    list.innerHTML = "";
    const scanned = state.repos.filter((repo) => repo.last_scan).length;
    const repoPct = state.repos.length ? Math.round((scanned / state.repos.length) * 100) : 0;
    const rows = [
      ["GitHub repos", repoPct, `${scanned}/${state.repos.length}`, repoPct >= 80 ? "green" : "amber"],
      ["Webhook scans", state.scans.some((scan) => scan.triggered_by === "webhook") ? 100 : 0, state.scans.some((scan) => scan.triggered_by === "webhook") ? "active" : "idle", "blue"],
      ["Manual scans", state.scans.some((scan) => scan.triggered_by === "manual") ? 100 : 0, state.scans.some((scan) => scan.triggered_by === "manual") ? "active" : "idle", "green"],
      ["Scheduled scans", state.scans.some((scan) => scan.triggered_by === "scheduled") ? 100 : 0, state.scans.some((scan) => scan.triggered_by === "scheduled") ? "active" : "idle", "amber"],
    ];

    rows.forEach(([label, pct, caption, color]) => {
      const row = el("div", "coverage-row");
      row.appendChild(el("div", "coverage-label", label));
      const bar = el("div", "coverage-bar");
      const fill = el("div", `coverage-fill ${color}`);
      fill.style.width = `${Math.max(0, Math.min(100, pct))}%`;
      bar.appendChild(fill);
      row.appendChild(bar);
      row.appendChild(el("div", "coverage-pct", caption));
      list.appendChild(row);
    });
  }

  function renderDetectedTypes() {
    const list = $("detected-list");
    list.innerHTML = "";
    const counts = new Map();
    state.scans.forEach((scan) => {
      (scan.findings || []).forEach((finding) => {
        const haystack = `${finding.rule_id || ""} ${finding.description || ""}`.toLowerCase();
        secretTypes.forEach(([, key]) => {
          if (haystack.includes(key)) counts.set(key, (counts.get(key) || 0) + 1);
        });
      });
    });

    secretTypes.forEach(([label, key]) => {
      const count = counts.get(key) || 0;
      const item = el("div", "detected-item");
      item.appendChild(el("span", "detected-name", label));
      item.appendChild(el("span", `detected-count ${count ? "" : "zero"}`, count));
      list.appendChild(item);
    });
  }

  function renderAll() {
    renderMetrics();
    renderRepos();
    renderAlerts();
    renderCoverage();
    renderDetectedTypes();
  }

  async function loadDashboard() {
    try {
      const auth = await request("/auth/me");
      if (!auth.authenticated) {
        window.location.href = "/";
        return;
      }
      state.user = auth;
      text($("avatar"), (auth.login || "U").slice(0, 1).toUpperCase());
    } catch {
      window.location.href = "/";
      return;
    }

    try {
      const [reposData, dashboardData] = await Promise.all([
        request("/api/repos"),
        request("/api/dashboard"),
      ]);
      state.repos = reposData.repos || [];
      state.scans = dashboardData.scans || [];
      renderAll();
    } catch (error) {
      toast(error.message, "error");
    }
  }

  async function addRepoFromUrl() {
    const url = $("repo-url-input").value.trim();
    const branch = $("repo-branch-input").value.trim() || "main";
    if (!url) {
      toast("Enter a repo URL", "error");
      return;
    }
    try {
      const data = await request("/api/repos", {
        method: "POST",
        body: JSON.stringify({ url, branch }),
      });
      toast(data.message || "Repository added", "success");
      $("repo-url-input").value = "";
      await loadDashboard();
    } catch (error) {
      toast(error.message, "error");
    }
  }

  async function loadGitHubRepos() {
    try {
      const data = await request("/api/github/repos");
      state.githubRepos = data.repos || [];
      $("github-picker").hidden = false;
      renderGitHubRepos(state.githubRepos);
    } catch (error) {
      toast(error.message, "error");
    }
  }

  function renderGitHubRepos(repos) {
    const list = $("github-repos-items");
    list.innerHTML = "";
    if (!repos.length) {
      list.appendChild(el("div", "empty", "No repositories matched."));
      return;
    }
    repos.slice(0, 50).forEach((repo) => {
      const row = el("div", "github-row");
      const info = el("div");
      info.appendChild(el("div", "repo-name", repo.name || "repository"));
      info.appendChild(el("div", "repo-meta", `${repo.private ? "private" : "public"} / ${repo.default_branch || "main"}`));
      const button = el("button", "mini-btn", "add");
      button.type = "button";
      button.addEventListener("click", () => addGitHubRepo(repo));
      row.append(info, button);
      list.appendChild(row);
    });
  }

  function filterGitHubRepos() {
    const query = $("github-search").value.trim().toLowerCase();
    renderGitHubRepos(state.githubRepos.filter((repo) => (repo.name || "").toLowerCase().includes(query)));
  }

  async function addGitHubRepo(repo) {
    try {
      const data = await request("/api/repos", {
        method: "POST",
        body: JSON.stringify({
          url: repo.url,
          name: repo.name,
          branch: repo.default_branch || "main",
          github_repo_id: repo.id,
        }),
      });
      toast(data.message || "Repository added", "success");
      await loadDashboard();
    } catch (error) {
      toast(error.message, "error");
    }
  }

  function appendScanLog(message, cls) {
    const log = $("scan-log");
    const line = el("div", `scan-log-line ${cls || ""}`, message);
    log.appendChild(line);
    log.scrollTop = log.scrollHeight;
  }

  function showScanOverlay() {
    $("scan-overlay").classList.add("show");
    $("scan-log").innerHTML = "";
    $("scan-progress").style.width = "0%";
    text($("scan-status"), "Scanning...");
  }

  async function scanRepo(repo) {
    showScanOverlay();
    appendScanLog(`scanning ${repo.name || repo.url}...`);
    try {
      const data = await request(`/api/repos/${encodeURIComponent(repo.id)}/scan`, { method: "POST" });
      $("scan-progress").style.width = "100%";
      appendScanLog(`complete: ${data.total_findings || 0} findings`, data.total_findings ? "warn" : "ok");
      text($("scan-status"), "Done.");
      toast(`Scan complete: ${data.total_findings || 0} findings`, data.total_findings ? "warning" : "success");
      await loadDashboard();
      setTimeout(() => $("scan-overlay").classList.remove("show"), 3000);
    } catch (error) {
      appendScanLog(error.message, "warn");
      text($("scan-status"), "Failed.");
      toast(error.message, "error");
    }
  }

  async function runScan() {
    if (!state.repos.length) {
      $("add-repo-panel").hidden = false;
      toast("Add a repository before running a scan", "warning");
      return;
    }
    const button = $("run-scan-btn");
    button.disabled = true;
    showScanOverlay();
    try {
      for (let i = 0; i < state.repos.length; i += 1) {
        const repo = state.repos[i];
        appendScanLog(`scanning ${repo.name || repo.url}...`);
        const data = await request(`/api/repos/${encodeURIComponent(repo.id)}/scan`, { method: "POST" });
        appendScanLog(`done: ${data.total_findings || 0} findings`, data.total_findings ? "warn" : "ok");
        $("scan-progress").style.width = `${Math.round(((i + 1) / state.repos.length) * 100)}%`;
      }
      text($("scan-status"), "Done.");
      toast("All scans complete", "success");
      await loadDashboard();
      setTimeout(() => $("scan-overlay").classList.remove("show"), 3000);
    } catch (error) {
      appendScanLog(error.message, "warn");
      text($("scan-status"), "Failed.");
      toast(error.message, "error");
    } finally {
      button.disabled = false;
    }
  }

  async function removeRepo(repo) {
    if (!window.confirm(`Remove "${repo.name || repo.url}" from monitoring?`)) return;
    try {
      await request(`/api/repos/${encodeURIComponent(repo.id)}`, { method: "DELETE" });
      toast("Repository removed", "success");
      await loadDashboard();
    } catch (error) {
      toast(error.message, "error");
    }
  }

  function initNav() {
    document.querySelectorAll(".nav-item[data-panel]").forEach((item) => {
      item.addEventListener("click", () => {
        document.querySelectorAll(".nav-item").forEach((nav) => nav.classList.remove("active"));
        item.classList.add("active");
        const target = item.dataset.panel;
        const section = document.querySelector(`[data-section="${target}"]`);
        if (section) section.scrollIntoView({ behavior: "smooth", block: "start" });
      });
    });
  }

  function init() {
    if (!$("repo-list")) return;
    initNav();
    $("show-add-repo").addEventListener("click", () => {
      $("add-repo-panel").hidden = !$("add-repo-panel").hidden;
      if (!$("add-repo-panel").hidden) $("repo-url-input").focus();
    });
    $("add-repo-btn").addEventListener("click", addRepoFromUrl);
    $("load-github-repos-btn").addEventListener("click", loadGitHubRepos);
    $("github-search").addEventListener("input", filterGitHubRepos);
    $("run-scan-btn").addEventListener("click", runScan);
    loadDashboard();
  }

  document.addEventListener("DOMContentLoaded", init);
})();
