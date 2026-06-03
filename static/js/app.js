/**
 * Secrets Hygiene Monitor — Shared JavaScript Utilities
 *
 * API client, toast/modal UI, scan polling, formatting helpers,
 * clipboard, confirm dialogs, sidebar toggle, keyboard shortcuts,
 * loading spinner, and empty-state generator.
 */

/* ==========================================================================
   API Client
   ========================================================================== */

const API_BASE = window.location.origin;

class ApiError extends Error {
  constructor(status, message, body) {
    super(message || `API error ${status}`);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
  }
}

const api = {
  /**
   * Core request method. Sends JSON body for POST/PUT, parses JSON
   * responses, and throws ApiError on non-2xx. 401s trigger a
   * redirect to /login.
   */
  async _request(method, path, body) {
    const url = `${API_BASE}${path}`;
    const opts = {
      method,
      headers: { "Content-Type": "application/json" },
      credentials: "include",          // send session cookie
    };
    if (body !== undefined) {
      opts.body = JSON.stringify(body);
    }

    let response;
    try {
      response = await fetch(url, opts);
    } catch (networkErr) {
      throw new ApiError(0, `Network error: ${networkErr.message}`);
    }

    // Attempt to parse JSON body (may be empty on 204 etc.)
    let data = null;
    const text = await response.text();
    if (text) {
      try { data = JSON.parse(text); } catch { data = text; }
    }

    if (response.status === 401) {
      window.location.href = "/login";
      return null;
    }

    if (!response.ok) {
      const msg = (data && data.detail) || data?.message || response.statusText;
      throw new ApiError(response.status, msg, data);
    }

    return data;
  },

  get(path)    { return this._request("GET",    path); },
  post(path, b){ return this._request("POST",   path, b); },
  put(path, b) { return this._request("PUT",    path, b); },
  delete(path) { return this._request("DELETE", path); },

  /* ---- Auth ---- */
  auth: {
    check:   ()     => api.get("/auth/me"),
    logout:  ()     => api.get("/auth/logout"),
  },

  /* ---- Repos ---- */
  repos: {
    list:   ()                        => api.get("/api/repos"),
    add:    (url, name, branch, githubRepoId) =>
              api.post("/api/repos", { url, name, branch, github_repo_id: githubRepoId }),
    remove: (id)                      => api.delete(`/api/repos/${id}`),
    scan:   (id)                      => api.post(`/api/repos/${id}/scan`),
    alerts: (id, config)              => api.post(`/api/repos/${id}/alert`, config),
    scans:  (id)                      => api.get(`/api/repos/${id}/scans`),
    github: ()                        => api.get("/api/github/repos"),
  },

  /* ---- Dashboard ---- */
  dashboard: () => api.get("/api/dashboard"),

  /* ---- Health ---- */
  health:    () => api.get("/api/health"),
};


/* ==========================================================================
   Toast Notification System
   ========================================================================== */

const toast = (() => {
  const CONTAINER_ID = "toast-container";

  // Ensure container exists
  function getContainer() {
    let el = document.getElementById(CONTAINER_ID);
    if (!el) {
      el = document.createElement("div");
      el.id = CONTAINER_ID;
      el.style.cssText = [
        "position:fixed", "top:1rem", "right:1rem",
        "display:flex", "flex-direction:column", "gap:0.5rem",
        "z-index:10000", "max-width:24rem", "pointer-events:none",
      ].join(";");
      document.body.appendChild(el);
    }
    return el;
  }

  const ICONS = {
    success: "✓",
    error:   "✕",
    warning: "⚠",
    info:    "ℹ",
  };

  const COLORS = {
    success: { bg: "#16a34a", border: "#15803d" },
    error:   { bg: "#dc2626", border: "#b91c1c" },
    warning: { bg: "#d97706", border: "#b45309" },
    info:    { bg: "#2563eb", border: "#1d4ed8" },
  };

  /**
   * Show a toast notification.
   * @param {string}  message  – Text to display.
   * @param {string}  type     – One of: success, error, warning, info.
   * @param {number}  duration – Milliseconds before auto-dismiss (default 4000).
   */
  function show(message, type = "info", duration = 4000) {
    const container = getContainer();
    const colors = COLORS[type] || COLORS.info;
    const icon = ICONS[type] || ICONS.info;

    const el = document.createElement("div");
    el.style.cssText = [
      `background:${colors.bg}`, `border-left:4px solid ${colors.border}`,
      "color:#fff", "padding:0.75rem 1rem", "border-radius:0.375rem",
      "font-size:0.875rem", "line-height:1.4",
      "box-shadow:0 4px 12px rgba(0,0,0,0.15)",
      "display:flex", "align-items:flex-start", "gap:0.5rem",
      "pointer-events:auto",
      "opacity:0", "transform:translateX(100%)",
      "transition:opacity 0.3s ease, transform 0.3s ease",
    ].join(";");

    el.innerHTML = `<span style="font-weight:700;font-size:1rem;">${icon}</span>`
                + `<span>${message}</span>`;

    // Dismiss button
    const closeBtn = document.createElement("button");
    closeBtn.textContent = "×";
    closeBtn.style.cssText = [
      "background:none", "border:none", "color:rgba(255,255,255,0.8)",
      "font-size:1.125rem", "cursor:pointer", "margin-left:auto",
      "padding:0 0 0 0.5rem", "line-height:1",
    ].join(";");
    closeBtn.addEventListener("click", () => dismiss(el));
    el.appendChild(closeBtn);

    container.appendChild(el);

    // Trigger enter animation
    requestAnimationFrame(() => {
      el.style.opacity = "1";
      el.style.transform = "translateX(0)";
    });

    // Auto-dismiss
    const timer = setTimeout(() => dismiss(el), duration);
    el._dismissTimer = timer;
  }

  function dismiss(el) {
    clearTimeout(el._dismissTimer);
    el.style.opacity = "0";
    el.style.transform = "translateX(100%)";
    setTimeout(() => el.remove(), 300);
  }

  return { show };
})();


/* ==========================================================================
   Modal System
   ========================================================================== */

const modal = (() => {
  let backdrop = null;
  let panel = null;

  /**
   * Open a modal with the given HTML content.
   * @param {string} html – Inner HTML for the modal body.
   */
  function open(html) {
    close(); // ensure only one modal at a time

    backdrop = document.createElement("div");
    backdrop.style.cssText = [
      "position:fixed", "inset:0", "z-index:9000",
      "background:rgba(0,0,0,0.5)", "display:flex",
      "align-items:center", "justify-content:center",
      "opacity:0", "transition:opacity 0.2s ease",
    ].join(";");

    panel = document.createElement("div");
    panel.style.cssText = [
      "background:#fff", "border-radius:0.5rem",
      "max-width:32rem", "width:90%", "max-height:80vh",
      "overflow-y:auto", "padding:1.5rem",
      "box-shadow:0 20px 40px rgba(0,0,0,0.2)",
      "transform:scale(0.95)", "transition:transform 0.2s ease",
    ].join(";");
    panel.innerHTML = html;

    backdrop.appendChild(panel);
    document.body.appendChild(backdrop);
    document.body.style.overflow = "hidden"; // lock scroll

    requestAnimationFrame(() => {
      backdrop.style.opacity = "1";
      panel.style.transform = "scale(1)";
    });
  }

  /** Close the currently open modal. */
  function close() {
    if (!backdrop) return;
    backdrop.style.opacity = "0";
    if (panel) panel.style.transform = "scale(0.95)";
    setTimeout(() => {
      backdrop.remove();
      backdrop = null;
      panel = null;
      document.body.style.overflow = "";
    }, 200);
  }

  return { open, close };
})();


/* ==========================================================================
   Scan Status Poller
   ========================================================================== */

class ScanStatus {
  /**
   * @param {string|number} repoId
   * @param {Function} onComplete  – Called with scan data when status is 'completed'.
   * @param {Function} onUpdate    – Called with scan data on every poll tick.
   * @param {Function} onError     – Called with error on failure.
   * @param {Object}   opts        – { interval: ms (default 3000), timeout: ms (default 300000) }
   */
  constructor(repoId, onComplete, onUpdate, onError, opts = {}) {
    this.repoId = repoId;
    this.onComplete = onComplete;
    this.onUpdate = onUpdate;
    this.onError = onError;
    this.interval = opts.interval || 3000;
    this.timeout = opts.timeout || 300000; // 5 min default
    this._timer = null;
    this._deadline = null;
    this._running = false;
  }

  /** Start polling. */
  start() {
    this._running = true;
    this._deadline = Date.now() + this.timeout;
    this._poll();
  }

  /** Stop polling. */
  stop() {
    this._running = false;
    clearTimeout(this._timer);
    this._timer = null;
  }

  async _poll() {
    if (!this._running) return;

    if (Date.now() >= this._deadline) {
      this.stop();
      if (this.onError) this.onError(new Error("Scan polling timed out"));
      return;
    }

    try {
      const data = await api.repos.scans(this.repoId);
      // data may be a list of scans or a single object; normalise
      const latest = Array.isArray(data) ? data[0] : data;

      if (this.onUpdate) this.onUpdate(latest);

      if (latest && (latest.status === "completed" || latest.status === "failed")) {
        this.stop();
        if (this.onComplete) this.onComplete(latest);
        return;
      }
    } catch (err) {
      if (this.onError) this.onError(err);
    }

    this._timer = setTimeout(() => this._poll(), this.interval);
  }
}


/* ==========================================================================
   Formatting Helpers
   ========================================================================== */

/**
 * Format an ISO-8601 string into a human-readable date.
 * e.g. "2025-01-15T10:30:00Z" → "Jan 15, 2025, 10:30 AM"
 */
function formatDate(isoString) {
  if (!isoString) return "—";
  const d = new Date(isoString);
  if (isNaN(d.getTime())) return "—";
  return d.toLocaleDateString("en-US", {
    year: "numeric", month: "short", day: "numeric",
    hour: "numeric", minute: "2-digit",
  });
}

/**
 * Format an ISO-8601 string as relative time.
 * e.g. "2 minutes ago", "3 hours ago", "yesterday"
 */
function formatRelativeTime(isoString) {
  if (!isoString) return "—";
  const d = new Date(isoString);
  if (isNaN(d.getTime())) return "—";

  const now = new Date();
  const diffMs = now - d;
  const diffSec = Math.floor(diffMs / 1000);
  const diffMin = Math.floor(diffSec / 60);
  const diffHr  = Math.floor(diffMin / 60);
  const diffDay = Math.floor(diffHr / 24);

  if (diffSec < 10)  return "just now";
  if (diffSec < 60)  return `${diffSec} seconds ago`;
  if (diffMin < 60)  return `${diffMin} minute${diffMin !== 1 ? "s" : ""} ago`;
  if (diffHr < 24)   return `${diffHr} hour${diffHr !== 1 ? "s" : ""} ago`;
  if (diffDay === 1) return "yesterday";
  if (diffDay < 7)   return `${diffDay} days ago`;
  return formatDate(isoString);
}

/**
 * Return a CSS class name for a severity level.
 * @param {string} severity – e.g. "critical", "high", "medium", "low", "info"
 */
function severityClass(severity) {
  const map = {
    critical: "severity-critical",
    high:     "severity-high",
    medium:   "severity-medium",
    low:      "severity-low",
    info:     "severity-info",
  };
  return map[(severity || "").toLowerCase()] || "severity-unknown";
}

/**
 * Return a hex colour for a severity level.
 * @param {string} severity
 */
function severityColor(severity) {
  const map = {
    critical: "#dc2626",
    high:     "#ea580c",
    medium:   "#d97706",
    low:      "#16a34a",
    info:     "#2563eb",
  };
  return map[(severity || "").toLowerCase()] || "#6b7280";
}


/* ==========================================================================
   Clipboard
   ========================================================================== */

/**
 * Copy text to clipboard and show a toast.
 * Falls back to a prompt-based approach for older browsers.
 */
async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast.show("Copied to clipboard", "success", 2000);
  } catch {
    // Fallback: select-and-copy via textarea
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    try {
      document.execCommand("copy");
      toast.show("Copied to clipboard", "success", 2000);
    } catch {
      toast.show("Press Ctrl+C to copy", "info", 3000);
    }
    document.body.removeChild(ta);
  }
}


/* ==========================================================================
   Confirm Dialog (Promise-based)
   ========================================================================== */

/**
 * Show a styled confirm dialog that resolves to true/false.
 * @param {string} message
 * @returns {Promise<boolean>}
 */
function confirm(message) {
  return new Promise((resolve) => {
    const html = `
      <div style="text-align:center;">
        <p style="margin:0 0 1.5rem;font-size:1rem;color:#374151;">${message}</p>
        <div style="display:flex;gap:0.75rem;justify-content:center;">
          <button id="modal-confirm-yes" style="
            padding:0.5rem 1.5rem;background:#dc2626;color:#fff;
            border:none;border-radius:0.375rem;font-size:0.875rem;
            cursor:pointer;font-weight:600;
          ">Confirm</button>
          <button id="modal-confirm-no" style="
            padding:0.5rem 1.5rem;background:#e5e7eb;color:#374151;
            border:none;border-radius:0.375rem;font-size:0.875rem;
            cursor:pointer;font-weight:600;
          ">Cancel</button>
        </div>
      </div>`;

    modal.open(html);

    document.getElementById("modal-confirm-yes").addEventListener("click", () => {
      modal.close();
      resolve(true);
    });
    document.getElementById("modal-confirm-no").addEventListener("click", () => {
      modal.close();
      resolve(false);
    });
  });
}


/* ==========================================================================
   Sidebar Toggle (mobile)
   ========================================================================== */

function initSidebarToggle() {
  const toggleBtn = document.getElementById("sidebar-toggle");
  const sidebar   = document.getElementById("sidebar");
  const overlay   = document.getElementById("sidebar-overlay");

  if (!toggleBtn || !sidebar) return;

  function openSidebar() {
    sidebar.classList.add("open");
    if (overlay) overlay.classList.add("visible");
    document.body.style.overflow = "hidden";
  }

  function closeSidebar() {
    sidebar.classList.remove("open");
    if (overlay) overlay.classList.remove("visible");
    document.body.style.overflow = "";
  }

  toggleBtn.addEventListener("click", () => {
    sidebar.classList.contains("open") ? closeSidebar() : openSidebar();
  });

  if (overlay) {
    overlay.addEventListener("click", closeSidebar);
  }
}


/* ==========================================================================
   Keyboard Shortcuts
   ========================================================================== */

function initKeyboardShortcuts() {
  document.addEventListener("keydown", (e) => {
    // '/' focuses the search input (unless already in an input)
    if (e.key === "/" && !["INPUT", "TEXTAREA", "SELECT"].includes(e.target.tagName)) {
      e.preventDefault();
      const searchInput = document.getElementById("search-input");
      if (searchInput) searchInput.focus();
    }

    // Escape closes any open modal
    if (e.key === "Escape") {
      modal.close();
    }
  });
}


/* ==========================================================================
   Loading Spinner
   ========================================================================== */

/**
 * Return a spinner DOM element.  Caller appends it wherever needed.
 * @param {string} size  – "sm" (1rem), "md" (2rem), "lg" (3rem)
 */
function spinner(size = "md") {
  const px = { sm: "1rem", md: "2rem", lg: "3rem" }[size] || "2rem";
  const el = document.createElement("div");
  el.className = "spinner";
  el.style.cssText = [
    `width:${px}`, `height:${px}`,
    "border:3px solid #e5e7eb", "border-top-color:#2563eb",
    "border-radius:50%", "animation:spin 0.6s linear infinite",
    "margin:0 auto",
  ].join(";");
  return el;
}

// Inject keyframes once
(function injectSpinnerKeyframes() {
  if (document.getElementById("spinner-style")) return;
  const style = document.createElement("style");
  style.id = "spinner-style";
  style.textContent = `@keyframes spin{to{transform:rotate(360deg)}}`;
  document.head.appendChild(style);
})();


/* ==========================================================================
   Empty State Generator
   ========================================================================== */

/**
 * Return an empty-state DOM element.
 * @param {Object} opts
 * @param {string} opts.title       – Heading text.
 * @param {string} opts.message     – Subtext.
 * @param {string} opts.icon        – Emoji or icon character (default: "📭").
 * @param {string} opts.actionHTML  – Optional HTML for a CTA button.
 */
function emptyState({ title = "Nothing here yet", message = "", icon = "📭", actionHTML = "" } = {}) {
  const el = document.createElement("div");
  el.className = "empty-state";
  el.style.cssText = [
    "text-align:center", "padding:3rem 1.5rem", "color:#6b7280",
  ].join(";");

  el.innerHTML = `
    <div style="font-size:3rem;margin-bottom:1rem;">${icon}</div>
    <h3 style="margin:0 0 0.5rem;font-size:1.125rem;color:#374151;">${title}</h3>
    ${message ? `<p style="margin:0 0 1.5rem;font-size:0.875rem;">${message}</p>` : ""}
    ${actionHTML}
  `;
  return el;
}


/* ==========================================================================
   Bootstrap
   ========================================================================== */

document.addEventListener("DOMContentLoaded", () => {
  initSidebarToggle();
  initKeyboardShortcuts();
});
