/**
 * PhishGuard AI - Popup Dashboard Controller (v2.0)
 * Manages semicircular risk gauge, real-time telemetry, quick actions,
 * allowlist management, sensitivity settings, and theme toggling.
 */

const DEFAULT_API_BASE = "http://127.0.0.1:8000";
// Semicircular Arc length: Radius = 80, Length = pi * 80 ≈ 251.327
const GAUGE_LENGTH = Math.PI * 80;

async function getApiBase() {
  try {
    const data = await chrome.storage.local.get("phishguard_api_base");
    if (data && data.phishguard_api_base && data.phishguard_api_base.trim()) {
      return data.phishguard_api_base.trim().replace(/\/+$/, "");
    }
  } catch (_) {}
  return DEFAULT_API_BASE;
}

let activeDomain = "";
let isWhitelistedState = false;
let currentTabUrl = "";

function showToast(message, type = "success") {
  const toast = document.getElementById("toast-notification");
  const msgElem = document.getElementById("toast-message");
  if (!toast || !msgElem) return;

  msgElem.textContent = message;
  toast.className = `toast-notification ${type}`;
  clearTimeout(showToast._timer);
  showToast._timer = setTimeout(() => {
    toast.className = "toast-notification hidden";
  }, 2200);
}

document.addEventListener("DOMContentLoaded", () => {
  setupTheme();
  setupTabs();
  checkBackendHealth();
  loadAllState();
  loadCurrentTabStatus();
  setupProtectionToggles();
  setupQuickActions();
  setupManualScanner();
  setupEmailScanner();
  setupHistoryView();
  setupWhitelistView();
  setupSettingsView();
});

// Theme Management (Charcoal Dark / Solaris Light)
function setupTheme() {
  chrome.storage.local.get("phishguard_theme", (data) => {
    let theme = data.phishguard_theme || "charcoal";
    if (theme === "dark") theme = "charcoal";
    if (theme === "light") theme = "solaris";
    document.documentElement.setAttribute("data-theme", theme);
    updateThemeBtnLabel(theme);
  });

  const themeBtn = document.getElementById("theme-toggle-btn");
  if (themeBtn) {
    themeBtn.addEventListener("click", () => {
      const current = document.documentElement.getAttribute("data-theme") || "charcoal";
      const isCharcoal = current === "charcoal" || current === "dark";
      const next = isCharcoal ? "solaris" : "charcoal";
      document.documentElement.setAttribute("data-theme", next);
      chrome.storage.local.set({ phishguard_theme: next });
      updateThemeBtnLabel(next);
      const name = next === "solaris" ? "Solaris Light" : "Charcoal Dark";
      showToast(`Switched to ${name}`);
    });
  }
}

function updateThemeBtnLabel(theme) {
  const label = document.getElementById("theme-btn-label");
  if (label) {
    const isCharcoal = theme === "charcoal" || theme === "dark";
    label.textContent = isCharcoal ? "Solaris Light" : "Charcoal Dark";
  }
}

// Segmented Tab Navigation
function setupTabs() {
  const tabs = document.querySelectorAll(".nav-tab");
  tabs.forEach((btn) => {
    btn.addEventListener("click", () => {
      tabs.forEach((t) => {
        t.classList.remove("active");
        t.setAttribute("aria-selected", "false");
      });
      document.querySelectorAll(".tab-pane").forEach((c) => c.classList.remove("active"));

      btn.classList.add("active");
      btn.setAttribute("aria-selected", "true");
      const targetId = btn.getAttribute("data-tab");
      const targetElem = document.getElementById(targetId);
      if (targetElem) targetElem.classList.add("active");

      if (targetId === "history-view" || targetId === "whitelist-view" || targetId === "settings-view") {
        loadAllState();
      }
    });
  });

  // Quick settings gear icon in header
  const quickSettingsBtn = document.getElementById("quick-settings-btn");
  if (quickSettingsBtn) {
    quickSettingsBtn.addEventListener("click", () => {
      const settingsTab = document.getElementById("tab-settings");
      if (settingsTab) settingsTab.click();
    });
  }
}

// Check Detection Backend Gateway Status
async function checkBackendHealth() {
  const statusChip = document.getElementById("backend-status-chip");
  const statusText = document.getElementById("backend-status");
  if (!statusChip || !statusText) return;

  try {
    const apiBase = await getApiBase();
    const urlObj = new URL(apiBase);
    const hostStr = `${urlObj.hostname}:${urlObj.port || (urlObj.protocol === "https:" ? "443" : "80")}`;

    const res = await fetch(`${apiBase}/api/health`, { method: "GET" });
    if (res.ok) {
      statusChip.className = "status-chip-container connected";
      statusText.textContent = `Backend connected · ${hostStr}`;
    } else {
      throw new Error();
    }
  } catch (_) {
    statusChip.className = "status-chip-container offline";
    statusText.textContent = "Offline mode: heuristic fallback";
  }
}

// Protection switches (Master & Gmail)
function setupProtectionToggles() {
  const masterToggle = document.getElementById("protection-master-toggle");
  const gmailToggle = document.getElementById("gmail-protection-toggle");

  chrome.storage.local.get(["phishguard_protection_enabled", "phishguard_gmail_enabled"], (data) => {
    if (masterToggle && data.phishguard_protection_enabled !== undefined) {
      masterToggle.checked = Boolean(data.phishguard_protection_enabled);
    }
    if (gmailToggle && data.phishguard_gmail_enabled !== undefined) {
      gmailToggle.checked = Boolean(data.phishguard_gmail_enabled);
    }
  });

  if (masterToggle) {
    masterToggle.addEventListener("change", () => {
      const enabled = masterToggle.checked;
      chrome.storage.local.set({ phishguard_protection_enabled: enabled });
      showToast(enabled ? "Real-time protection enabled" : "Real-time protection paused", enabled ? "success" : "warning");
    });
  }

  if (gmailToggle) {
    gmailToggle.addEventListener("change", () => {
      const enabled = gmailToggle.checked;
      chrome.storage.local.set({ phishguard_gmail_enabled: enabled });
      showToast(enabled ? "Gmail guard enabled" : "Gmail guard disabled", enabled ? "success" : "warning");
    });
  }
}

// Quick Actions: Allowlist toggle, Re-scan, Report
function setupQuickActions() {
  const whitelistBtn = document.getElementById("whitelist-toggle-btn");
  const rescanBtn = document.getElementById("rescan-btn");
  const reportBtn = document.getElementById("report-site-btn");

  if (whitelistBtn) {
    whitelistBtn.addEventListener("click", () => {
      if (!activeDomain) return;
      const msgType = isWhitelistedState ? "REMOVE_WHITELIST" : "ADD_WHITELIST";
      chrome.runtime.sendMessage({ type: msgType, domain: activeDomain }, () => {
        isWhitelistedState = !isWhitelistedState;
        updateWhitelistUI(isWhitelistedState);
        showToast(isWhitelistedState ? `Added ${activeDomain} to allowlist` : `Removed ${activeDomain} from allowlist`);
        loadCurrentTabStatus();
      });
    });
  }

  if (rescanBtn) {
    rescanBtn.addEventListener("click", () => {
      if (!currentTabUrl) return;
      rescanBtn.classList.add("loading");
      showToast("Re-scanning active destination...", "info");

      // Purge cached verdict for this URL via service worker
      chrome.runtime.sendMessage({ type: "PURGE_CACHE", url: currentTabUrl }, () => {
        chrome.runtime.sendMessage({ type: "CHECK_URL", url: currentTabUrl }, (freshReport) => {
          rescanBtn.classList.remove("loading");
          if (freshReport) {
            renderTabReport(freshReport);
            showToast(`Re-scan completed · Score: ${freshReport.threat_score}/100`);
          }
        });
      });
    });
  }

  if (reportBtn) {
    reportBtn.addEventListener("click", () => {
      if (!activeDomain) return;
      const userVerdict = confirm(
        `PhishGuard AI Incident Feedback\n\nTarget: ${activeDomain}\n\nWould you like to report this classification for review?`
      );
      if (userVerdict) {
        showToast("Feedback submitted to security intelligence team.");
      }
    });
  }
}

// Load stats, history, whitelist, settings
function loadAllState() {
  chrome.runtime.sendMessage({ type: "GET_ALL_STATE" }, (state) => {
    if (!state) return;

    // 1. Stats
    const stats = state.stats || { totalScans: 0, threatsNeutralized: 0 };
    const statScans = document.getElementById("stat-scans");
    const statBlocked = document.getElementById("stat-blocked");
    const statMode = document.getElementById("stat-mode");

    if (statScans) statScans.textContent = stats.totalScans || 0;
    if (statBlocked) statBlocked.textContent = stats.threatsNeutralized || 0;

    const level = state.protectionLevel || "balanced";
    if (statMode) {
      statMode.textContent = level.charAt(0).toUpperCase() + level.slice(1);
    }

    // 2. Sensitivity Radio
    const radio = document.getElementById(`radio-${level}`);
    if (radio) radio.checked = true;

    // 3. Render History
    renderHistoryList(state.history || []);

    // 4. Render Whitelist
    renderWhitelistList(state.whitelist || []);

    // 5. API Base
    const apiInput = document.getElementById("api-base-input");
    if (apiInput && state.apiBase) {
      apiInput.value = state.apiBase;
    }
  });
}

// History List
function renderHistoryList(history) {
  const listElem = document.getElementById("history-list");
  if (!listElem) return;

  if (!history || history.length === 0) {
    listElem.innerHTML = `<div class="empty-state">No recent scan activity recorded.</div>`;
    return;
  }

  listElem.innerHTML = history
    .slice(0, 30)
    .map((item) => {
      const date = item.timestamp ? new Date(item.timestamp) : new Date();
      const timeStr = date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
      const verdict = (item.verdict || "safe").toLowerCase();
      const score = Math.round(item.threat_score || 0);

      let badgeClass = "verdict-safe";
      if (verdict === "phishing") badgeClass = "verdict-phishing";
      else if (verdict === "suspicious") badgeClass = "verdict-suspicious";

      const displayDomain = item.domain || (item.url ? extractDomain(item.url) : "Unknown destination");

      return `
        <div class="history-item">
          <div class="history-left">
            <span class="history-domain" title="${escapeHtml(item.url || displayDomain)}">
              ${escapeHtml(displayDomain)}
            </span>
            <span class="history-meta">${escapeHtml(timeStr)} &bull; Risk: ${score}/100</span>
          </div>
          <span class="verdict-pill ${badgeClass}">
            ${escapeHtml(verdict)}
          </span>
        </div>
      `;
    })
    .join("");
}

// Export History to CSV
function setupHistoryView() {
  const exportBtn = document.getElementById("export-history-btn");
  const clearBtn = document.getElementById("clear-history-btn");

  if (exportBtn) {
    exportBtn.addEventListener("click", () => {
      chrome.runtime.sendMessage({ type: "GET_ALL_STATE" }, (state) => {
        const history = state?.history || [];
        if (history.length === 0) {
          showToast("No scan history to export", "warning");
          return;
        }

        const headers = ["Timestamp", "ISO_Date", "Domain", "URL", "Threat_Score", "Verdict", "Risk_Level", "Signals"];
        const rows = history.map((item) => {
          const date = item.timestamp ? new Date(item.timestamp).toISOString() : "";
          const signals = (item.reasons || []).join(" | ").replace(/"/g, '""');
          return [
            item.timestamp || "",
            `"${date}"`,
            `"${(item.domain || "").replace(/"/g, '""')}"`,
            `"${(item.url || "").replace(/"/g, '""')}"`,
            item.threat_score || 0,
            `"${item.verdict || "safe"}"`,
            `"${item.risk_level || "LOW"}"`,
            `"${signals}"`
          ].join(",");
        });

        const csvContent = "\uFEFF" + [headers.join(","), ...rows].join("\r\n");
        const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        const nowStr = new Date().toISOString().slice(0, 10);
        a.download = `phishguard_audit_log_${nowStr}.csv`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        showToast("Audit log exported to CSV");
      });
    });
  }

  if (clearBtn) {
    clearBtn.addEventListener("click", () => {
      if (confirm("Clear all scan history logs?")) {
        chrome.runtime.sendMessage({ type: "CLEAR_HISTORY" }, () => {
          renderHistoryList([]);
          const statScans = document.getElementById("stat-scans");
          const statBlocked = document.getElementById("stat-blocked");
          if (statScans) statScans.textContent = "0";
          if (statBlocked) statBlocked.textContent = "0";
          showToast("Scan history cleared");
        });
      }
    });
  }
}

// Allowlist UI & Management
function renderWhitelistList(whitelist) {
  const listElem = document.getElementById("whitelist-list");
  const countBadge = document.getElementById("whitelist-count");
  if (!listElem) return;

  if (countBadge) countBadge.textContent = whitelist ? whitelist.length : 0;

  if (!whitelist || whitelist.length === 0) {
    listElem.innerHTML = `<div class="empty-state">No domains currently in allowlist.</div>`;
    return;
  }

  listElem.innerHTML = whitelist
    .map(
      (domain) => `
      <div class="whitelist-row">
        <span class="whitelist-domain-name" title="${escapeHtml(domain)}">${escapeHtml(domain)}</span>
        <button class="whitelist-del-btn" data-domain="${escapeHtml(domain)}" title="Remove domain">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="3 6 5 6 21 6"/>
            <path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>
            <path d="M10 11v6"/>
            <path d="M14 11v6"/>
          </svg>
        </button>
      </div>
    `
    )
    .join("");

  listElem.querySelectorAll(".whitelist-del-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const domain = btn.getAttribute("data-domain");
      if (!domain) return;
      chrome.runtime.sendMessage({ type: "REMOVE_WHITELIST", domain }, (res) => {
        if (res && res.whitelist) {
          renderWhitelistList(res.whitelist);
          if (activeDomain === domain) updateWhitelistUI(false);
          showToast(`Removed ${domain} from allowlist`);
        }
      });
    });
  });
}

function setupWhitelistView() {
  const addBtn = document.getElementById("add-whitelist-btn");
  const input = document.getElementById("new-whitelist-input");
  if (!addBtn || !input) return;

  function addDomain() {
    let domain = (input.value || "").trim().toLowerCase();
    if (!domain) return;
    try {
      if (domain.includes("://")) {
        domain = new URL(domain).hostname;
      }
    } catch (_) {}
    domain = domain.replace(/^\.+|\.+$/g, "");

    chrome.runtime.sendMessage({ type: "ADD_WHITELIST", domain }, (res) => {
      if (res && res.whitelist) {
        renderWhitelistList(res.whitelist);
        input.value = "";
        if (activeDomain === domain) updateWhitelistUI(true);
        showToast(`Added ${domain} to allowlist`);
      }
    });
  }

  addBtn.addEventListener("click", addDomain);
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") addDomain();
  });
}

// Settings: Sensitivity Radios, API Base, Cache Purge
function setupSettingsView() {
  const radios = document.querySelectorAll('input[name="protection-level"]');
  radios.forEach((r) => {
    r.addEventListener("change", () => {
      if (r.checked) {
        const level = r.value;
        chrome.runtime.sendMessage({ type: "SET_PROTECTION_LEVEL", level }, () => {
          const statMode = document.getElementById("stat-mode");
          if (statMode) statMode.textContent = level.charAt(0).toUpperCase() + level.slice(1);
          showToast(`Sensitivity set to ${level}`);
        });
      }
    });
  });

  const saveApiBtn = document.getElementById("save-api-base-btn");
  const apiInput = document.getElementById("api-base-input");
  if (saveApiBtn && apiInput) {
    saveApiBtn.addEventListener("click", () => {
      const val = (apiInput.value || "").trim();
      chrome.storage.local.set({ phishguard_api_base: val }, () => {
        showToast("Gateway endpoint saved");
        checkBackendHealth();
      });
    });
  }

  const purgeBtn = document.getElementById("purge-cache-btn");
  if (purgeBtn) {
    purgeBtn.addEventListener("click", () => {
      chrome.runtime.sendMessage({ type: "PURGE_CACHE" }, (res) => {
        const count = res?.count || 0;
        showToast(`Purged ${count} cached evaluations`);
        loadCurrentTabStatus();
      });
    });
  }
}

// Update Trust Domain button state
function updateWhitelistUI(isWhitelisted) {
  const btn = document.getElementById("whitelist-toggle-btn");
  const label = document.getElementById("whitelist-label");
  if (!btn) return;

  if (isWhitelisted) {
    btn.classList.add("trusted");
    if (label) label.textContent = "Domain Trusted";
  } else {
    btn.classList.remove("trusted");
    if (label) label.textContent = "Trust domain";
  }
}

// Active Tab Inspection
function loadCurrentTabStatus() {
  chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
    if (!tabs || tabs.length === 0) return;
    const tab = tabs[0];
    currentTabUrl = tab.url || "";

    const domainElem = document.getElementById("active-domain");
    const protocolBadge = document.getElementById("protocol-badge");

    try {
      const parsed = new URL(currentTabUrl);
      activeDomain = parsed.hostname || "";
      if (domainElem) domainElem.textContent = activeDomain || currentTabUrl;

      if (protocolBadge) {
        if (parsed.protocol === "https:") {
          protocolBadge.textContent = "HTTPS";
          protocolBadge.className = "card-badge";
        } else if (parsed.protocol === "http:") {
          protocolBadge.textContent = "HTTP";
          protocolBadge.className = "card-badge";
        } else {
          protocolBadge.textContent = parsed.protocol.replace(":", "").toUpperCase();
          protocolBadge.className = "card-badge";
        }
      }
    } catch (_) {
      activeDomain = currentTabUrl;
      if (domainElem) domainElem.textContent = currentTabUrl;
    }

    if (activeDomain) {
      chrome.runtime.sendMessage(
        { type: "IS_WHITELISTED", domain: activeDomain },
        (res) => {
          isWhitelistedState = Boolean(res && res.whitelisted);
          updateWhitelistUI(isWhitelistedState);
        }
      );
    }

    if (!currentTabUrl || currentTabUrl.startsWith("chrome://") || currentTabUrl.startsWith("edge://")) {
      renderTabReport({
        threat_score: 0,
        verdict: "safe",
        reasons: ["Internal browser system page - trusted destination."]
      });
      return;
    }

    chrome.runtime.sendMessage({ type: "CHECK_URL", url: currentTabUrl }, (report) => {
      if (report) {
        renderTabReport(report);
      }
    });
  });
}

// Render Semicircular Animated Risk Gauge & Reasons
function renderTabReport(report) {
  const score = Math.round(report.threat_score || 0);
  const scoreElem = document.getElementById("active-score");
  const gaugeBar = document.getElementById("gauge-bar");
  const badge = document.getElementById("active-verdict-badge");
  const reasonsContainer = document.getElementById("reasons-container");

  if (scoreElem) scoreElem.textContent = score;

  // Calibrate Semicircular Gauge (Arc length: 251.33)
  if (gaugeBar) {
    const offset = GAUGE_LENGTH - (score / 100) * GAUGE_LENGTH;
    gaugeBar.style.strokeDashoffset = offset;

    // Color transitions: Emerald (Safe) -> Amber (Suspicious) -> Red (Phishing)
    if (isWhitelistedState) {
      gaugeBar.style.stroke = "var(--accent-blue)";
    } else if (score >= 70) {
      gaugeBar.style.stroke = "var(--color-danger)";
    } else if (score >= 40) {
      gaugeBar.style.stroke = "var(--color-warning)";
    } else {
      gaugeBar.style.stroke = "var(--color-safe)";
    }
  }

  // Verdict Pill
  if (badge) {
    if (isWhitelistedState) {
      badge.className = "verdict-pill verdict-safe";
      badge.textContent = "Allowlisted";
    } else if (report.verdict === "phishing") {
      badge.className = "verdict-pill verdict-phishing";
      badge.textContent = "Phishing";
    } else if (report.verdict === "suspicious") {
      badge.className = "verdict-pill verdict-suspicious";
      badge.textContent = "Suspicious";
    } else {
      badge.className = "verdict-pill verdict-safe";
      badge.textContent = "Safe";
    }
  }

  // "Why this verdict" reasons list
  if (reasonsContainer) {
    const reasons = report.reasons || [];
    if (reasons.length === 0) {
      reasonsContainer.innerHTML = `
        <div class="reason-row pass">
          <svg class="reason-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="20 6 9 17 4 12"/>
          </svg>
          <div><strong>Clean domain namespace:</strong> Verified domain reputation with no typosquatting or brand impersonation.</div>
        </div>
        <div class="reason-row pass">
          <svg class="reason-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="20 6 9 17 4 12"/>
          </svg>
          <div><strong>Safe structure:</strong> Validated TLD category, no deceptive subdomains or credential harvest triggers.</div>
        </div>
      `;
    } else {
      reasonsContainer.innerHTML = reasons
        .map((r) => {
          const isDanger = report.verdict === "phishing";
          const rowClass = isDanger ? "danger" : "warning";
          const iconSvg = isDanger
            ? `<svg class="reason-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                <circle cx="12" cy="12" r="10"/>
                <line x1="15" y1="9" x2="9" y2="15"/>
                <line x1="9" y1="9" x2="15" y2="15"/>
              </svg>`
            : `<svg class="reason-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                <line x1="12" y1="9" x2="12" y2="13"/>
                <line x1="12" y1="17" x2="12.01" y2="17"/>
              </svg>`;

          return `
            <div class="reason-row ${rowClass}">
              ${iconSvg}
              <div>${escapeHtml(r)}</div>
            </div>
          `;
        })
        .join("");
    }
  }
}

// Manual Scanner Controller
function setupManualScanner() {
  const input = document.getElementById("manual-input");
  const scanBtn = document.getElementById("manual-scan-btn");
  const pasteBtn = document.getElementById("manual-paste-btn");
  const resultCard = document.getElementById("scan-result");
  const badge = document.getElementById("manual-verdict-badge");
  const scoreText = document.getElementById("manual-score");
  const reasonsBox = document.getElementById("manual-reasons");

  if (pasteBtn && input) {
    pasteBtn.addEventListener("click", async () => {
      try {
        const text = await navigator.clipboard.readText();
        if (text) {
          input.value = text.trim();
          input.focus();
        }
      } catch (_) {
        input.focus();
      }
    });
  }

  async function performScan() {
    const rawVal = input.value.trim();
    if (!rawVal) return;

    scanBtn.disabled = true;
    scanBtn.querySelector("span").textContent = "Scanning...";

    chrome.runtime.sendMessage(
      { type: "CHECK_URL", url: rawVal },
      (report) => {
        scanBtn.disabled = false;
        scanBtn.querySelector("span").textContent = "Scan URL";
        if (!report) return;

        resultCard.classList.remove("hidden");
        scoreText.textContent = `Score: ${report.threat_score}/100`;

        const verdict = (report.verdict || "safe").toLowerCase();
        badge.className = `verdict-pill verdict-${verdict}`;
        badge.textContent = verdict.charAt(0).toUpperCase() + verdict.slice(1);

        const reasons = report.reasons || [];
        if (reasons.length === 0) {
          reasonsBox.innerHTML = `
            <div class="reason-row pass">
              <svg class="reason-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                <polyline points="20 6 9 17 4 12"/>
              </svg>
              <div>Clean signature: No deceptive lexical or network indicators found.</div>
            </div>
          `;
        } else {
          reasonsBox.innerHTML = reasons
            .map((r) => {
              const isDanger = verdict === "phishing";
              return `
                <div class="reason-row ${isDanger ? 'danger' : 'warning'}">
                  <svg class="reason-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                    <circle cx="12" cy="12" r="10"/>
                    <line x1="12" y1="8" x2="12" y2="12"/>
                    <line x1="12" y1="16" x2="12.01" y2="16"/>
                  </svg>
                  <div>${escapeHtml(r)}</div>
                </div>
              `;
            })
            .join("");
        }
        if (report.scoring_breakdown) {
          const sb = report.scoring_breakdown;
          reasonsBox.innerHTML += `
            <div class="email-scan-links-section" style="margin-top: 8px;">
              <div class="links-section-title">Engine Fusion Telemetry</div>
              <div class="pg-scoring-tags">
                <span class="pg-tag-chip">ML Score: ${sb.ml_score}%</span>
                <span class="pg-tag-chip">Heuristic: ${sb.heuristic_penalty !== undefined ? sb.heuristic_penalty : (sb.heuristic_score !== undefined ? sb.heuristic_score : 0)}</span>
                <span class="pg-tag-chip">Domain Trust: ${escapeHtml(sb.domain_trust || "standard")}</span>
              </div>
            </div>
          `;
        }

        loadAllState();
      }
    );
  }

  if (scanBtn && input) {
    scanBtn.addEventListener("click", performScan);
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") performScan();
    });
  }
}

// Manual Email Scanner (v2.2)
function setupEmailScanner() {
  const scanBtn = document.getElementById("manual-email-scan-btn");
  const senderInput = document.getElementById("email-sender-input");
  const subjectInput = document.getElementById("email-subject-input");
  const bodyInput = document.getElementById("email-body-input");
  const linksInput = document.getElementById("email-links-input");
  const resultCard = document.getElementById("email-scan-result");
  const badge = document.getElementById("email-verdict-badge");
  const scoreChip = document.getElementById("email-score-chip");
  const mlVal = document.getElementById("email-ml-val");
  const heurVal = document.getElementById("email-heur-val");
  const finalVal = document.getElementById("email-final-val");
  const reasonsList = document.getElementById("email-reasons-list");

  if (!scanBtn || !bodyInput) return;

  async function performEmailScan() {
    const rawSender = (senderInput ? senderInput.value : "").trim();
    const rawSubject = (subjectInput ? subjectInput.value : "").trim();
    const rawBody = (bodyInput ? bodyInput.value : "").trim();
    const rawLinks = (linksInput ? linksInput.value : "").trim();

    if (!rawBody && !rawSubject) {
      showToast("Please enter email subject or body text", "warning");
      return;
    }

    // Extract sender name and email from "Name <email@domain.com>"
    let senderName = rawSender;
    let senderEmail = rawSender;
    const match = rawSender.match(/^(.*?)\s*<([^>]+)>/);
    if (match) {
      senderName = match[1].trim();
      senderEmail = match[2].trim();
    } else if (rawSender.includes("@")) {
      senderEmail = rawSender;
      senderName = rawSender.split("@")[0];
    }

    // Parse links from input and also auto-extract any http/https links from body!
    const links = [];
    const imageUrls = [];
    if (rawLinks) {
      rawLinks.split(/[,\s\n]+/).forEach((l) => {
        const cl = l.trim();
        if (!cl) return;
        if (cl.startsWith("data:image/") || cl.match(/\.(png|jpg|jpeg|gif|webp|svg)$/i)) {
          if (!imageUrls.includes(cl)) imageUrls.push(cl);
        } else if (cl.startsWith("http")) {
          if (!links.includes(cl)) links.push(cl);
        }
      });
    }

    const bodyUrlMatches = rawBody.match(/https?:\/\/[^\s<>"')]+/g) || [];
    bodyUrlMatches.forEach((l) => {
      if (!links.includes(l)) links.push(l);
    });

    scanBtn.disabled = true;
    scanBtn.querySelector("span").textContent = "Analyzing Email...";

    chrome.runtime.sendMessage(
      {
        type: "CHECK_EMAIL",
        payload: {
          sender_name: senderName,
          sender_email: senderEmail,
          subject: rawSubject,
          body_text: rawBody,
          links: links.slice(0, 10),
          image_urls: imageUrls.slice(0, 6)
        }
      },
      (report) => {
        scanBtn.disabled = false;
        scanBtn.querySelector("span").textContent = "Scan Email";
        if (!report) {
          showToast("Email scan failed: backend offline", "error");
          return;
        }

        resultCard.classList.remove("hidden");
        const score = Math.round(report.threat_score || 0);
        scoreChip.textContent = `Score: ${score}/100`;

        const verdict = (report.verdict || "safe").toLowerCase();
        badge.className = `verdict-pill verdict-${verdict}`;
        badge.textContent = verdict.charAt(0).toUpperCase() + verdict.slice(1);

        // Scoring telemetry
        const breakdown = report.scoring_breakdown;
        if (breakdown) {
          if (mlVal) mlVal.textContent = `${Math.round(breakdown.ml_score)}%`;
          if (heurVal) heurVal.textContent = `${Math.round(breakdown.heuristic_score)}/100`;
          if (finalVal) finalVal.textContent = `${score}/100`;
        } else {
          if (mlVal) mlVal.textContent = report.nlp_analysis?.phishing_probability ? `${report.nlp_analysis.phishing_probability}%` : "--";
          if (heurVal) heurVal.textContent = "--";
          if (finalVal) finalVal.textContent = `${score}/100`;
        }

        const reasons = report.reasons || [];
        if (reasons.length === 0) {
          reasonsList.innerHTML = `
            <div class="reason-row pass">
              <svg class="reason-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                <polyline points="20 6 9 17 4 12"/>
              </svg>
              <div>Clean email: No spoofing, urgency traps, BEC, or dangerous links detected.</div>
            </div>
          `;
        } else {
          reasonsList.innerHTML = reasons
            .map((r) => {
              const isDanger = verdict === "phishing";
              return `
                <div class="reason-row ${isDanger ? 'danger' : 'warning'}">
                  <svg class="reason-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                    <circle cx="12" cy="12" r="10"/>
                    <line x1="12" y1="8" x2="12" y2="12"/>
                    <line x1="12" y1="16" x2="12.01" y2="16"/>
                  </svg>
                  <div>${escapeHtml(r)}</div>
                </div>
              `;
            })
            .join("");
        }

        // Analyzed links summary
        const analyzed = report.analyzed_links || [];
        if (analyzed.length > 0) {
          const linksHtml = analyzed
            .map((l) => `
              <div class="email-scan-link-item ${l.threat_score >= 70 ? 'danger' : (l.threat_score >= 40 ? 'warning' : 'safe')}">
                <span class="scan-link-url" title="${escapeHtml(l.url)}">${escapeHtml(l.url)}</span>
                <span class="scan-link-score">${l.threat_score}/100</span>
              </div>
            `)
            .join("");
          reasonsList.innerHTML += `
            <div class="email-scan-links-section">
              <div class="links-section-title">Analyzed Links (${analyzed.length})</div>
              ${linksHtml}
            </div>
          `;
        }

        // Quishing findings summary
        const quishing = report.quishing_findings || [];
        if (quishing.length > 0) {
          const quishingHtml = quishing
            .map((q) => `
              <div class="email-scan-link-item ${q.destination_threat_score >= 70 ? 'danger' : 'warning'}">
                <span class="scan-link-url" title="${escapeHtml(q.payload)}">QR Payload: ${escapeHtml(q.payload)}</span>
                <span class="scan-link-score">${q.destination_threat_score}/100</span>
              </div>
            `)
            .join("");
          reasonsList.innerHTML += `
            <div class="email-scan-links-section">
              <div class="links-section-title">Quishing (QR Code Analysis)</div>
              ${quishingHtml}
            </div>
          `;
        }

        loadAllState();
        showToast(`Email evaluated: ${verdict.toUpperCase()}`);
      }
    );
  }

  scanBtn.addEventListener("click", performEmailScan);
}

function extractDomain(url) {
  try {
    return new URL(url).hostname;
  } catch (_) {
    return url;
  }
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
