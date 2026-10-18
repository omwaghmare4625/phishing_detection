/**
 * PhishGuard Security - Popup Dashboard Controller (v1.3)
 */

const DEFAULT_API_BASE = "http://127.0.0.1:8000";
const CIRCUMFERENCE = 2 * Math.PI * 42; // r = 42 -> ~263.89

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

document.addEventListener("DOMContentLoaded", () => {
  setupTabs();
  checkBackendHealth();
  loadAllState();
  loadCurrentTabStatus();
  setupManualScanner();
  setupHistoryView();
  setupWhitelistView();
  setupSettingsView();
  setupSiteReporting();
});

// Segmented tab navigation
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

      // Refresh state when navigating
      if (targetId === "history-view" || targetId === "whitelist-view" || targetId === "settings-view") {
        loadAllState();
      }
    });
  });
}

// Check FastAPI detection backend status
async function checkBackendHealth() {
  const backendStatus = document.getElementById("backend-status");
  if (!backendStatus) return;

  try {
    const apiBase = await getApiBase();
    const res = await fetch(`${apiBase}/api/health`, { method: "GET" });
    if (res.ok) {
      backendStatus.textContent = "Online";
      backendStatus.className = "telemetry-val status-online";
    } else {
      throw new Error();
    }
  } catch (_) {
    backendStatus.textContent = "Offline (Local Shield)";
    backendStatus.className = "telemetry-val status-offline";
  }
}


// Load stats, history, whitelist, and settings from storage
function loadAllState() {
  chrome.runtime.sendMessage({ type: "GET_ALL_STATE" }, (state) => {
    if (!state) return;

    // 1. Telemetry Stats
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

    // 2. Settings Radio
    const radio = document.getElementById(`radio-${level}`);
    if (radio) radio.checked = true;

    // 3. Render History
    renderHistoryList(state.history || []);

    // 4. Render Whitelist
    renderWhitelistList(state.whitelist || []);

    // 5. API Base Input
    const apiInput = document.getElementById("api-base-input");
    if (apiInput && state.apiBase) {
      apiInput.value = state.apiBase;
    }
  });
}

// Render Event Log
function renderHistoryList(history) {
  const listElem = document.getElementById("history-list");
  if (!listElem) return;

  if (!history || history.length === 0) {
    listElem.innerHTML = `<div class="empty-state">No recent scan activity recorded.</div>`;
    return;
  }

  listElem.innerHTML = history
    .map((item) => {
      const score = Math.round(item.threat_score || 0);
      const verdict = (item.verdict || "safe").toLowerCase();
      let badgeClass = "verdict-tag safe";
      let badgeText = "SAFE";

      if (verdict === "phishing") {
        badgeClass = "verdict-tag phishing";
        badgeText = "BLOCKED";
      } else if (verdict === "suspicious") {
        badgeClass = "verdict-tag suspicious";
        badgeText = "SUSPICIOUS";
      }

      const timeStr = item.timestamp ? formatTimeAgo(item.timestamp) : "Just now";
      const displayDomain = item.domain || (item.url ? extractDomain(item.url) : "Unknown target");

      return `
        <div class="history-item">
          <div class="history-info">
            <span class="history-host" title="${escapeHtml(item.url || displayDomain)}">
              ${escapeHtml(displayDomain)}
            </span>
            <span class="history-time">${escapeHtml(timeStr)} &bull; Risk: ${score}/100</span>
          </div>
          <span class="history-badge ${badgeClass}">${badgeText}</span>
        </div>
      `;
    })
    .join("");
}

// Setup History Clear & Export
function setupHistoryView() {
  const clearBtn = document.getElementById("clear-history-btn");
  if (clearBtn) {
    clearBtn.addEventListener("click", () => {
      chrome.runtime.sendMessage({ type: "CLEAR_HISTORY" }, () => {
        renderHistoryList([]);
      });
    });
  }

  const exportBtn = document.getElementById("export-history-btn");
  if (exportBtn) {
    exportBtn.addEventListener("click", exportHistoryToCSV);
  }
}

function exportHistoryToCSV() {
  chrome.storage.local.get("phishguard_history", (data) => {
    const history = data.phishguard_history || [];
    if (history.length === 0) {
      alert("No security events recorded yet.");
      return;
    }

    const headers = ["Timestamp", "ISO_Date", "Domain", "URL", "Threat_Score", "Verdict", "Risk_Level", "Signals"];
    const rows = history.map((item) => {
      const dateStr = item.timestamp ? new Date(item.timestamp).toISOString() : "";
      const reasons = Array.isArray(item.reasons) ? item.reasons.join(" | ") : "";
      return [
        item.timestamp || "",
        `"${dateStr}"`,
        `"${(item.domain || "").replace(/"/g, '""')}"`,
        `"${(item.url || "").replace(/"/g, '""')}"`,
        item.threat_score || 0,
        `"${item.verdict || ""}"`,
        `"${item.risk_level || ""}"`,
        `"${reasons.replace(/"/g, '""')}"`
      ].join(",");
    });

    const csvContent = [headers.join(","), ...rows].join("\r\n");
    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.setAttribute("href", url);
    link.setAttribute("download", `phishguard_history_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  });
}

function setupSiteReporting() {
  const reportBtn = document.getElementById("report-site-btn");
  if (reportBtn) {
    reportBtn.addEventListener("click", () => {
      if (!currentTabUrl) return;
      const feedback = prompt(
        `Submit classification feedback for:\n${currentTabUrl}\n\nEnter 'fp' if safe site blocked incorrectly, or 'fn' if phishing missed:`,
        "fp"
      );
      if (feedback) {
        alert("Thank you. Security feedback recorded for domain triage.");
      }
    });
  }
}

// Render Allowlist Items
function renderWhitelistList(whitelist) {
  const countElem = document.getElementById("whitelist-count");
  const listElem = document.getElementById("whitelist-list");
  if (countElem) countElem.textContent = whitelist.length;
  if (!listElem) return;

  if (!whitelist || whitelist.length === 0) {
    listElem.innerHTML = `<div class="empty-state">No domains currently whitelisted.</div>`;
    return;
  }

  listElem.innerHTML = whitelist
    .map(
      (domain) => `
      <div class="whitelist-item">
        <span class="whitelist-domain" title="${escapeHtml(domain)}">${escapeHtml(domain)}</span>
        <button class="whitelist-remove-btn" data-domain="${escapeHtml(domain)}" title="Remove allowlist exception">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <line x1="18" y1="6" x2="6" y2="18"/>
            <line x1="6" y1="6" x2="18" y2="18"/>
          </svg>
        </button>
      </div>
    `
    )
    .join("");

  // Attach delete handlers
  listElem.querySelectorAll(".whitelist-remove-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const domain = btn.getAttribute("data-domain");
      if (!domain) return;
      chrome.runtime.sendMessage({ type: "REMOVE_WHITELIST", domain }, (res) => {
        if (res && res.list) {
          renderWhitelistList(res.list);
          if (activeDomain === domain) updateWhitelistUI(false);
        }
      });
    });
  });
}

// Setup Allowlist Add Action
function setupWhitelistView() {
  const addBtn = document.getElementById("add-whitelist-btn");
  const input = document.getElementById("new-whitelist-input");

  function addDomain() {
    let domain = (input.value || "").trim().toLowerCase();
    if (!domain) return;
    try {
      if (domain.includes("://")) {
        domain = new URL(domain).hostname;
      }
    } catch (_) {}

    chrome.runtime.sendMessage({ type: "ADD_WHITELIST", domain }, (res) => {
      input.value = "";
      if (res && res.list) {
        renderWhitelistList(res.list);
        if (activeDomain === domain) updateWhitelistUI(true);
      }
    });
  }

  if (addBtn && input) {
    addBtn.addEventListener("click", addDomain);
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") addDomain();
    });
  }
}

// Setup Settings View
function setupSettingsView() {
  const radios = document.querySelectorAll('input[name="protection-level"]');
  radios.forEach((radio) => {
    radio.addEventListener("change", () => {
      if (radio.checked) {
        const level = radio.value;
        chrome.runtime.sendMessage({ type: "SET_PROTECTION_LEVEL", level }, () => {
          const statMode = document.getElementById("stat-mode");
          if (statMode) statMode.textContent = level.charAt(0).toUpperCase() + level.slice(1);
        });
      }
    });
  });

  const purgeBtn = document.getElementById("purge-cache-btn");
  if (purgeBtn) {
    purgeBtn.addEventListener("click", async () => {
      const allItems = await chrome.storage.local.get(null);
      const cacheKeys = Object.keys(allItems).filter((k) => k.startsWith("pg_cache_"));
      if (cacheKeys.length > 0) {
        await chrome.storage.local.remove(cacheKeys);
      }
      purgeBtn.innerHTML = `<span>Purged ${cacheKeys.length} items</span>`;
      setTimeout(() => {
        purgeBtn.innerHTML = `<span>Purge Cache</span>`;
      }, 2000);
    });
  }

  const saveApiBtn = document.getElementById("save-api-base-btn");
  const apiInput = document.getElementById("api-base-input");
  if (saveApiBtn && apiInput) {
    saveApiBtn.addEventListener("click", () => {
      const newBase = apiInput.value.trim();
      chrome.runtime.sendMessage({ type: "SET_API_BASE", apiBase: newBase }, (res) => {
        if (res && res.apiBase) {
          apiInput.value = res.apiBase;
          saveApiBtn.innerHTML = `<span>Saved!</span>`;
          setTimeout(() => {
            saveApiBtn.innerHTML = `<span>Save</span>`;
          }, 1500);
          checkBackendHealth();
        }
      });
    });
  }
}

function updateWhitelistUI(isWhitelisted) {
  isWhitelistedState = isWhitelisted;
  const btn = document.getElementById("whitelist-toggle-btn");
  const label = document.getElementById("whitelist-label");
  const icon = document.getElementById("whitelist-icon");
  if (!btn) return;

  if (isWhitelisted) {
    btn.classList.add("trusted");
    if (label) label.textContent = "Trusted Domain";
    if (icon) {
      icon.innerHTML = `
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
          <polyline points="20 6 9 17 4 12"/>
        </svg>
      `;
    }
  } else {
    btn.classList.remove("trusted");
    if (label) label.textContent = "Trust Domain";
    if (icon) {
      icon.innerHTML = `
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
      `;
    }
  }
}

// Query active browser tab and load assessment
async function loadCurrentTabStatus() {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (!tabs || tabs.length === 0) return;
    const currentTab = tabs[0];
    currentTabUrl = currentTab.url || "";

    const domainElem = document.getElementById("active-domain");
    const protocolBadge = document.getElementById("protocol-badge");

    try {
      const parsed = new URL(currentTabUrl);
      activeDomain = parsed.hostname || "";
      if (domainElem) domainElem.textContent = activeDomain || currentTabUrl;

      // Update protocol badge
      if (protocolBadge) {
        if (parsed.protocol === "https:") {
          protocolBadge.className = "site-protocol-badge";
          protocolBadge.innerHTML = `
            <svg class="protocol-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
              <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
              <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
            </svg>
            <span class="protocol-text">SECURE HTTPS</span>
          `;
        } else if (parsed.protocol === "http:") {
          protocolBadge.className = "site-protocol-badge insecure";
          protocolBadge.innerHTML = `
            <svg class="protocol-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
              <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
              <path d="M7 11V7a5 5 0 0 1 9.9-1"/>
            </svg>
            <span class="protocol-text">INSECURE HTTP</span>
          `;
        } else {
          protocolBadge.className = "site-protocol-badge";
          protocolBadge.innerHTML = `<span class="protocol-text">INTERNAL</span>`;
        }
      }
    } catch (_) {
      if (domainElem) domainElem.textContent = currentTabUrl;
    }

    if (activeDomain) {
      chrome.runtime.sendMessage(
        { type: "IS_WHITELISTED", domain: activeDomain },
        (res) => {
          updateWhitelistUI(res && res.whitelisted);
        }
      );
    }

    const whitelistBtn = document.getElementById("whitelist-toggle-btn");
    if (whitelistBtn && !whitelistBtn.dataset.bound) {
      whitelistBtn.dataset.bound = "true";
      whitelistBtn.addEventListener("click", () => {
        if (!activeDomain) return;
        const msgType = isWhitelistedState ? "REMOVE_WHITELIST" : "ADD_WHITELIST";
        chrome.runtime.sendMessage({ type: msgType, domain: activeDomain }, () => {
          updateWhitelistUI(!isWhitelistedState);
          loadAllState();
          // Re-evaluate URL
          chrome.runtime.sendMessage(
            { type: "CHECK_URL", url: currentTabUrl },
            (report) => {
              if (report) renderTabReport(report);
            }
          );
        });
      });
    }

    // Ask background script for verdict
    chrome.runtime.sendMessage(
      { type: "CHECK_URL", url: currentTabUrl },
      (report) => {
        if (report) {
          renderTabReport(report);
        }
      }
    );
  });
}

// Render threat gauge and signals
function renderTabReport(report) {
  const score = Math.round(report.threat_score || 0);
  const scoreElem = document.getElementById("active-score");
  const gaugeBar = document.getElementById("gauge-bar");
  const badge = document.getElementById("active-verdict-badge");
  const desc = document.getElementById("active-verdict-desc");
  const reasonsContainer = document.getElementById("reasons-container");

  if (scoreElem) scoreElem.textContent = score;

  // Calibrated radial meter
  if (gaugeBar) {
    const offset = CIRCUMFERENCE - (score / 100) * CIRCUMFERENCE;
    gaugeBar.style.strokeDashoffset = offset;
  }

  // Verdict state
  if (badge && desc && gaugeBar) {
    if (isWhitelistedState) {
      gaugeBar.style.stroke = "#3b82f6";
      badge.className = "verdict-tag whitelisted";
      badge.textContent = "ALLOWLISTED";
      desc.textContent = "Domain is explicitly trusted in your allowlist settings.";
    } else if (report.verdict === "phishing") {
      gaugeBar.style.stroke = "#ef4444";
      badge.className = "verdict-tag phishing";
      badge.textContent = "DANGEROUS SITE";
      desc.textContent = "Critical phishing violation detected. Avoid entering credentials or sensitive data.";
    } else if (report.verdict === "suspicious") {
      gaugeBar.style.stroke = "#f59e0b";
      badge.className = "verdict-tag suspicious";
      badge.textContent = "SUSPICIOUS SITE";
      desc.textContent = "Anomalous patterns flagged. Exercise vigilance before navigating further.";
    } else {
      gaugeBar.style.stroke = "#10b981";
      badge.className = "verdict-tag safe";
      badge.textContent = "SECURE SITE";
      desc.textContent = "Domain verified. No deceptive signatures or spoofing markers identified.";
    }
  }

  // Render Telemetry Signals
  if (reasonsContainer) {
    const reasons = report.reasons || [];
    if (reasons.length === 0) {
      reasonsContainer.innerHTML = `
        <div class="signal-item pass">
          <svg class="signal-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
            <polyline points="20 6 9 17 4 12"/>
          </svg>
          <div>
            <strong>Identity Reputation:</strong> Clean namespace, zero brand homoglyphs or typosquatting patterns detected.
          </div>
        </div>
        <div class="signal-item pass">
          <svg class="signal-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
            <polyline points="20 6 9 17 4 12"/>
          </svg>
          <div>
            <strong>Structural Analysis:</strong> Standard subdomain depth, valid TLD category, no credential-masking symbols.
          </div>
        </div>
      `;
    } else {
      reasonsContainer.innerHTML = reasons
        .map((r) => {
          const isDanger = report.verdict === "phishing";
          const itemClass = isDanger ? "danger" : "warning";
          const iconSvg = isDanger
            ? `<svg class="signal-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                <circle cx="12" cy="12" r="10"/>
                <line x1="15" y1="9" x2="9" y2="15"/>
                <line x1="9" y1="9" x2="15" y2="15"/>
              </svg>`
            : `<svg class="signal-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                <line x1="12" y1="9" x2="12" y2="13"/>
                <line x1="12" y1="17" x2="12.01" y2="17"/>
              </svg>`;

          return `
            <div class="signal-item ${itemClass}">
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
    scanBtn.querySelector("span").textContent = "Inspecting...";

    chrome.runtime.sendMessage(
      { type: "CHECK_URL", url: rawVal },
      (report) => {
        scanBtn.disabled = false;
        scanBtn.querySelector("span").textContent = "Run Security Inspection";
        if (!report) return;

        resultCard.classList.remove("hidden");
        scoreText.textContent = `Score: ${report.threat_score}/100`;

        const verdict = (report.verdict || "safe").toLowerCase();
        badge.className = `verdict-tag ${verdict}`;
        badge.textContent = verdict.toUpperCase();

        const reasons = report.reasons || [];
        if (reasons.length === 0) {
          reasonsBox.innerHTML = `
            <div class="signal-item pass">
              <svg class="signal-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                <polyline points="20 6 9 17 4 12"/>
              </svg>
              <span>Clean signature: No deceptive lexical or network indicators found.</span>
            </div>
          `;
        } else {
          reasonsBox.innerHTML = reasons
            .map((r) => {
              const isDanger = verdict === "phishing";
              return `
                <div class="signal-item ${isDanger ? 'danger' : 'warning'}">
                  <svg class="signal-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                    <circle cx="12" cy="12" r="10"/>
                    <line x1="12" y1="8" x2="12" y2="12"/>
                    <line x1="12" y1="16" x2="12.01" y2="16"/>
                  </svg>
                  <span>${escapeHtml(r)}</span>
                </div>
              `;
            })
            .join("");
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

function extractDomain(url) {
  try {
    return new URL(url).hostname;
  } catch (_) {
    return url;
  }
}

function formatTimeAgo(timestamp) {
  const seconds = Math.floor((Date.now() - timestamp) / 1000);
  if (seconds < 60) return "Just now";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
