/**
 * PhishGuard Security - URL Guard Content Script
 * Intercepts malicious web navigation and renders security barrier.
 */

(function () {
  let hasInjected = false;

  function renderBlockOverlay(report) {
    if (document.getElementById("phishguard-block-overlay")) return;

    const overlay = document.createElement("div");
    overlay.id = "phishguard-block-overlay";

    const defaultReasons = [
      "Typosquatting brand impersonation detected",
      "Domain registered under 30 days ago",
      "Deceptive credential-harvesting triggers flagged"
    ];

    const reasonsList = (report.reasons && report.reasons.length > 0)
      ? report.reasons.slice(0, 3)
      : defaultReasons;

    const reasonItems = reasonsList
      .map((r) => `<li>${escapeHtml(r)}</li>`)
      .join("");

    overlay.innerHTML = `
      <div class="pg-block-card">
        <div class="pg-block-header-group">
          <div class="pg-block-icon-badge" aria-hidden="true">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#EF4444" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              <line x1="12" y1="8" x2="12" y2="12"/>
              <line x1="12" y1="16" x2="12.01" y2="16"/>
            </svg>
          </div>
          <div class="pg-block-title-box">
            <div class="pg-block-title-row">
              <h1 class="pg-block-title">Deceptive site blocked</h1>
              <span class="pg-risk-score-chip">Risk: ${report.threat_score}/100</span>
            </div>
            <div class="pg-block-url-chip">
              <code>${escapeHtml(window.location.href)}</code>
            </div>
          </div>
        </div>

        <p class="pg-block-desc">
          PhishGuard AI intercepted navigation to this destination because it was identified as a dangerous credential-harvesting or impersonation site.
        </p>

        <div class="pg-reasons-box">
          <div class="pg-reasons-header">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="12" cy="12" r="10"/>
              <line x1="12" y1="8" x2="12" y2="12"/>
              <line x1="12" y1="16" x2="12.01" y2="16"/>
            </svg>
            <span>Primary Threat Indicators:</span>
          </div>
          <ul class="pg-reasons-list">
            ${reasonItems}
          </ul>
        </div>

        <div class="pg-btn-group">
          <button class="pg-btn pg-btn-primary" id="pg-btn-retreat">
            Take me to safety
          </button>
          <button class="pg-btn pg-btn-secondary" id="pg-btn-whitelist">
            Trust this domain
          </button>
          <button class="pg-btn pg-btn-link" id="pg-btn-ignore">
            I understand the risk, continue
          </button>
        </div>
      </div>
    `;

    document.documentElement.appendChild(overlay);

    document.getElementById("pg-btn-retreat").addEventListener("click", () => {
      if (window.history.length > 1) {
        window.history.back();
      } else {
        window.location.href = "https://www.google.com";
      }
    });

    document.getElementById("pg-btn-whitelist").addEventListener("click", () => {
      chrome.runtime.sendMessage({
        type: "ADD_WHITELIST",
        domain: window.location.hostname
      }, () => {
        overlay.remove();
      });
    });

    document.getElementById("pg-btn-ignore").addEventListener("click", () => {
      overlay.remove();
    });
  }

  function renderTopBanner(report) {
    if (document.getElementById("phishguard-top-banner")) return;

    const banner = document.createElement("div");
    banner.id = "phishguard-top-banner";

    banner.innerHTML = `
      <div class="pg-banner-content">
        <span class="pg-banner-badge">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
            <line x1="12" y1="9" x2="12" y2="13"/>
            <line x1="12" y1="17" x2="12.01" y2="17"/>
          </svg>
          Suspicious
        </span>
        <span class="pg-banner-text">
          Caution: PhishGuard AI detected anomalies on this site (Risk Score: ${report.threat_score}/100). Do not enter credentials or confidential data.
        </span>
      </div>
      <div class="pg-banner-actions">
        <button class="pg-banner-action-btn" id="pg-banner-back">Leave Site</button>
        <button class="pg-banner-close" title="Dismiss">&times;</button>
      </div>
    `;

    document.documentElement.appendChild(banner);

    const backBtn = banner.querySelector("#pg-banner-back");
    if (backBtn) {
      backBtn.addEventListener("click", () => {
        if (window.history.length > 1) {
          window.history.back();
        } else {
          window.location.href = "https://www.google.com";
        }
      });
    }

    banner.querySelector(".pg-banner-close").addEventListener("click", () => {
      banner.remove();
    });
  }

  function handleVerdict(report) {
    if (!report || hasInjected) return;
    chrome.storage.local.get("phishguard_protection_enabled", (data) => {
      if (data && data.phishguard_protection_enabled === false) return;
      if (report.verdict === "phishing") {
        hasInjected = true;
        renderBlockOverlay(report);
      } else if (report.verdict === "suspicious") {
        hasInjected = true;
        renderTopBanner(report);
      }
    });
  }

  function escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  // Disguised Link Hover Inspector
  function setupLinkHoverInspector() {
    let tooltip = null;

    function getOrCreateTooltip() {
      if (!tooltip) {
        tooltip = document.createElement("div");
        tooltip.id = "phishguard-link-tooltip";
        tooltip.className = "phishguard-link-tooltip hidden";
        document.documentElement.appendChild(tooltip);
      }
      return tooltip;
    }

    function removeTooltip() {
      if (tooltip) {
        tooltip.classList.add("hidden");
      }
    }

    const KNOWN_BRANDS = [
      "paypal", "google", "apple", "microsoft", "amazon",
      "chase", "bankofamerica", "wellsfargo", "netflix", "facebook", "instagram"
    ];

    document.addEventListener("mouseover", (e) => {
      const link = e.target.closest("a[href]");
      if (!link) return;

      const rawHref = link.getAttribute("href") || "";
      if (!rawHref || rawHref.startsWith("#") || rawHref.startsWith("javascript:") || rawHref.startsWith("mailto:")) return;

      let targetUrl;
      try {
        targetUrl = new URL(link.href);
      } catch (_) {
        return;
      }

      const targetHost = targetUrl.hostname.toLowerCase();
      const linkText = (link.innerText || "").trim().toLowerCase();
      let alertMsg = null;
      let badgeType = "warning";

      // 1. Text displays a domain or URL that does not match actual target host
      const domainRegex = /([a-z0-9-]+\.(?:com|org|net|edu|gov|io|co|ai|app))/i;
      const textDomainMatch = linkText.match(domainRegex);
      if (textDomainMatch) {
        const textDomain = textDomainMatch[1].toLowerCase();
        if (targetHost !== textDomain && !targetHost.endsWith("." + textDomain)) {
          alertMsg = `Deceptive Link! Text claims '${textDomain}' but navigates to '${targetHost}'`;
          badgeType = "danger";
        }
      }

      // 2. Text claims brand name but target host is third-party
      if (!alertMsg) {
        for (const brand of KNOWN_BRANDS) {
          if (linkText.includes(brand) && !targetHost.includes(brand)) {
            alertMsg = `Suspicious Anchor! Text mentions '${brand}' but target domain is '${targetHost}'`;
            badgeType = "danger";
            break;
          }
        }
      }

      // 3. Raw IP address or credential @ in target
      if (!alertMsg) {
        if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(targetHost)) {
          alertMsg = `Risk: Destination is a raw numerical IP address (${targetHost})`;
          badgeType = "danger";
        } else if (rawHref.includes("@")) {
          alertMsg = `Risk: Credential masking syntax '@' detected in link destination`;
          badgeType = "danger";
        } else if (/\.(xyz|top|click|buzz|cf|gq|zip)$/i.test(targetHost) && targetHost !== window.location.hostname) {
          alertMsg = `Caution: High-risk TLD (${targetHost})`;
          badgeType = "warning";
        }
      }

      if (alertMsg) {
        const tip = getOrCreateTooltip();
        tip.className = `phishguard-link-tooltip pg-tip-${badgeType}`;
        tip.innerHTML = `
          <div class="pg-tip-header">
            <span class="pg-tip-icon">${badgeType === "danger" ? "🚨" : "⚠️"}</span>
            <strong>PhishGuard Link Shield</strong>
          </div>
          <div class="pg-tip-body">${escapeHtml(alertMsg)}</div>
          <div class="pg-tip-dest">Target: <span>${escapeHtml(targetHost)}</span></div>
        `;

        const rect = link.getBoundingClientRect();
        const top = window.scrollY + rect.bottom + 6;
        const left = Math.max(10, Math.min(window.scrollX + rect.left, window.innerWidth - 320));

        tip.style.top = `${top}px`;
        tip.style.left = `${left}px`;
        tip.classList.remove("hidden");
      }
    });

    document.addEventListener("mouseout", (e) => {
      const link = e.target.closest("a[href]");
      if (link) {
        removeTooltip();
      }
    });

    window.addEventListener("scroll", removeTooltip, { passive: true });
  }

  // Initialize hover inspector
  setupLinkHoverInspector();

  // Request security check on load
  chrome.runtime.sendMessage(
    { type: "CHECK_URL", url: window.location.href },
    (response) => {
      if (response) handleVerdict(response);
    }
  );

  // Listen for broadcast from background worker
  chrome.runtime.onMessage.addListener((message) => {
    if (message.type === "PHISHGUARD_SHOW_WARNING") {
      handleVerdict(message.report);
    }
  });
})();

