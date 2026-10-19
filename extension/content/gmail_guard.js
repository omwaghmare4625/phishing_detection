/**
 * PhishGuard Security - Gmail Inbox & Email Content Guard
 * Automatically observes opened emails in Gmail, extracts sender & link features,
 * and renders an in-context trust assessment card.
 */

(function () {
  const PROCESSED_ATTR = "data-phishguard-scanned";

  const GMAIL_INTERNAL_HOSTS = new Set([
    "mail.google.com",
    "contacts.google.com",
    "clients6.google.com",
    "hangouts.google.com",
    "chat.google.com"
  ]);

  function unwrapUrl(url) {
    if (!url) return "";
    try {
      const parsed = new URL(url);
      if (parsed.hostname === "www.google.com" || parsed.hostname === "google.com") {
        if (parsed.pathname === "/url") {
          const q = parsed.searchParams.get("q") || parsed.searchParams.get("url");
          if (q) return q;
        }
      }
    } catch (_) {}
    return url;
  }

  function isInternalGmailLink(url) {
    try {
      const parsed = new URL(url);
      if (GMAIL_INTERNAL_HOSTS.has(parsed.hostname.toLowerCase())) {
        return true;
      }
      if (parsed.searchParams.has("attid") || (parsed.searchParams.get("view") === "att")) {
        return true;
      }
    } catch (_) {}
    return false;
  }

  function scanEmailContainer(container) {
    if (container.hasAttribute(PROCESSED_ATTR)) return;

    // 1. Extract body text first - wait until Gmail renders body DOM
    const bodyElem = container.querySelector(".a3s.aiL") || container.querySelector(".ii.gt");
    if (!bodyElem) return;

    const bodyText = (bodyElem.innerText || "").slice(0, 3000);
    if (!bodyText.trim()) return;

    // Check if user disabled Gmail protection or Master protection
    chrome.storage.local.get(["phishguard_protection_enabled", "phishguard_gmail_enabled"], (settings) => {
      if (settings && (settings.phishguard_protection_enabled === false || settings.phishguard_gmail_enabled === false)) {
        return;
      }

      container.setAttribute(PROCESSED_ATTR, "true");

      // 2. Extract sender element (standard Gmail selector)
      const senderElem = container.querySelector(".gD") || container.querySelector("[email]");
      const senderName = senderElem ? senderElem.innerText.replace(/<[^>]+>/g, "").trim() : "Unknown";
      let senderEmail = senderElem ? (senderElem.getAttribute("email") || "").trim() : "";
      if (!senderEmail && senderElem) {
        const emailMatch = senderElem.innerText.match(/[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}/);
        if (emailMatch) {
          senderEmail = emailMatch[0];
        }
      }

      // 3. Extract subject line
      const subjectElem = document.querySelector(".hP") || document.querySelector("h2");
      const subject = subjectElem ? subjectElem.innerText.trim() : "";

      // 4. Extract embedded links (filtering internal Gmail controls & attachments)
      const linkElems = bodyElem.querySelectorAll("a[href]");
      const links = [];
      linkElems.forEach((a) => {
        let href = a.getAttribute("href");
        if (!href) return;
        href = href.trim();
        if (href.startsWith("#") || href.startsWith("mailto:") || href.startsWith("javascript:") || href.startsWith("tel:")) {
          return;
        }
        const unwrapped = unwrapUrl(href);
        if (!isInternalGmailLink(unwrapped) && !links.includes(unwrapped)) {
          links.push(unwrapped);
        }
      });

      // 4b. Extract embedded images for Quishing QR code detection
      const imgElems = bodyElem.querySelectorAll("img[src]");
      const imageUrls = [];
      imgElems.forEach((img) => {
        const src = (img.getAttribute("src") || "").trim();
        if (!src) return;
        if (img.width === 1 || img.height === 1) return;
        if ((src.startsWith("data:image/") || src.startsWith("http://") || src.startsWith("https://")) && !imageUrls.includes(src)) {
          imageUrls.push(src);
        }
      });

      // 5. Send to background worker for deep threat & heuristic analysis
      chrome.runtime.sendMessage(
        {
          type: "CHECK_EMAIL",
          payload: {
            sender_name: senderName,
            sender_email: senderEmail,
            subject,
            body_text: bodyText,
            links: links.slice(0, 10), // Limit to top 10 unique links
            image_urls: imageUrls.slice(0, 6) // Pass images for quishing analysis
          }
        },
        (report) => {
          if (!report || typeof report !== "object" || report.threat_score === undefined) return;
          injectEmailSecurityCard(bodyElem, report);
        }
      );
    });
  }


  function injectEmailSecurityCard(bodyElem, report) {
    // Avoid double injection
    if (bodyElem.parentNode.querySelector(".phishguard-email-card")) return;

    const card = document.createElement("div");
    const verdict = (report.verdict || "safe").toLowerCase();
    card.className = `phishguard-email-card pg-${verdict}`;

    let iconSvg = "";
    let verdictText = "";

    if (verdict === "phishing") {
      iconSvg = `
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#EF4444" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
          <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
          <line x1="12" y1="9" x2="12" y2="13"/>
          <line x1="12" y1="17" x2="12.01" y2="17"/>
        </svg>
      `;
      verdictText = "Phishing suspected";
    } else if (verdict === "suspicious") {
      iconSvg = `
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#F59E0B" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="12" cy="12" r="10"/>
          <line x1="12" y1="8" x2="12" y2="12"/>
          <line x1="12" y1="16" x2="12.01" y2="16"/>
        </svg>
      `;
      verdictText = "Suspicious email";
    } else {
      iconSvg = `
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#10B981" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
          <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
          <polyline points="22 4 12 14.01 9 11.01"/>
        </svg>
      `;
      verdictText = "Safe email";
    }

    const reasons = report.reasons || [];
    const reasonsStr = reasons.join(" ").toLowerCase();

    // 1. Brand Spoofing check
    let brandStatus = "Verified: display name matches sender domain.";
    if (reasonsStr.includes("spoof") || reasonsStr.includes("claims brand") || reasonsStr.includes("mismatch")) {
      const match = reasons.find(r => r.toLowerCase().includes("brand") || r.toLowerCase().includes("spoof"));
      brandStatus = match || "Sender display name does not match originating domain.";
    }

    // 2. Urgency language check
    let urgencyStatus = "No urgency pressure or credential traps detected.";
    if (reasonsStr.includes("urgency") || reasonsStr.includes("nlp") || reasonsStr.includes("social engineering")) {
      const match = reasons.find(r => r.toLowerCase().includes("urgency") || r.toLowerCase().includes("nlp") || r.toLowerCase().includes("phishing language"));
      urgencyStatus = match || "Urgent call-to-action requesting credential review detected.";
    }

    // 3. Links analysed
    const analyzedLinks = report.analyzed_links || [];
    let linksHtml = "";
    if (analyzedLinks.length > 0) {
      linksHtml = analyzedLinks
        .map(l => `
          <div class="pg-link-item ${l.threat_score >= 70 ? 'danger' : (l.threat_score >= 40 ? 'warning' : 'safe')}">
            <span class="pg-link-url" title="${escapeHtml(l.url)}">${escapeHtml(l.url)}</span>
            <span class="pg-link-score">Score: ${l.threat_score}/100</span>
          </div>
        `).join("");
    } else if (report.link_count === 0) {
      linksHtml = `<div class="pg-link-empty">No embedded hyperlinks found in message body.</div>`;
    } else {
      linksHtml = `<div class="pg-link-empty">${report.link_count} link(s) scanned and verified.</div>`;
    }

    // 4. Quishing QR Code check
    const quishingFindings = report.quishing_findings || [];
    let quishingHtml = "";
    if (quishingFindings.length > 0) {
      quishingHtml = `
        <div class="pg-detail-row pg-detail-quishing">
          <span class="pg-detail-label">Quishing (QR Defense):</span>
          <div class="pg-quishing-list">
            ${quishingFindings.map(q => `
              <div class="pg-quishing-item ${q.destination_threat_score >= 70 ? 'danger' : 'warning'}">
                <span class="pg-qr-badge">QR CODE</span>
                <span class="pg-qr-dest" title="${escapeHtml(q.payload)}">Points to: ${escapeHtml(q.payload)}</span>
                <span class="pg-qr-score">Score: ${q.destination_threat_score}/100</span>
              </div>
            `).join('')}
          </div>
        </div>
      `;
    }

    // 5. Dual-Engine Telemetry (ML + Heuristic)
    const breakdown = report.scoring_breakdown;
    let breakdownHtml = "";
    if (breakdown) {
      breakdownHtml = `
        <div class="pg-detail-row pg-detail-scoring">
          <span class="pg-detail-label">Engine Telemetry:</span>
          <span class="pg-detail-val pg-scoring-tags">
            <span class="pg-tag-chip">ML Score: ${breakdown.ml_score}/100</span>
            <span class="pg-tag-chip">Heuristic Penalty: ${breakdown.heuristic_score}/100</span>
            <span class="pg-tag-chip">Combined: ${breakdown.final_threat_score}/100</span>
          </span>
        </div>
      `;
    }

    card.innerHTML = `
      <div class="pg-email-header-bar">
        <div class="pg-email-status-group">
          <span class="pg-email-icon">${iconSvg}</span>
          <span class="pg-email-verdict">${verdictText}</span>
          <span class="pg-email-score-tag">Risk: ${report.threat_score}/100</span>
        </div>
        <button class="pg-email-toggle-btn" type="button" aria-expanded="false">
          <span>Details</span>
          <svg class="pg-chevron" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="6 9 12 15 18 9"/>
          </svg>
        </button>
      </div>

      <div class="pg-email-details-drawer">
        <div class="pg-detail-row">
          <span class="pg-detail-label">Brand Spoofing:</span>
          <span class="pg-detail-val">${escapeHtml(brandStatus)}</span>
        </div>
        <div class="pg-detail-row">
          <span class="pg-detail-label">Urgency Language:</span>
          <span class="pg-detail-val">${escapeHtml(urgencyStatus)}</span>
        </div>
        ${quishingHtml}
        ${breakdownHtml}
        <div class="pg-detail-row pg-detail-links">
          <span class="pg-detail-label">Links Analysed (${report.link_count || analyzedLinks.length}):</span>
          <div class="pg-links-list">
            ${linksHtml}
          </div>
        </div>
      </div>
    `;

    // Insert card immediately before email body
    bodyElem.parentNode.insertBefore(card, bodyElem);

    // Highlight any suspicious or phishing links directly in the email body
    highlightInlineLinks(bodyElem, analyzedLinks);

    // Expand/collapse details row on click
    const toggleBtn = card.querySelector(".pg-email-toggle-btn");
    const drawer = card.querySelector(".pg-email-details-drawer");
    if (toggleBtn && drawer) {
      toggleBtn.addEventListener("click", () => {
        const isExpanded = card.classList.toggle("expanded");
        toggleBtn.setAttribute("aria-expanded", String(isExpanded));
      });
    }
  }

  function highlightInlineLinks(bodyElem, analyzedLinks) {
    if (!analyzedLinks || analyzedLinks.length === 0) return;

    const linkMap = new Map();
    analyzedLinks.forEach((item) => {
      if (item && item.url) {
        linkMap.set(item.url.toLowerCase().trim(), item);
        try {
          const u = new URL(item.url);
          linkMap.set((u.origin + u.pathname).toLowerCase().trim(), item);
          linkMap.set(u.hostname.toLowerCase().trim(), item);
        } catch (_) {}
      }
    });

    const anchors = bodyElem.querySelectorAll("a[href]");
    anchors.forEach((a) => {
      if (a.hasAttribute("data-phishguard-badged")) return;
      const rawHref = a.getAttribute("href") || "";
      const unwrapped = unwrapUrl(rawHref).trim();
      if (!unwrapped) return;

      const lower = unwrapped.toLowerCase();
      let match = linkMap.get(lower);
      if (!match) {
        try {
          const u = new URL(unwrapped);
          match = linkMap.get((u.origin + u.pathname).toLowerCase().trim()) || linkMap.get(u.hostname.toLowerCase().trim());
        } catch (_) {}
      }

      if (match && match.threat_score >= 40.0) {
        a.setAttribute("data-phishguard-badged", "true");
        const isPhish = match.threat_score >= 70.0;
        a.classList.add("phishguard-inline-link", isPhish ? "pg-flagged-phish" : "pg-flagged-warn");

        const badge = document.createElement("span");
        badge.className = `phishguard-inline-badge ${isPhish ? 'pg-inline-danger' : 'pg-inline-warning'}`;
        badge.setAttribute("tabindex", "0");
        badge.setAttribute("role", "note");
        badge.setAttribute("aria-label", `${isPhish ? 'Phishing' : 'Suspicious'} link detected`);

        const reasonsSnippet = (match.reasons && match.reasons.length > 0)
          ? match.reasons.slice(0, 2).join("; ")
          : (isPhish ? "Malicious phishing destination identified" : "Suspicious link attributes detected");

        badge.innerHTML = `
          <span class="pg-badge-icon">${isPhish ? "⚠️" : "⚡"}</span>
          <span class="pg-badge-text">${isPhish ? "PHISHING LINK" : "SUSPICIOUS LINK"}</span>
          <span class="phishguard-inline-tooltip">
            <span class="pg-tip-heading">${isPhish ? "Deceptive Link Blocked" : "Caution: Suspicious Link"}</span>
            <span class="pg-tip-metrics">Threat Score: <strong>${match.threat_score}/100</strong></span>
            <span class="pg-tip-url" title="${escapeHtml(unwrapped)}">${escapeHtml(unwrapped)}</span>
            <span class="pg-tip-reason">${escapeHtml(reasonsSnippet)}</span>
          </span>
        `;

        if (a.nextSibling) {
          a.parentNode.insertBefore(badge, a.nextSibling);
        } else {
          a.parentNode.appendChild(badge);
        }
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

  // Observe Gmail dynamic DOM for opened email containers
  const observer = new MutationObserver(() => {
    // Gmail email containers: .adn.ads or .gs
    const containers = document.querySelectorAll(".adn.ads, .gs");
    containers.forEach(scanEmailContainer);
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true
  });
})();
