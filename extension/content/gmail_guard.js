/**
 * PhishGuard AI - Gmail Inbox & Email Content Guard
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
    container.setAttribute(PROCESSED_ATTR, "true");

    // 1. Extract sender element (standard Gmail selector)
    const senderElem = container.querySelector(".gD") || container.querySelector("[email]");
    const senderName = senderElem ? senderElem.innerText.replace(/<[^>]+>/g, "").trim() : "Unknown";
    let senderEmail = senderElem ? (senderElem.getAttribute("email") || "").trim() : "";
    if (!senderEmail && senderElem) {
      const emailMatch = senderElem.innerText.match(/[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}/);
      if (emailMatch) {
        senderEmail = emailMatch[0];
      }
    }

    // 2. Extract subject line
    const subjectElem = document.querySelector(".hP") || document.querySelector("h2");
    const subject = subjectElem ? subjectElem.innerText.trim() : "";

    // 3. Extract body text
    const bodyElem = container.querySelector(".a3s.aiL") || container.querySelector(".ii.gt");
    if (!bodyElem) return;

    const bodyText = bodyElem.innerText.slice(0, 3000); // Sample first 3000 chars

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

    // 5. Send to background worker for deep ML & heuristic analysis
    chrome.runtime.sendMessage(
      {
        type: "CHECK_EMAIL",
        payload: {
          sender_name: senderName,
          sender_email: senderEmail,
          subject,
          body_text: bodyText,
          links: links.slice(0, 10) // Limit to top 10 unique links
        }
      },
      (report) => {
        if (!report) return;
        injectEmailSecurityCard(bodyElem, report);
      }
    );
  }


  function injectEmailSecurityCard(bodyElem, report) {
    // Avoid double injection
    if (bodyElem.parentNode.querySelector(".phishguard-email-card")) return;

    const card = document.createElement("div");
    card.className = `phishguard-email-card pg-${report.verdict}`;

    let iconSvg = "";
    let statusTitle = "";

    if (report.verdict === "phishing") {
      iconSvg = `
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
          <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
          <line x1="12" y1="9" x2="12" y2="13"/>
          <line x1="12" y1="17" x2="12.01" y2="17"/>
        </svg>
      `;
      statusTitle = "High Threat &bull; Phishing / BEC Scam Detected";
    } else if (report.verdict === "suspicious") {
      iconSvg = `
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="12" cy="12" r="10"/>
          <line x1="12" y1="8" x2="12" y2="12"/>
          <line x1="12" y1="16" x2="12.01" y2="16"/>
        </svg>
      `;
      statusTitle = "Caution &bull; Suspicious Email Indicators";
    } else {
      iconSvg = `
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
          <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
          <polyline points="22 4 12 14.01 9 11.01"/>
        </svg>
      `;
      statusTitle = "Protected &bull; Verified Safe Communication";
    }

    const reasonList = (report.reasons || [])
      .map((r) => `<li>${escapeHtml(r)}</li>`)
      .join("");

    card.innerHTML = `
      <div class="pg-email-badge">
        <span>${iconSvg}</span>
        <span>${statusTitle}</span>
        <span class="pg-email-score-tag">Risk Score: ${report.threat_score}/100</span>
      </div>
      <div class="pg-email-details">
        ${
          report.verdict !== "safe"
            ? `<div>Security findings identified in this message:</div>
               <ul>${reasonList}</ul>`
            : `<div>No sender domain spoofing, urgency traps, or high-risk hyperlinks detected.</div>`
        }
      </div>
    `;

    // Insert card immediately before email body
    bodyElem.parentNode.insertBefore(card, bodyElem);
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
