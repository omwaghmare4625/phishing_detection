/**
 * PhishGuard AI - Background Service Worker (v1.1)
 * Features:
 * - Persistent chrome.storage.local caching with 1-hour TTL
 * - Deep offline fallback heuristic engine
 * - User allowlist / whitelist management
 * - Real-time navigation interception & tab security status
 */

const DEFAULT_API_BASE = "http://127.0.0.1:8000";
const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour
const memoryCache = new Map();

/**
 * Fetch dynamic API base URL from storage or fallback to default.
 */
async function getApiBase() {
  try {
    const data = await chrome.storage.local.get("phishguard_api_base");
    if (data && data.phishguard_api_base && data.phishguard_api_base.trim()) {
      return data.phishguard_api_base.trim().replace(/\/+$/, "");
    }
  } catch (_) {}
  return DEFAULT_API_BASE;
}

// Default offline brands (syncs dynamically from backend /api/health)
const DEFAULT_OFFLINE_BRANDS = [
  "google", "paypal", "microsoft", "apple", "amazon",
  "netflix", "facebook", "chase", "bankofamerica", "coinbase"
];

let dynamicBrands = null;

async function getProtectedBrands() {
  if (dynamicBrands && dynamicBrands.length > 0) return dynamicBrands;
  try {
    const data = await chrome.storage.local.get("phishguard_synced_brands");
    if (data && data.phishguard_synced_brands && data.phishguard_synced_brands.length > 0) {
      dynamicBrands = data.phishguard_synced_brands;
      return dynamicBrands;
    }
  } catch (_) {}
  return DEFAULT_OFFLINE_BRANDS;
}

async function syncBackendConfig() {
  try {
    const apiBase = await getApiBase();
    const res = await fetch(`${apiBase}/api/health`);
    if (res.ok) {
      const data = await res.json();
      if (data.popular_brands && Array.isArray(data.popular_brands)) {
        dynamicBrands = data.popular_brands;
        chrome.storage.local.set({ phishguard_synced_brands: data.popular_brands });
      }
    }
  } catch (_) {}
}


/**
 * Fast Levenshtein distance for client-side offline heuristics.
 */
function clientLevenshtein(a, b) {
  if (a.length < b.length) return clientLevenshtein(b, a);
  if (b.length === 0) return a.length;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 0; i < a.length; i++) {
    const curr = [i + 1];
    for (let j = 0; j < b.length; j++) {
      const ins = prev[j + 1] + 1;
      const del = curr[j] + 1;
      const sub = prev[j] + (a[i] !== b[j] ? 1 : 0);
      curr.push(Math.min(ins, del, sub));
    }
    prev = curr;
  }
  return prev[prev.length - 1];
}

/**
 * Robust client-side fallback heuristic when backend is offline.
 */
function clientSideFallbackCheck(urlString) {
  try {
    const url = new URL(urlString);
    const host = url.hostname.toLowerCase();
    const pathname = (url.pathname || "").toLowerCase();
    const full = (host + pathname).toLowerCase();
    const flags = [];
    let score = 0;

    // 1. IP address host
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host)) {
      flags.push("Host is a raw IP address");
      score += 55;
    }

    // 2. Punycode / IDN homograph
    if (host.includes("xn--")) {
      flags.push("Punycode / IDN homograph encoding detected");
      score += 45;
    }

    // 3. Credential masking via @ symbol
    if (urlString.includes("@")) {
      flags.push("URL contains embedded '@' symbol for credential masking");
      score += 40;
    }

    // 4. Double slash redirect trick in path
    if (pathname.includes("//")) {
      flags.push("URL path contains double slash redirect sequence");
      score += 25;
    }

    // 5. Suspicious / high-risk TLD
    if (/\.(xyz|top|tk|ml|ga|cf|gq|buzz|click|zip|cam|loan|fit)$/i.test(host)) {
      flags.push("High-risk top level domain frequently abused in phishing");
      score += 30;
    }

    // 6. Excessive subdomains
    const domainParts = host.split(".");
    if (domainParts.length > 4) {
      flags.push(`Excessive subdomain nesting (${domainParts.length - 2} levels)`);
      score += 20;
    }

    // 7. Sensitive authentication keywords in path/host
    const authKeywords = ["login", "verify", "account", "security", "update", "password", "banking"];
    const matchedKws = authKeywords.filter((k) => full.includes(k));
    if (matchedKws.length > 0) {
      flags.push(`Contains credential-harvesting keyword(s): ${matchedKws.join(", ")}`);
      score += 25;
    }

    // 8. Brand typosquatting check
    const activeBrands = dynamicBrands && dynamicBrands.length > 0 ? dynamicBrands : DEFAULT_OFFLINE_BRANDS;
    const subTokens = host.split(/[-_.]/).filter((t) => t.length >= 4);
    for (const token of subTokens) {
      const normToken = token.replace(/0/g, "o").replace(/1/g, "l").replace(/rn/g, "m");
      for (const brand of activeBrands) {
        if (normToken === brand && !host.endsWith(`.${brand}.com`) && host !== `${brand}.com`) {
          flags.push(`Domain impersonates popular brand: '${brand}'`);
          score += 45;
          break;
        }
        const dist = clientLevenshtein(normToken, brand);
        if (dist === 1 && brand.length >= 5) {
          flags.push(`Domain appears to typosquat brand: '${brand}'`);
          score += 45;
          break;
        }
      }
    }

    score = Math.min(score, 95);
    const verdict = score >= 70 ? "phishing" : score >= 40 ? "suspicious" : "safe";
    return {
      url: urlString,
      threat_score: score,
      verdict,
      risk_level: score >= 70 ? "HIGH" : score >= 40 ? "MEDIUM" : "LOW",
      reasons: flags.length > 0 ? flags : ["Offline client heuristics scanned: no critical threats detected"],
      ml_probability: 0.0,
      offline_fallback: true
    };
  } catch (e) {
    return { url: urlString, threat_score: 0, verdict: "safe", risk_level: "LOW", reasons: [] };
  }
}

/**
 * Protection Sensitivity Levels
 * - aggressive: threat_score >= 50 is phishing, >= 25 is suspicious
 * - balanced (default): threat_score >= 70 is phishing, >= 40 is suspicious
 * - permissive: threat_score >= 85 is phishing, >= 60 is suspicious
 */
async function getProtectionLevel() {
  const data = await chrome.storage.local.get("phishguard_protection_level");
  return data.phishguard_protection_level || "balanced";
}

function applyProtectionLevel(report, level) {
  if (report.whitelisted) return report;
  const score = report.threat_score || 0;
  let verdict = "safe";
  let risk_level = "LOW";

  if (level === "aggressive") {
    if (score >= 50) {
      verdict = "phishing";
      risk_level = "CRITICAL";
    } else if (score >= 25) {
      verdict = "suspicious";
      risk_level = "MEDIUM";
    }
  } else if (level === "permissive") {
    if (score >= 85) {
      verdict = "phishing";
      risk_level = "HIGH";
    } else if (score >= 60) {
      verdict = "suspicious";
      risk_level = "MEDIUM";
    }
  } else {
    // balanced default
    if (score >= 70) {
      verdict = "phishing";
      risk_level = "HIGH";
    } else if (score >= 40) {
      verdict = "suspicious";
      risk_level = "MEDIUM";
    }
  }

  return {
    ...report,
    verdict,
    risk_level,
    applied_level: level
  };
}

/**
 * Record scan metrics and store rolling history in chrome.storage.local.
 */
async function recordScanStatsAndHistory(report) {
  if (!report || !report.url || report.url.startsWith("chrome://") || report.url.startsWith("about:")) return;

  try {
    const data = await chrome.storage.local.get(["phishguard_stats", "phishguard_history"]);
    const stats = data.phishguard_stats || { totalScans: 0, threatsNeutralized: 0 };
    stats.totalScans = (stats.totalScans || 0) + 1;

    if (report.verdict === "phishing" || report.verdict === "suspicious") {
      stats.threatsNeutralized = (stats.threatsNeutralized || 0) + 1;
    }

    const history = Array.isArray(data.phishguard_history) ? data.phishguard_history : [];
    let domain = report.url;
    try {
      domain = new URL(report.url).hostname;
    } catch (_) {}

    const historyEntry = {
      url: report.url,
      domain,
      threat_score: report.threat_score || 0,
      verdict: report.verdict || "safe",
      risk_level: report.risk_level || "LOW",
      timestamp: Date.now()
    };

    // Keep unique recent domains or unshift, capped at 30 entries
    const filteredHistory = history.filter((h) => h.url !== report.url);
    filteredHistory.unshift(historyEntry);
    const cappedHistory = filteredHistory.slice(0, 30);

    await chrome.storage.local.set({
      phishguard_stats: stats,
      phishguard_history: cappedHistory
    });
  } catch (e) {
    console.warn("[PhishGuard] Failed to record stats/history:", e);
  }
}

/**
 * Get user allowlist from storage.
 */
async function getWhitelist() {
  const result = await chrome.storage.local.get("phishguard_whitelist");
  return Array.isArray(result.phishguard_whitelist) ? result.phishguard_whitelist : [];
}

/**
 * Check if a hostname is allowed.
 */
async function isHostWhitelisted(hostname) {
  if (!hostname) return false;
  const list = await getWhitelist();
  const lowerHost = hostname.toLowerCase();
  return list.some((item) => lowerHost === item.toLowerCase() || lowerHost.endsWith("." + item.toLowerCase()));
}

/**
 * Cache lookup in memory and chrome.storage.local with TTL.
 */
async function getCachedVerdict(urlKey) {
  const now = Date.now();

  // 1. Memory cache check
  if (memoryCache.has(urlKey)) {
    const entry = memoryCache.get(urlKey);
    if (now - entry.timestamp < CACHE_TTL_MS) {
      return entry.report;
    }
    memoryCache.delete(urlKey);
  }

  // 2. Persistent storage cache check
  const storageKey = `pg_cache_${encodeURIComponent(urlKey)}`;
  const stored = await chrome.storage.local.get(storageKey);
  if (stored && stored[storageKey]) {
    const entry = stored[storageKey];
    if (now - entry.timestamp < CACHE_TTL_MS) {
      memoryCache.set(urlKey, entry);
      return entry.report;
    }
    // Expired
    chrome.storage.local.remove(storageKey);
  }

  return null;
}

/**
 * Store verdict in cache with timestamp.
 */
async function setCachedVerdict(urlKey, report) {
  const entry = { report, timestamp: Date.now() };
  memoryCache.set(urlKey, entry);
  const storageKey = `pg_cache_${encodeURIComponent(urlKey)}`;
  await chrome.storage.local.set({ [storageKey]: entry });
}

/**
 * Check URL against backend, storage cache, or client fallback.
 */
async function checkUrl(urlString, skipHistory = false) {
  if (!urlString || urlString.startsWith("chrome://") || urlString.startsWith("chrome-extension://") || urlString.startsWith("about:")) {
    return { url: urlString, threat_score: 0, verdict: "safe", risk_level: "LOW", reasons: [] };
  }

  const level = await getProtectionLevel();

  try {
    const parsed = new URL(urlString);
    if (await isHostWhitelisted(parsed.hostname)) {
      const whiteReport = {
        url: urlString,
        threat_score: 0,
        verdict: "safe",
        risk_level: "LOW",
        reasons: [`Site '${parsed.hostname}' is on your trusted allowlist`],
        whitelisted: true
      };
      if (!skipHistory) recordScanStatsAndHistory(whiteReport);
      return whiteReport;
    }
  } catch (_) {}

  // Check TTL cache
  const cached = await getCachedVerdict(urlString);
  if (cached) {
    const adjusted = applyProtectionLevel(cached, level);
    if (!skipHistory) recordScanStatsAndHistory(adjusted);
    return adjusted;
  }

  let finalReport;
  try {
    const apiBase = await getApiBase();
    const res = await fetch(`${apiBase}/api/check-url`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: urlString })
    });

    if (!res.ok) {
      throw new Error(`API error: ${res.status}`);
    }

    const report = await res.json();
    await setCachedVerdict(urlString, report);
    finalReport = applyProtectionLevel(report, level);
  } catch (err) {
    console.warn("[PhishGuard] Backend API unreachable, invoking v1.1 offline fallback:", err.message);
    const fallback = clientSideFallbackCheck(urlString);
    await setCachedVerdict(urlString, fallback);
    finalReport = applyProtectionLevel(fallback, level);
  }

  if (!skipHistory) {
    recordScanStatsAndHistory(finalReport);
  }

  return finalReport;
}

/**
 * Update badge icon and text based on security verdict.
 */
function updateBadge(tabId, verdict, score) {
  if (verdict === "phishing") {
    chrome.action.setBadgeText({ tabId, text: "!" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#EF4444" });
  } else if (verdict === "suspicious") {
    chrome.action.setBadgeText({ tabId, text: "?" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#F59E0B" });
  } else {
    chrome.action.setBadgeText({ tabId, text: "✓" });
    chrome.action.setBadgeBackgroundColor({ tabId, color: "#10B981" });
  }
}

// Navigation monitor
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status === "loading" && tab.url) {
    const report = await checkUrl(tab.url);
    updateBadge(tabId, report.verdict, report.threat_score);

    // Save active tab verdict to storage for popup view
    chrome.storage.local.set({ [`tab_${tabId}`]: report });

    // Show warning banner or modal overlay if threat detected
    if (report.verdict !== "safe") {
      chrome.tabs.sendMessage(tabId, {
        type: "PHISHGUARD_SHOW_WARNING",
        report
      }).catch(() => {
        // Content script might not be injected yet
      });
    }
  }
});

// Clean up tab state on close
chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.local.remove([`tab_${tabId}`]);
});

// Context Menus Registration
chrome.runtime.onInstalled.addListener(() => {
  syncBackendConfig();
  // Setup default storage structures
  chrome.storage.local.get(["phishguard_stats", "phishguard_history", "phishguard_protection_level", "phishguard_whitelist", "phishguard_api_base"], (res) => {
    if (!res.phishguard_stats) {
      chrome.storage.local.set({ phishguard_stats: { totalScans: 0, threatsNeutralized: 0 } });
    }
    if (!res.phishguard_history) {
      chrome.storage.local.set({ phishguard_history: [] });
    }
    if (!res.phishguard_protection_level) {
      chrome.storage.local.set({ phishguard_protection_level: "balanced" });
    }
    if (!res.phishguard_whitelist) {
      chrome.storage.local.set({ phishguard_whitelist: [] });
    }
    if (!res.phishguard_api_base) {
      chrome.storage.local.set({ phishguard_api_base: DEFAULT_API_BASE });
    }
  });

  // Create context menu for scanning links
  chrome.contextMenus.create({
    id: "phishguard-scan-link",
    title: "Scan Link with PhishGuard",
    contexts: ["link"]
  });
});

// Context Menu Click Action
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === "phishguard-scan-link" && info.linkUrl) {
    const targetUrl = info.linkUrl;
    let targetDomain = targetUrl;
    try {
      targetDomain = new URL(targetUrl).hostname;
    } catch (_) {}

    const report = await checkUrl(targetUrl);
    const isPhish = report.verdict === "phishing";
    const isSusp = report.verdict === "suspicious";

    const title = isPhish
      ? `🚨 Threat Blocked (${report.threat_score}/100)`
      : isSusp
      ? `⚠️ Suspicious Link (${report.threat_score}/100)`
      : `🛡️ Verified Safe (${report.threat_score}/100)`;

    const reasonText = report.reasons && report.reasons.length > 0 ? report.reasons[0] : `Threat Score: ${report.threat_score}/100`;

    chrome.notifications.create({
      type: "basic",
      iconUrl: "icons/icon48.png",
      title: `${title} - ${targetDomain}`,
      message: `${reasonText}\nVerdict: ${report.verdict.toUpperCase()}`,
      priority: isPhish ? 2 : 1
    });
  }
});

// Message listener
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "CHECK_URL") {
    checkUrl(message.url).then(sendResponse);
    return true;
  }

  if (message.type === "CHECK_EMAIL") {
    getApiBase().then((apiBase) => {
      fetch(`${apiBase}/api/check-email`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(message.payload)
      })
        .then((res) => res.json())
        .then((report) => {
          // Record email scan stats
          chrome.storage.local.get("phishguard_stats", (data) => {
            const stats = data.phishguard_stats || { totalScans: 0, threatsNeutralized: 0 };
            stats.totalScans = (stats.totalScans || 0) + 1;
            if (report.verdict !== "safe") {
              stats.threatsNeutralized = (stats.threatsNeutralized || 0) + 1;
            }
            chrome.storage.local.set({ phishguard_stats: stats });
          });
          sendResponse(report);
        })
        .catch((err) => {
          sendResponse({
            threat_score: 50,
            verdict: "suspicious",
            risk_level: "MEDIUM",
            reasons: ["Backend offline: unable to run deep email analysis"]
          });
        });
    });
    return true;
  }

  if (message.type === "GET_ALL_STATE") {
    Promise.all([
      chrome.storage.local.get([
        "phishguard_stats",
        "phishguard_history",
        "phishguard_protection_level",
        "phishguard_whitelist",
        "phishguard_api_base"
      ])
    ]).then(([data]) => {
      sendResponse({
        stats: data.phishguard_stats || { totalScans: 0, threatsNeutralized: 0 },
        history: data.phishguard_history || [],
        protectionLevel: data.phishguard_protection_level || "balanced",
        whitelist: data.phishguard_whitelist || [],
        apiBase: data.phishguard_api_base || DEFAULT_API_BASE
      });
    });
    return true;
  }

  if (message.type === "SET_API_BASE") {
    const raw = (message.apiBase || "").trim().replace(/\/+$/, "");
    chrome.storage.local.set({ phishguard_api_base: raw }, () => {
      syncBackendConfig();
      sendResponse({ success: true, apiBase: raw || DEFAULT_API_BASE });
    });
    return true;
  }

  if (message.type === "SET_PROTECTION_LEVEL") {
    const level = message.level || "balanced";
    chrome.storage.local.set({ phishguard_protection_level: level }, () => {
      sendResponse({ success: true, level });
    });
    return true;
  }

  if (message.type === "CLEAR_HISTORY") {
    chrome.storage.local.set({ phishguard_history: [] }, () => {
      sendResponse({ success: true });
    });
    return true;
  }

  if (message.type === "ADD_WHITELIST") {
    getWhitelist().then((list) => {
      const lower = (message.domain || "").toLowerCase().trim();
      if (lower && !list.includes(lower)) {
        list.push(lower);
        chrome.storage.local.set({ phishguard_whitelist: list }, () => {
          sendResponse({ success: true, list });
        });
      } else {
        sendResponse({ success: true, list });
      }
    });
    return true;
  }

  if (message.type === "REMOVE_WHITELIST") {
    getWhitelist().then((list) => {
      const lower = (message.domain || "").toLowerCase().trim();
      const updated = list.filter((d) => d !== lower);
      chrome.storage.local.set({ phishguard_whitelist: updated }, () => {
        sendResponse({ success: true, list: updated });
      });
    });
    return true;
  }

  if (message.type === "IS_WHITELISTED") {
    isHostWhitelisted(message.domain).then((whitelisted) => {
      sendResponse({ whitelisted });
    });
    return true;
  }
});
