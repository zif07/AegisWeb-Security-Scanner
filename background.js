const resultsByTab = new Map();

function normalizeHeaders(headers) {
  const map = {};
  for (const h of headers || []) {
    map[String(h.name).toLowerCase()] = String(h.value);
  }
  return map;
}

function analyzeHeaders(url, headerMap) {
  return {
    https: String(url).startsWith('https://'),
    hsts: {
      present: !!headerMap['strict-transport-security'],
      maxAge: (headerMap['strict-transport-security'] || '').match(/max-age=(\d+)/i)?.[1] || 0
    },
    csp: !!headerMap['content-security-policy'],
    xContentTypeOptions: (headerMap['x-content-type-options'] || '').toLowerCase() === 'nosniff',
    xFrameOptions: !!headerMap['x-frame-options'],
    referrerPolicy: !!headerMap['referrer-policy'],
    permissionsPolicy: !!(headerMap['permissions-policy'] || headerMap['feature-policy']),
    server: headerMap['server'] || '',
    poweredBy: headerMap['x-powered-by'] || ''
  };
}

function computePassiveRisks(analysis) {
  const risks = [];
  if (!analysis.https) risks.push('No HTTPS');
  if (!analysis.hsts.present) risks.push('Missing HSTS');
  if (!analysis.csp) risks.push('Missing CSP');
  if (!analysis.xContentTypeOptions) risks.push('Missing X-Content-Type-Options');
  if (!analysis.xFrameOptions) risks.push('Missing X-Frame-Options');
  return risks;
}

// --- ACTIVE SCAN ORCHESTRATOR ---
async function performActiveScan(tabId, url) {
  const findings = [];

  // 1. Cookie Analysis
  try {
    const cookies = await chrome.cookies.getAll({ url });
    let accessibleCount = 0;
    cookies.forEach(c => {
      if (!c.secure) {
        findings.push({
          category: 'A02:2025 Security Misconfiguration',
          severity: 'MEDIUM',
          title: 'Insecure Cookie',
          description: `Cookie "${c.name}" is missing the Secure flag.`,
          location: c.name
        });
      }
      if (!c.httpOnly) {
        accessibleCount++;
      }
    });
    if (accessibleCount > 0) {
      findings.push({
        category: 'A05:2025 Injection',
        severity: 'MEDIUM',
        title: 'Cookies accessible via JavaScript',
        description: `${accessibleCount} cookie(s) can be accessed by JavaScript, vulnerable to XSS theft`,
        location: `Accessible cookies: ${accessibleCount}`
      });
    }
    if (cookies.length > 0) {
      findings.push({
        category: 'A02:2025 Security Misconfiguration',
        severity: 'INFO',
        title: 'Cookie security flags should be verified',
        description: 'Ensure all cookies have Secure flag set for HTTPS sites',
        location: 'Use browser DevTools to verify Secure and SameSite flags'
      });
    }
  } catch (e) {
    console.error('Cookie scan failed', e);
  }

  // 2. Content Script Analysis (Phishing, DOM)
  try {
    const response = await chrome.tabs.sendMessage(tabId, { type: 'runPageScan' });
    if (response && response.findings) {
      findings.push(...response.findings);
    }
  } catch (e) {
    console.error('Content script scan failed', e);
  }

  // 3. Header Analysis (from stored passive data)
  const passiveData = resultsByTab.get(tabId);
  if (passiveData && passiveData.analysis) {
    const a = passiveData.analysis;
    if (!a.csp) findings.push({ category: 'A02:2025 Security Misconfiguration', severity: 'MEDIUM', title: 'Missing CSP', description: 'No Content Security Policy detected.', location: 'Headers' });
    if (!a.hsts.present) findings.push({ category: 'A04:2025 Cryptographic Failures', severity: 'LOW', title: 'Missing HSTS', description: 'Strict Transport Security not enforced.', location: 'Headers' });
    if (!a.xFrameOptions) findings.push({ category: 'A02:2025 Security Misconfiguration', severity: 'LOW', title: 'Missing X-Frame-Options', description: 'Potential Clickjacking risk.', location: 'Headers' });
    
    // Header Information Disclosure (OWASP A02:2025)
    if (a.server) findings.push({ category: 'A02:2025 Security Misconfiguration', severity: 'INFO', title: 'Server Header Exposed', description: `Server header exposes technology: ${a.server}`, location: 'Headers: Server' });
    if (a.poweredBy) findings.push({ category: 'A02:2025 Security Misconfiguration', severity: 'INFO', title: 'X-Powered-By Header Exposed', description: `X-Powered-By header exposes framework: ${a.poweredBy}`, location: 'Headers: X-Powered-By' });

    if (a.https) {
      try {
        const proto = new URL(url).protocol;
        findings.push({ category: 'A04:2025 Cryptographic Failures', severity: 'INFO', title: 'HTTPS properly implemented', description: 'Site correctly uses HTTPS encryption', location: `Protocol: ${proto}` });
      } catch (_) {
        findings.push({ category: 'A04:2025 Cryptographic Failures', severity: 'INFO', title: 'HTTPS properly implemented', description: 'Site correctly uses HTTPS encryption', location: 'Protocol: https:' });
      }
    }
  }

  return { findings };
}

// --- LISTENERS ---
chrome.webRequest.onHeadersReceived.addListener(
  details => {
    if (details.type !== 'main_frame' || details.tabId < 0) return;
    console.log(`[AegisWeb] Passive Interception: Intercepted headers for URL: ${details.url}`);
    const headerMap = normalizeHeaders(details.responseHeaders);
    const analysis = analyzeHeaders(details.url, headerMap);
    const data = {
      url: details.url,
      analysis,
      headerMap,
      risks: computePassiveRisks(analysis)
    };

    // Merge
    const prev = resultsByTab.get(details.tabId) || {};
    resultsByTab.set(details.tabId, { ...prev, ...data });
    console.log(`[AegisWeb] Stored Passive Data: Saved headers and security analysis in memory for tab ${details.tabId}.`);
  },
  { urls: ['<all_urls>'] },
  ['responseHeaders']
);

// --- TAMPER AUDIT LOG ---
const tamperLog = [];

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // Tech Detection (Passive)
  if (msg.type === 'techDetection') {
    const tabId = sender.tab?.id;
    if (tabId) {
      const prev = resultsByTab.get(tabId) || {};
      prev.tech = msg.payload.tech;
      resultsByTab.set(tabId, prev);
      console.log(`[AegisWeb] Tech Detection: Identified technologies on tab ${tabId}:`, msg.payload.tech);
    }
    return;
  }

  // Anti-Tamper Event (from content/anti-tamper.js)
  if (msg.type === 'aegisTamperDetected') {
    const entry = {
      tabId:  sender.tab?.id,
      url:    sender.tab?.url,
      ts:     Date.now(),
      detail: msg.detail
    };
    tamperLog.push(entry);
    console.warn('[AegisWeb Background] Tamper event recorded:', entry);
    // Optionally surface alert to the user via badge
    if (sender.tab?.id) {
      chrome.action.setBadgeText({ text: '⚠', tabId: sender.tab.id }).catch(() => {});
      chrome.action.setBadgeBackgroundColor({ color: '#ef4444', tabId: sender.tab.id }).catch(() => {});
    }
    sendResponse({ ok: true });
    return true;
  }

  // Dashboard Data Request
  if (msg.type === 'getResultsForTab') {
    sendResponse({ result: resultsByTab.get(msg.tabId) });
    return true;
  }

  // Active Scan Trigger
  if (msg.type === 'startActiveScan') {
    const tabId = msg.tabId || (sender.tab && sender.tab.id);
    const data = resultsByTab.get(tabId) || { url: sender.tab && sender.tab.url };
    if (tabId && data && data.url) {
      console.log(`[AegisWeb] Active Scan Triggered: Starting security audit on tab ${tabId} for: ${data.url}`);
      performActiveScan(tabId, data.url).then(report => {
        console.log(`[AegisWeb] Active Scan Finished: Found ${report.findings.length} security vulnerability findings.`);
        sendResponse({ report });
      });
      return true; // async response
    } else {
      console.warn('[AegisWeb] Active Scan Failed: Tab ID or URL not resolved.');
      sendResponse({ report: null });
      return false;
    }
  }
});

chrome.tabs.onRemoved.addListener(tabId => resultsByTab.delete(tabId));

// --- EXPORTS FOR TESTING ---
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    normalizeHeaders,
    analyzeHeaders,
    computePassiveRisks,
    performActiveScan
  };
}
