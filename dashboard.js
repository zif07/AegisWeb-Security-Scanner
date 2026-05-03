// --- STATE ---
let currentTabId = null;

// --- UTILS ---
function getQueryParam(name) {
  return new URLSearchParams(window.location.search).get(name);
}

// --- KNOWLEDGE BASE DICTIONARY ---
const KNOWLEDGE_BASE_ARTICLES = {
  'A08: Software & Data Integrity Failures': {
    title: 'Deceptive Links & Fake Sites (Phishing)',
    desc: 'Phishing is a trick where a website pretends to be an app you trust to steal your passwords or credit card info. We found links or domain names here that look suspiciously like popular websites, which is a major red flag that someone might be trying to trick you.'
  },
  'A07: Identification & Auth Failures': {
    title: 'Insecure Login Forms',
    desc: 'When you type your password or personal info, it should always be sent over a secure, scrambled connection. We noticed this website is sending your data unencrypted or asking your browser to save passwords unsafely, meaning anyone sharing your Wi-Fi (like at a coffee shop) could potentially snoop on your information.'
  },
  'A03: Injection': {
    title: 'Malicious Code Injection (XSS)',
    desc: 'This flaw allows hackers to sneak their own invisible code into the webpage you are viewing. If a hacker does this, they can secretly press buttons as if they were you, or steal your login session to take over your account without you noticing.'
  },
  'A02: Cryptographic Failures': {
    title: 'Missing Encryption (No HTTPS)',
    desc: 'Secure websites use "HTTPS" (the little padlock icon) to scramble data so hackers cannot read it. This site is missing proper encryption armor or is mixing secure and unsecure data together, making it dangerous to browse or enter sensitive information.'
  },
  'A04: Insecure Design': {
    title: 'Untrusted Outside Connections & Design Flaws',
    desc: 'Websites often load images or tools from other companies. This site is bringing in outside tools without double-checking them, or is missing standard design safeguards like CAPTCHAs, allowing attackers to use automated bots.'
  },
  'A05: Security Misconfiguration': {
    title: 'Missing Security Armor & Secrets',
    desc: 'Modern web browsers have built-in shields. This website has forgotten to turn them on, or is accidentally broadcasting sensitive details about how it was built underneath the hood. Hackers look for these specific clues.'
  },
  'A01: Broken Access Control': {
    title: 'Broken Access Control',
    desc: 'Websites must strictly enforce what users can see and do. We discovered signs that the app might be leaking hidden administrative privileges or administrative links securely, relying on obscurity instead of proper permissions.'
  },
  'A09: Security Logging Failures': {
    title: 'Security Logging Failures',
    desc: 'Whenever an error occurs, it should be securely logged on the backend. This website is instead exposing sensitive stack traces or database errors directly to your screen, indicating that their logging and monitoring mechanisms are deeply flawed.'
  }
};

// --- COUNTERMEASURES DICTIONARY ---
const COUNTERMEASURES_DICT = {
  'A08: Software & Data Integrity Failures': {
    title: 'Anti-Phishing Defenses',
    steps: [
      'Implement strict domain verification and SPF/DKIM/DMARC email authentication records.',
      'Train employees and users to recognize deceitful URLs.',
      'Deploy monitoring solutions to alert on newly registered look-alike domains.'
    ]
  },
  'A07: Identification & Auth Failures': {
    title: 'Strengthen Authentication',
    steps: [
      'Enforce strong password policies and prohibit predictable credentials.',
      'Implement Multi-Factor Authentication (MFA) for all user accounts.',
      'Never send credentials over unencrypted channels (ensure HTTPS is enforced everywhere).'
    ]
  },
  'A03: Injection': {
    title: 'Prevent Code Injection',
    steps: [
      'Sanitize and validate all user-supplied input on both client and server sides.',
      'Use context-aware output encoding to safely render data back to the browser.',
      'Adopt modern web frameworks that automatically escape XSS by design (like React or Vue).'
    ]
  },
  'A02: Cryptographic Failures': {
    title: 'Enforce Encryption',
    steps: [
      'Obtain and install a valid SSL/TLS certificate for your web server.',
      'Configure HTTP Strict Transport Security (HSTS) to force browsers to only use HTTPS.',
      'Disable outdated protocols (like TLS 1.0/1.1) and rely solely on modern equivalents (TLS 1.2+).'
    ]
  },
  'A04: Insecure Design': {
    title: 'Manage Dependencies & Design Safeguards',
    steps: [
      'Use Subresource Integrity (SRI) to verify that third-party scripts haven\'t been tampered with.',
      'Audit all external iframes and scripts; remove those that are unnecessary.',
      'Integrate missing anti-automation measures (like reCAPTCHA or Rate Limiting) on all authentication endpoints.'
    ]
  },
  'A05: Security Misconfiguration': {
    title: 'Implement Security Headers & Hardening',
    steps: [
      'Configure Content Security Policy (CSP) to restrict where scripts and resources can be loaded from.',
      'Add X-Frame-Options (e.g., DENY or SAMEORIGIN) to prevent clickjacking attacks.',
      'Keep server software, libraries, and frameworks up to date with the latest security patches.'
    ]
  },
  'A01: Broken Access Control': {
    title: 'Enforce Strict Access Controls',
    steps: [
      'Implement role-based access control (RBAC) securely on the backend, not the frontend.',
      'Never rely on modifying hidden HTML/DOM fields to govern user privileges.',
      'Ensure administrative pages require explicit backend authentication checks.'
    ]
  },
  'A09: Security Logging Failures': {
    title: 'Secure Event Logging',
    steps: [
      'Ensure all sensitive errors throw safe, generic error messages to the end user.',
      'Configure the backend framework to log stack traces or database issues securely to a file or monitoring service (like Sentry or Datadog).',
      'Establish alerts for repeated failed login attempts or systematic injection errors.'
    ]
  }
};

// --- RENDERERS ---
function renderReport(report, monitorResults = null) {
  if (!report) return;
  const findings = report.findings || [];

  // Update Target
  if (monitorResults && monitorResults.url) {
    document.getElementById('target-url-header').textContent = new URL(monitorResults.url).hostname;
  }

  // 1. Calc Score & Summaries
  let score = 100;
  const counts = { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const categoriesFound = new Set();
  const penalisedTitles = new Set();

  findings.forEach(f => {
    counts.total++;
    const s = f.severity?.toUpperCase() || 'INFO';
    categoriesFound.add(f.category || 'General Security');

    if (s === 'CRITICAL') { counts.critical++; }
    else if (s === 'HIGH') { counts.high++; }
    else if (s === 'MEDIUM') { counts.medium++; }
    else if (s === 'LOW') { counts.low++; }
    else { counts.info++; }

    if (!penalisedTitles.has(f.title)) {
      penalisedTitles.add(f.title);
      if (s === 'CRITICAL') { score -= 20; }
      else if (s === 'HIGH') { score -= 15; }
      else if (s === 'MEDIUM') { score -= 10; }
      else if (s === 'LOW') { score -= 5; }
    }
  });

  score = Math.max(0, score);

  // Update Meter Gauge
  const meterNeedle = document.getElementById('meter-needle');
  if (meterNeedle) {
    // Score 0 -> 180deg (left), Score 100 -> 360deg (right)
    const degrees = 180 + (score / 100) * 180;
    
    // Add small delay to ensure CSS transition triggers properly 
    // from the initial 180deg state set in CSS
    setTimeout(() => {
      meterNeedle.style.transform = `rotate(${degrees}deg)`;
    }, 50);
  }

  const meterScoreText = document.getElementById('meter-score-text');
  if (meterScoreText) {
    meterScoreText.textContent = score;
    if (score >= 80) meterScoreText.style.color = '#10b981';
    else if (score >= 60) meterScoreText.style.color = '#84cc16';
    else if (score >= 40) meterScoreText.style.color = '#eab308';
    else if (score >= 20) meterScoreText.style.color = '#f97316';
    else meterScoreText.style.color = '#ef4444';
  }

  // Update Summary DOM
  const scoreEl = document.getElementById('overview-score');
  scoreEl.textContent = score;
  scoreEl.className = 'stat-value ' + (score >= 80 ? 'positive' : score >= 50 ? 'warning' : 'danger');
  
  const scoreText = document.getElementById('score-text');
  if (score >= 80) { scoreText.textContent = 'Excellent'; scoreText.className = 'stat-trend positive'; }
  else if (score >= 50) { scoreText.textContent = 'Fair'; scoreText.className = 'stat-trend warning'; }
  else { scoreText.textContent = 'Critical Risk'; scoreText.className = 'stat-trend danger'; }

  document.getElementById('vuln-total').textContent = counts.total;
  document.getElementById('overview-critical').textContent = counts.critical + counts.high;
  document.getElementById('overview-tech-count').textContent = monitorResults ? (monitorResults.tech || []).length : '0';

  // 2. Categories
  const catList = document.getElementById('vuln-categories');
  catList.innerHTML = '';
  Array.from(categoriesFound).forEach(cat => {
    let icon = '🛡';
    if (cat.includes('Transport')) icon = '🔒';
    if (cat.includes('Header')) icon = '📝';
    if (cat.includes('XSS')) icon = '💉';
    if (cat.includes('Auth')) icon = '🔑';
    if (cat.includes('External')) icon = '🔗';
    if (cat.includes('Phishing')) icon = '🎣';
    if (cat.includes('Access')) icon = '🚪';
    if (cat.includes('Insecure Design')) icon = '🏗️';
    if (cat.includes('Logging')) icon = '📊';

    catList.innerHTML += `
      <li>
        <span>${icon} ${DOMPurify.sanitize(cat)}</span>
      </li>
    `;
  });
  if (categoriesFound.size === 0) catList.innerHTML = '<li><span style="color:#10b981">No categories flagged</span></li>';

  // 3. Security Risks (Findings List)
  const findingsList = document.getElementById('vuln-findings-list');
  findingsList.innerHTML = '';

  if (findings.length === 0) {
    findingsList.innerHTML = '<div style="color:#10b981; font-weight:600; padding:10px;">✨ No vulnerabilities found!</div>';
  } else {
    // Sort
    findings.sort((a, b) => {
      const order = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4 };
      return order[a.severity?.toUpperCase()] - order[b.severity?.toUpperCase()];
    });

    findings.forEach(f => {
      const s = f.severity?.toUpperCase() || 'INFO';
      const sClass = s === 'CRITICAL' ? 'critical' : s === 'MEDIUM' || s === 'HIGH' ? 'medium' : 'low';

      findingsList.innerHTML += `
        <div class="finding-card ${s.toLowerCase()}">
          <div class="finding-header">
            <span class="finding-title">${DOMPurify.sanitize(f.title)}</span>
            <span class="badge ${sClass === 'critical' ? 'fail' : sClass === 'medium' ? 'warning' : 'info'}">${DOMPurify.sanitize(s)}</span>
          </div>
          <div class="finding-desc">${DOMPurify.sanitize(f.description)}</div>
          ${f.location ? `<div class="finding-loc">Location: <code>${DOMPurify.sanitize(f.location)}</code></div>` : ''}
          <div class="finding-loc" style="margin-top:4px; opacity:0.8; font-size:0.8rem">Category: ${DOMPurify.sanitize(f.category)}</div>
        </div>
      `;
    });
  }

  // 4. Knowledge Base
  const kbContainer = document.getElementById('knowledge-base-container');
  kbContainer.innerHTML = '';

  if (categoriesFound.size === 0) {
    kbContainer.innerHTML = '<div style="color:#94a3b8">No issues found, so nothing to review!</div>';
  } else {
    Array.from(categoriesFound).forEach(cat => {
      const article = KNOWLEDGE_BASE_ARTICLES[cat] || {
        title: cat,
        desc: 'Review standard web security guidelines for this vulnerability category to understand the potential impact on your infrastructure.'
      };
      
      kbContainer.innerHTML += `
        <div class="kb-card">
          <h3 class="kb-title">🛡️ ${article.title}</h3>
          <p class="kb-desc">${article.desc}</p>
        </div>
      `;
    });
  }

  // 5. Countermeasures
  const countermeasuresContainer = document.getElementById('countermeasures-container');
  if (countermeasuresContainer) {
    countermeasuresContainer.innerHTML = '';

    if (categoriesFound.size === 0) {
      countermeasuresContainer.innerHTML = '<div style="color:#94a3b8">No issues found, so no specific countermeasures are required!</div>';
    } else {
      Array.from(categoriesFound).forEach(cat => {
        const countermeasure = COUNTERMEASURES_DICT[cat] || {
          title: 'General Mitigation Steps',
          steps: [
            'Investigate the reported vulnerability to determine its root cause.',
            'Apply relevant security patches or configuration changes immediately.',
            'Review industry best practices to prevent similar issues in the future.'
          ]
        };
        
        let stepsHtml = countermeasure.steps.map(step => `<li>${step}</li>`).join('');
        
        countermeasuresContainer.innerHTML += `
          <div class="kb-card">
            <h3 class="kb-title">🛠️ ${countermeasure.title}</h3>
            <ul class="kb-desc" style="margin-top: 10px; padding-left: 20px;">
              ${stepsHtml}
            </ul>
          </div>
        `;
      });
    }
  }
}

// --- MAIN ---
document.addEventListener('DOMContentLoaded', () => {
  const urlParam = getQueryParam('tabId');
  if (urlParam) {
     currentTabId = parseInt(urlParam, 10);
     
     // 1. Fetch Passive Monitor data immediately for the header/tech stack
     chrome.runtime.sendMessage({ type: 'getResultsForTab', tabId: currentTabId }, monitorResp => {
       const monitorResults = monitorResp && monitorResp.result ? monitorResp.result : null;
       
       // 2. We trigger Active Scan to ensure we have the absolute latest report
       chrome.runtime.sendMessage({ type: 'startActiveScan', tabId: currentTabId }, (resp) => {
          if (resp && resp.report) {
            renderReport(resp.report, monitorResults);
          } else {
            document.getElementById('error').classList.remove('hidden');
          }
       });
    });

  } else {
    document.getElementById('target-url-header').textContent = "No Target Selected";
    document.getElementById('error').textContent = "Please open the dashboard from the extension popup on a valid page.";
    document.getElementById('error').classList.remove('hidden');
  }
});
