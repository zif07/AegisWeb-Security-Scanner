// --- ACTIVE SCANNER ---
// Note: This file relies on createFinding and levenshtein from utils.js, and detectTech from tech-detector.js
// Since it's loaded as a content script, those will be available globally in the browser.

function runActiveScan() {
  const findings = [];
  const origin = window.location.origin;

  // 1. Phishing: Mismatched Links & Local Probing (OWASP A01:2025) & Info Disclosure (OWASP A02:2025)
  document.querySelectorAll('a').forEach(a => {
    // Snyk Fix: Sanitize text and href immediately upon extraction to prevent XSS payloads
    // from propagating into the extension's dashboard UI.
    const text = escapeHTML(a.textContent.trim());
    const href = a.href || '';
    const safeHref = escapeHTML(href);
    const lowerHref = href.toLowerCase();

    // Heuristic: Text looks like a URL but href is different
    if (text.match(/^[a-z0-9.-]+\.[a-z]{2,}(\/.*)?$/i)) {
      if (lowerHref.startsWith('http') && !lowerHref.includes(text) && !text.includes('...')) {
        findings.push(createFinding('Phishing', 'HIGH', 'Deceptive Link Detected', `The wording says "${text}" but actually sends you to a completely different place!`, `<a href="${safeHref}">${text}</a>`));
      }
    }

    // SSRF / Local Probing
    if (lowerHref.includes('127.0.0.1') || lowerHref.includes('localhost') || lowerHref.includes('169.254.169.254')) {
      findings.push(createFinding('Iframe & External', 'HIGH', 'Sneaky Network Probing', 'This link isn\'t pointing to a normal website—it\'s trying to peek at secret files behind the scenes.', safeHref));
    }

    // Info Disclosure (Files)
    if (lowerHref.endsWith('.env') || lowerHref.endsWith('.git') || lowerHref.endsWith('.bak') || lowerHref.endsWith('.sql')) {
      findings.push(createFinding('General Security', 'CRITICAL', 'Leaked Technical File', 'This link points to a private backup or settings file that hackers shouldn\'t be allowed to see.', safeHref));
    }

    // Exposed Emails
    if (lowerHref.startsWith('mailto:')) {
      findings.push(createFinding('General Security', 'INFO', 'Visible Email Address', 'An email address is printed directly in the code, meaning spam bots can easily copy it.', safeHref.replace('mailto:', '')));
    }

    // XSS: javascript: links
    if (lowerHref.startsWith('javascript:')) {
      findings.push(createFinding('XSS & Injection', 'MEDIUM', 'Hidden Script inside a Link', 'This link is actually a hidden piece of code. Clicking it runs the code, which hackers sometimes use to steal your account.', `<a href="${safeHref}">`));
      
      // FYP Remediation: Active Protection
      // We block the actual click event so the malicious code cannot execute in the browser.
      a.addEventListener('click', function(event) {
        event.preventDefault(); // Stop the javascript: from running
        console.log("AegisWeb blocked a non-standard URI scheme:", lowerHref);
        alert("🛡️ AegisWeb Security Scanner blocked a malicious script from executing!");
      });
    }

    // Reverse Tabnabbing
    if (a.getAttribute('target') === '_blank') {
      const rel = (a.getAttribute('rel') || '').toLowerCase();
      if (!rel.includes('noopener') && !rel.includes('noreferrer')) {
        findings.push(createFinding('Iframe & External', 'LOW', 'Dangerous Outside Link', 'This link opens a new tab but doesn\'t lock it down. The new tab could secretly rewrite the original page to trick you.', safeHref));
      }
    }
  });

  // 2. Phishing: IP Address Usage
  if (window.location.hostname.match(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/)) {
    findings.push(createFinding('Phishing', 'MEDIUM', 'Suspicious Website Address', 'You are visiting this site using numbers (an IP address) instead of a normal name like "google.com". Scammers often do this to hide.', window.location.hostname));
  }

  // 3. Forms: Insecure Actions (OWASP A07:2025)
  document.querySelectorAll('form').forEach(f => {
    const actionStr = (typeof f.action === 'string' ? f.action : f.getAttribute('action')) || '';
    if (actionStr.startsWith('http:')) {
      findings.push(createFinding('Authentication', 'CRITICAL', 'Unsafe Data Submission', 'When you click submit, your data is sent without encryption. Anyone watching the network can read it.', `Form action: ${actionStr}`));
    }

    // Password field checks
    const passwordFields = f.querySelectorAll('input[type="password"]');
    if (passwordFields.length > 0) {
      if (window.location.protocol === 'http:') {
        findings.push(createFinding('Authentication', 'CRITICAL', 'Unsafe Login Page', 'This password box does not have a secure connection. Your password could be stolen as you type it.', 'Password Field'));
      }
      passwordFields.forEach(pw => {
        const autocomplete = (pw.getAttribute('autocomplete') || '').toLowerCase();
        if (autocomplete !== 'off' && autocomplete !== 'new-password' && autocomplete !== 'current-password') {
          findings.push(createFinding('Authentication', 'LOW', 'Risky Browser Saving', 'This site encourages the browser to memorize your password in an unsafe, poorly-controlled way.', 'Password Input'));
        }
      });
    }
  });

  // 4. Mixed Content (Static Check)
  if (window.location.protocol === 'https:') {
    const insecureResources = [];
    document.querySelectorAll('img, script, iframe, link').forEach(el => {
      const src = el.src || el.href;
      if (src && src.startsWith('http:')) {
        insecureResources.push(src);
      }
    });
    if (insecureResources.length > 0) {
      findings.push(createFinding('Transport Security', 'MEDIUM', 'Mixed Secure & Unsecure Data', `Found ${insecureResources.length} pieces of data that are not encrypted, even though the main page is.`, insecureResources[0]));
    }
  }

  // 5. Typosquatting (Simple Levenshtein check)
  const safeList = ['google.com', 'facebook.com', 'twitter.com', 'linkedin.com', 'paypal.com', 'github.com', 'microsoft.com', 'apple.com', 'amazon.com', 'netflix.com'];
  const currentHost = window.location.hostname.replace('www.', '');
  safeList.forEach(safe => {
    const dist = levenshtein(currentHost, safe);
    if (dist > 0 && dist <= 2 && currentHost.length > 4) {
      findings.push(createFinding('Phishing', 'CRITICAL', 'Potential Lookalike Scam', `This domain (${currentHost}) looks dangerously similar to ${safe}. Please be very careful!`, currentHost));
    }
  });

  // 6. DOM Analysis for Dangerous Sinks (OWASP A05:2025 Injection)
  document.querySelectorAll('script:not([src])').forEach(script => {
    const content = script.textContent || '';
    if (content.match(/eval\s*\(/)) {
      findings.push(createFinding('XSS & Injection', 'HIGH', 'Dangerous Hidden Code', 'The website uses a coding command that makes it extremely easy for hackers to break in and run their own viruses.', 'Inline Script'));
    }
    if (content.match(/document\.write\s*\(/)) {
      findings.push(createFinding('XSS & Injection', 'LOW', 'Outdated risky code formatting', 'An outdated way of drawing the webpage is being used, making it slightly easier for scammers to interfere.', 'Inline Script'));
    }
  });

  // 6.5 Reflected XSS (Heuristic)
  try {
    const params = new URLSearchParams(window.location.search);
    const pageHtml = document.documentElement.innerHTML || '';
    params.forEach((val, key) => {
      // Ignore very short or purely numeric values to reduce false positives
      if (val && val.length > 3 && isNaN(val)) {
        // Also check if decoded val is found in raw HTML
        if (pageHtml.includes(val) || pageHtml.includes(encodeURIComponent(val))) {
          let severity = 'MEDIUM';
          let desc = `The URL parameter "${key}" is reflected directly onto the webpage. If the server doesn't properly sanitize this data, it's vulnerable to Reflected XSS.`;
          
          if (val.match(/[<>"']/)) {
            severity = 'HIGH';
            desc = `The URL parameter "${key}" contains dangerous characters and is reflected onto the webpage. This strongly indicates a Reflected XSS vulnerability!`;
          }
          
          findings.push(createFinding('XSS & Injection', severity, 'Potential Reflected XSS in URL parameter', desc, `URL Parameter: ?${key}=...`));
        }
      }
    });
  } catch(e) {}

  // 7. Missing SRI (OWASP A03:2025 Software Supply Chain Failures)
  document.querySelectorAll('script[src], link[rel="stylesheet"][href]').forEach(el => {
    try {
      const url = el.src || el.href;
      if (!url) return;
      const u = new URL(url, window.location.href);
      if (u.origin !== window.location.origin) {
        if (!el.getAttribute('integrity')) {
          findings.push(createFinding('General Security', 'LOW', 'Unverified Outside Code', 'This page loads tools from another company, but lacks the settings to check if the tool was secretly replaced by a virus.', url));
        }
      }
    } catch (e) {}
  });

  // A01:2025 Broken Access Control (Heuristic)
  document.querySelectorAll('input[type="hidden"]').forEach(inp => {
    const name = (inp.name || '').toLowerCase();
    if (name.includes('role') || name.includes('isadmin') || name.includes('permission')) {
      findings.push(createFinding('Access Control', 'HIGH', 'Exposed Privilege Control', 'A hidden field controlling user roles was found. If modified, a user might trick the server into giving them admin access.', `Hidden Input: ${inp.name}`));
    }
  });
  document.querySelectorAll('a').forEach(a => {
    const href = (a.href || '').toLowerCase();
    const txt = (a.textContent || '').toLowerCase();
    if ((href.includes('/admin') || href.includes('/wp-admin') || href.includes('/cpanel') || href.includes('/config')) && !href.includes('github.com')) {
      findings.push(createFinding('Access Control', 'LOW', 'Exposed Administrative Link', 'A link to a sensitive administrative page was found. Ensure this page strictly verifies user permissions.', href));
    }
  });

  // A06:2025 Insecure Design (Heuristic - Missing CAPTCHA)
  const allForms = document.querySelectorAll('form');
  if (allForms.length > 0) {
    let hasCaptcha = false;
    const bodyHtml = document.body.innerHTML.toLowerCase();
    if (bodyHtml.includes('recaptcha') || bodyHtml.includes('hcaptcha') || bodyHtml.includes('turnstile')) {
      hasCaptcha = true;
    }
    
    if (!hasCaptcha) {
       let hasPasswordField = false;
       allForms.forEach(f => { if (f.querySelector('input[type="password"]')) hasPasswordField = true; });
       if (hasPasswordField) {
         findings.push(createFinding('Insecure Design', 'MEDIUM', 'Missing Anti-Automation (CAPTCHA)', 'A login or registration form was found without a CAPTCHA. This insecure design allows hackers to use bots to brute-force passwords.', 'Form Element'));
       }
    }
  }

  // A09:2025 Security Logging & Alerting Failures (Heuristic)
  const bodyText = document.body.innerText || '';
  if (bodyText.includes('SQL syntax error') || bodyText.includes('Stack trace:') || bodyText.match(/Warning: (mysql_|pg_|pdo_)/i)) {
    findings.push(createFinding('Logging & Monitoring', 'HIGH', 'Exposed Error Logs', 'The website is printing detailed database errors directly to the screen. These should be securely logged internally, not shown to the public!', 'Page Content'));
  }
  const hasMon = Array.from(document.scripts).some(s => {
    const src = (s.src || '').toLowerCase();
    return src.includes('sentry') || src.includes('new relic') || src.includes('datadog');
  });
  if (!hasMon && !bodyText.includes('SQL syntax error')) {
     findings.push(createFinding('Logging & Monitoring', 'INFO', 'No Frontend Monitoring Detected', 'No active error reporting scripts were detected. Ensure your backend logging is robust enough to catch attacks without them.', 'Website Tech'));
  }

  // 8. Vulnerable Components (OWASP A03:2025 Software Supply Chain Failures)
  const tech = detectTech();
  tech.forEach(t => {
    if (t.toLowerCase().startsWith('jquery ')) {
      const v = t.split(' ')[1];
      if (v && v.startsWith('1.') || v.startsWith('2.')) {
        findings.push(createFinding('Supply Chain', 'HIGH', 'Old, Vulnerable Technology', `The website was built using an old version of jQuery (${v}) that hackers already know exactly how to break into.`, t));
      }
    }
  });

  // Deduplicate findings just in case
  const uniqueFindings = [];
  const seenStr = new Set();
  findings.forEach(f => {
    const id = f.title + f.location;
    if (!seenStr.has(id)) {
      seenStr.add(id);
      uniqueFindings.push(f);
    }
  });

  return uniqueFindings;
}

// --- EXPORTS FOR TESTING ---
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    runActiveScan
  };
}
