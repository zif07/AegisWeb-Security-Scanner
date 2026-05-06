// --- KNOWLEDGE BASE DICTIONARY (OWASP Top 10:2025) ---
const KNOWLEDGE_BASE_ARTICLES = {
  'A01:2025 Broken Access Control': {
    title: 'Broken Access Control',
    desc: 'Access control enforces rules so that users cannot act outside of their intended permissions. When these controls fail, attackers can view other users\' data, modify records, or perform privileged actions like deleting accounts. In 2025 this remains the #1 risk, and now also includes Server-Side Request Forgery (SSRF) — where a server is tricked into making requests to unintended locations on behalf of an attacker.'
  },
  'A02:2025 Security Misconfiguration': {
    title: 'Security Misconfiguration',
    desc: 'Security misconfiguration is the most commonly seen issue in modern applications and cloud environments. It happens when security settings are left at their defaults, unnecessary features are enabled, error messages reveal too much information, or security headers are missing. As applications grow more complex with cloud services and microservices, the attack surface for misconfiguration has expanded significantly — making this the #2 risk in 2025.'
  },
  'A03:2025 Software Supply Chain Failures': {
    title: 'Software Supply Chain Failures',
    desc: 'This is an expanded category in 2025, going beyond just "outdated components." It now covers the entire software supply chain — including third-party libraries, build systems, CI/CD pipelines, and distribution infrastructure. If an attacker compromises any link in this chain (for example, injecting malware into a popular open-source library), every application using that dependency becomes vulnerable automatically. We check for outdated libraries and missing Subresource Integrity (SRI) to catch these risks.'
  },
  'A04:2025 Cryptographic Failures': {
    title: 'Cryptographic Failures',
    desc: 'Cryptographic failures occur when sensitive data is not properly protected — either in transit or at rest. This includes using weak or deprecated encryption algorithms, transmitting data over unencrypted HTTP connections, failing to enforce HTTPS via HSTS, or exposing cryptographic keys. Without strong encryption, passwords, credit card numbers, and personal information can be intercepted by anyone on the same network.'
  },
  'A05:2025 Injection': {
    title: 'Injection (Including XSS)',
    desc: 'Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query, tricking it into executing unintended actions. This includes SQL injection, OS command injection, and Cross-Site Scripting (XSS) — where malicious scripts are injected into web pages viewed by other users. Attackers can use injection to steal session cookies, redirect users to malicious sites, or gain full control of the application backend.'
  },
  'A06:2025 Insecure Design': {
    title: 'Insecure Design',
    desc: 'Insecure design refers to fundamental flaws in the application\'s architecture that cannot be fixed by better code alone — the security controls simply were never designed in the first place. Examples include missing rate limiting on login forms (allowing brute-force attacks), lack of CAPTCHA on authentication endpoints, and business logic flaws. Addressing this requires threat modeling and building security into the design from the start, not just patching code later.'
  },
  'A07:2025 Authentication Failures': {
    title: 'Authentication Failures',
    desc: 'Authentication failures occur when applications do not properly verify a user\'s identity or manage their sessions. Weaknesses include allowing automated credential stuffing or brute-force attacks, accepting weak or default passwords, transmitting credentials over unencrypted connections, and failing to implement Multi-Factor Authentication (MFA). When authentication is broken, attackers can assume the identity of any user — including administrators.'
  },
  'A08:2025 Software or Data Integrity Failures': {
    title: 'Software or Data Integrity Failures',
    desc: 'This category covers failures to verify the integrity of software updates, critical data, and CI/CD pipelines. Applications that rely on plugins, libraries, or content from untrusted sources without proper verification are at risk. We also flag deceptive links and lookalike domains (phishing) under this category, as these are attempts to compromise the integrity of the trust relationship between a user and a legitimate service — tricking users into submitting data to fraudulent sites.'
  },
  'A09:2025 Security Logging and Alerting Failures': {
    title: 'Security Logging & Alerting Failures',
    desc: 'Without sufficient logging, monitoring, and alerting, security breaches go undetected and unresponded to. This includes failing to log critical events (logins, failed logins, high-value transactions), not monitoring logs for suspicious patterns, and exposing detailed error messages (like database stack traces) directly to users instead of logging them securely. The 2025 update emphasizes alerting — it\'s not enough to just log; teams must be actively notified of suspicious activity.'
  },
  'A10:2025 Mishandling of Exceptional Conditions': {
    title: 'Mishandling of Exceptional Conditions',
    desc: 'New in OWASP 2025, this category addresses how applications respond to unexpected, abnormal, or edge-case situations. When errors are poorly handled, applications may crash, leak sensitive information, enter undefined states, or — most dangerously — "fail open," defaulting to an unprotected state that grants access instead of denying it. Attackers actively probe for these conditions to bypass authentication, trigger authorization errors, or cause denial-of-service.'
  }
};

// --- COUNTERMEASURES DICTIONARY (OWASP Top 10:2025) ---
const COUNTERMEASURES_DICT = {
  'A01:2025 Broken Access Control': {
    title: 'Enforce Strict Access Controls',
    steps: [
      'Implement role-based access control (RBAC) on the server side — never trust client-side controls for permissions.',
      'Deny access by default and only grant the minimum privileges needed (principle of least privilege).',
      'Never expose hidden form fields or URL parameters that control user roles or admin status.',
      'Validate all server-side requests to prevent SSRF — restrict outbound connections to approved hosts only.'
    ]
  },
  'A02:2025 Security Misconfiguration': {
    title: 'Harden Security Configuration',
    steps: [
      'Configure Content Security Policy (CSP), X-Frame-Options, and X-Content-Type-Options headers on all responses.',
      'Remove default credentials, disable directory listing, and turn off unnecessary features or services.',
      'Suppress detailed error messages and server/technology banners (Server, X-Powered-By headers) from production.',
      'Establish a repeatable hardening process and audit configurations across development, staging, and production environments.'
    ]
  },
  'A03:2025 Software Supply Chain Failures': {
    title: 'Secure the Software Supply Chain',
    steps: [
      'Use Subresource Integrity (SRI) hashes on all third-party scripts and stylesheets to detect tampering.',
      'Regularly audit dependencies with tools like npm audit, Snyk, or OWASP Dependency-Check.',
      'Pin dependency versions and verify package integrity using lock files and signature checks.',
      'Monitor for supply chain attacks — subscribe to security advisories for your critical dependencies.'
    ]
  },
  'A04:2025 Cryptographic Failures': {
    title: 'Enforce Strong Encryption',
    steps: [
      'Enforce HTTPS everywhere and configure HTTP Strict Transport Security (HSTS) with a long max-age.',
      'Disable deprecated protocols (TLS 1.0/1.1, SSL) and use only TLS 1.2+ with strong cipher suites.',
      'Never transmit sensitive data (passwords, tokens, PII) over unencrypted HTTP connections.',
      'Use strong, modern hashing algorithms (bcrypt, Argon2) for passwords — never MD5 or plain SHA.'
    ]
  },
  'A05:2025 Injection': {
    title: 'Prevent Injection Attacks',
    steps: [
      'Sanitize and validate all user-supplied input on both client and server sides using allow-lists.',
      'Use parameterized queries or prepared statements to prevent SQL injection — never concatenate user input into queries.',
      'Apply context-aware output encoding (HTML, JavaScript, URL) to prevent Cross-Site Scripting (XSS).',
      'Avoid dangerous functions like eval(), document.write(), and innerHTML with untrusted data.'
    ]
  },
  'A06:2025 Insecure Design': {
    title: 'Implement Secure Design Patterns',
    steps: [
      'Conduct threat modeling during the design phase to identify abuse scenarios before writing code.',
      'Implement rate limiting and anti-automation (CAPTCHA, reCAPTCHA) on login and registration forms.',
      'Audit all external iframes, scripts, and third-party integrations — remove unnecessary ones.',
      'Use secure design patterns and reference architectures; ensure business logic enforces security constraints.'
    ]
  },
  'A07:2025 Authentication Failures': {
    title: 'Strengthen Authentication & Sessions',
    steps: [
      'Implement Multi-Factor Authentication (MFA) to prevent credential stuffing and brute-force attacks.',
      'Enforce strong password policies — minimum length, complexity, and check against known breached password lists.',
      'Never transmit credentials over unencrypted connections; set Secure and HttpOnly flags on session cookies.',
      'Implement account lockout or progressive delays after repeated failed login attempts.'
    ]
  },
  'A08:2025 Software or Data Integrity Failures': {
    title: 'Protect Software & Data Integrity',
    steps: [
      'Verify the integrity of all software updates, plugins, and CI/CD pipeline artifacts using digital signatures.',
      'Implement strict domain verification and SPF/DKIM/DMARC to prevent phishing and domain spoofing.',
      'Train users to recognize deceptive URLs and lookalike domains that impersonate trusted services.',
      'Deploy monitoring to alert on newly registered look-alike domains targeting your brand.'
    ]
  },
  'A09:2025 Security Logging and Alerting Failures': {
    title: 'Implement Robust Logging & Alerting',
    steps: [
      'Log all critical security events — logins, failed logins, access control failures, and high-value transactions.',
      'Never display detailed error messages (stack traces, SQL errors) to end users; show generic messages instead.',
      'Centralize logs in a tamper-resistant system and integrate with a SIEM or monitoring service (Sentry, Datadog).',
      'Configure real-time alerts for suspicious patterns — repeated failed logins, injection attempts, or privilege escalation.'
    ]
  },
  'A10:2025 Mishandling of Exceptional Conditions': {
    title: 'Handle Exceptions Gracefully',
    steps: [
      'Implement comprehensive try-catch blocks and error boundaries — ensure no unhandled exceptions reach production.',
      'Design systems to "fail closed" — deny access by default when errors occur, never "fail open."',
      'Return generic, safe error responses to users while logging full details securely on the backend.',
      'Test edge cases, boundary conditions, and failure modes extensively to prevent undefined application states.'
    ]
  }
};

// --- EXPORTS FOR TESTING ---
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    KNOWLEDGE_BASE_ARTICLES,
    COUNTERMEASURES_DICT
  };
}
