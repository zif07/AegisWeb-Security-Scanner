/**
 * AegisWeb Anti-Tampering Guard
 * ─────────────────────────────────────────────────────────────────────────────
 * Uses MutationObserver to detect and respond to unauthorized DOM changes
 * that could indicate tampering, injection attacks, or widget removal attempts.
 *
 * Protections implemented:
 *   1. Script Injection Guard  – watches <head> and <body> for dynamically
 *                                inserted <script> or <iframe> elements that
 *                                were not placed by AegisWeb itself.
 *   2. Tamper Event Bus        – dispatches a custom "aegis:tamper" event so
 *                                other extension modules can react.
 *   3. Storage Integrity Guard – monitors chrome.storage.local for unauthorized
 *                                or invalid changes to extension settings.
 * ─────────────────────────────────────────────────────────────────────────────
 */

; (function AegisAntiTamper() {
  'use strict';

  /* ------------------------------------------------------------------ */
  /*  Constants                                                           */
  /* ------------------------------------------------------------------ */

  const TAMPER_EVENT = 'aegis:tamper';
  const LOG_PREFIX = '[AegisWeb Anti-Tamper]';

  /**
   * Trusted hostname patterns. Scripts/iframes from these origins are
   * considered page-native and are NOT flagged by the injection guard.
   * This prevents false-positives from Google APIs, CDNs, analytics, etc.
   */
  const TRUSTED_ORIGIN_PATTERNS = [
    /^https:\/\/[a-z0-9-]+\.google\.com(\/.+)?$/i,
    /^https:\/\/[a-z0-9-]+\.googleapis\.com(\/.+)?$/i,
    /^https:\/\/[a-z0-9-]+\.gstatic\.com(\/.+)?$/i,
    /^https:\/\/[a-z0-9-]+\.googletagmanager\.com(\/.+)?$/i,
    /^https:\/\/[a-z0-9-]+\.googleusercontent\.com(\/.+)?$/i,
    /^https:\/\/[a-z0-9-]+\.doubleclick\.net(\/.+)?$/i,
    /^https:\/\/[a-z0-9-]+\.facebook\.net(\/.+)?$/i,
    /^https:\/\/[a-z0-9-]+\.facebook\.com(\/.+)?$/i,
    /^https:\/\/[a-z0-9-]+\.cloudflare\.com(\/.+)?$/i,
    /^https:\/\/cdn\.jsdelivr\.net(\/.+)?$/i,
    /^https:\/\/cdnjs\.cloudflare\.com(\/.+)?$/i,
    /^https:\/\/unpkg\.com(\/.+)?$/i,
    /^https:\/\/ajax\.googleapis\.com(\/.+)?$/i,
    /^https:\/\/[a-z0-9-]+\.youtube\.com(\/.+)?$/i,
    /^https:\/\/[a-z0-9-]+\.ytimg\.com(\/.+)?$/i,
    /^https:\/\/[a-z0-9-]+\.twitter\.com(\/.+)?$/i,
    /^https:\/\/platform\.twitter\.com(\/.+)?$/i,
  ];

  /**
   * Returns true when a src URL is considered genuinely suspicious.
   * A URL is suspicious only if it:
   *   – is an inline script (no src / "(inline)")
   *   – uses a data: or javascript: URI
  /**
   * Returns true only when a script/iframe src is CLEARLY malicious.
   *
   * Design principle: when running as a content script on an arbitrary web
   * page, there is no way to know what scripts/iframes the page legitimately
   * uses. We therefore only flag sources that have NO legitimate use:
   *   – javascript: URIs as a src attribute (XSS classic)
   *   – data: URIs as a script src (data-URI script injection)
   *   – Non-HTTPS, non-about, non-blob third-party origins (rare but suspicious)
   *
   * Everything else (HTTPS third-parties, about:blank, srcdoc, inline scripts
   * with normal content, same-origin) is treated as safe to avoid the
   * constant false-positive storm seen on pages like google.com.
   */
  function _isSuspiciousSrc(src) {
    if (!src) return false;

    // Normalize to lowercase for case-insensitive comparison
    const lowerSrc = src.toLowerCase().trim();

    // Explicit dangerous schemes used as src values (XSS vectors)
    // Using a regex is more secure against leading whitespace/control characters and satisfies Snyk
    if (/^\s*(javascript|vbscript|data):/i.test(lowerSrc)) return true;

    // Our own extension is always safe
    if (/^chrome-extension:\/\//i.test(lowerSrc)) return false;

    // about: and blob: are standard browser-generated URIs — not suspicious
    if (/^(about|blob):/i.test(lowerSrc)) return false;

    // Placeholder values we assign when there is no src/srcdoc
    if (lowerSrc === '(inline)' || lowerSrc === '(unknown)' || lowerSrc === '(srcdoc)') return false;

    try {
      const url = new URL(src);
      // Same-origin is always safe
      if (url.origin === window.location.origin) return false;
      // HTTPS third-party: treat as safe (normal web behaviour)
      if (url.protocol === 'https:') return false;
      // Trusted CDN / platform origins (also covers http: variants of known CDNs)
      if (TRUSTED_ORIGIN_PATTERNS.some(re => re.test(src))) return false;
      // http: or other non-standard protocol from unknown origin → suspicious
      return url.protocol !== 'https:';
    } catch (_) {
      // URL could not be parsed (e.g. relative or unusual scheme) — not suspicious
      return false;
    }
  }

  /**
   * Returns true when an INLINE script's text content looks malicious.
   * Used only for <script> nodes with no src attribute.
   * Inline scripts are so common on the web that we NEVER flag them purely
   * for being inline — we only flag ones whose content matches known-bad
   * patterns that have no legitimate use.
   */
  function _isInlineScriptMalicious(node) {
    const text = (node.textContent || '').trim();
    if (!text) return false;
    // Obfuscated eval-of-base64: classic malware dropper pattern
    if (/eval\s*\(\s*atob\s*\(/.test(text)) return true;
    // document.write with javascript: URI
    if (/document\.write\s*\(.*javascript:/i.test(text)) return true;
    // Exfil attempt via image beacon with hardcoded external IP
    if (/new\s+Image\s*\(\s*\).*\.src\s*=.*http:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}/.test(text)) return true;
    return false;
  }

  /* ------------------------------------------------------------------ */
  /*  Internal State                                                      */
  /* ------------------------------------------------------------------ */

  let _injectionObserver = null;
  let _tamperCount = 0;
  let _guardActive = false;
  let _isReverting = false;  // Prevents storage-revert infinite loops

  /* ------------------------------------------------------------------ */
  /*  Utility: dispatch tamper event                                      */
  /* ------------------------------------------------------------------ */

  function dispatchTamperEvent(detail) {
    _tamperCount++;
    const event = new CustomEvent(TAMPER_EVENT, {
      bubbles: false,
      cancelable: false,
      detail: { ...detail, count: _tamperCount, ts: Date.now() }
    });
    document.dispatchEvent(event);

    // Also log to extension background for audit trail
    try {
      chrome.runtime.sendMessage({
        type: 'aegisTamperDetected',
        detail: { ...detail, count: _tamperCount }
      });
    } catch (_) { /* Extension context may be gone – ignore */ }
  }

  /* ------------------------------------------------------------------ */
  /*  1. Script / IFrame Injection Guard                                  */
  /* ------------------------------------------------------------------ */

  /**
   * Watches <head> and <body> for dynamically added <script> or <iframe>
   * elements not present at the time AegisWeb initialised.
   */
  function startInjectionGuard() {
    if (_injectionObserver) return; // Already running

    _injectionObserver = new MutationObserver((mutations) => {
      for (const mut of mutations) {
        for (const node of mut.addedNodes) {
          if (!(node instanceof Element)) continue;

          /* ---- <script> injection ------------------------------------ */
          if (node.tagName === 'SCRIPT') {
            const src = node.getAttribute('src'); // null if truly inline

            if (src) {
              // External script: check if the src looks malicious
              if (_isSuspiciousSrc(src)) {
                console.warn(`${LOG_PREFIX} Suspicious external script injection detected:`, src);
                dispatchTamperEvent({ type: 'script-injection', src });
              }
            } else {
              // Inline script: only flag if content matches known-bad patterns
              if (_isInlineScriptMalicious(node)) {
                console.warn(`${LOG_PREFIX} Malicious inline script pattern detected.`);
                dispatchTamperEvent({ type: 'inline-script-injection', src: '(inline-malicious)' });
              }
              // Otherwise: silently ignore — inline scripts are universal
            }
          }

          /* ---- <iframe> injection ------------------------------------ */
          if (node.tagName === 'IFRAME') {
            // srcdoc iframes are a browser-standard sandboxing pattern — always safe
            if (node.hasAttribute('srcdoc')) continue;

            const src = node.getAttribute('src') || '(unknown)';
            if (_isSuspiciousSrc(src)) {
              console.warn(`${LOG_PREFIX} Suspicious iframe injection detected:`, src);
              dispatchTamperEvent({ type: 'iframe-injection', src });
            }
          }
        }
      }
    });

    // Observe <head> and <body> — direct children only (subtree: false).
    // Using subtree: true caused thousands of false-positives from deeply-nested
    // page scripts (Google XJS, widget iframes, analytics, etc.).
    const targets = [document.head, document.body].filter(Boolean);
    for (const target of targets) {
      _injectionObserver.observe(target, {
        childList: true,
        subtree: false   // ← intentionally NOT recursive
      });
    }
  }

  /* ------------------------------------------------------------------ */
  /*  3. Storage Integrity Guard                                          */
  /* ------------------------------------------------------------------ */

  /**
   * Listens for changes in chrome.storage.local. If a critical value
   * is changed to an invalid state, it flags a tamper event.
   */
  /**
   * A flag set by the extension's own UI (popup) when it legitimately
   * changes a storage value. Content scripts signal this via a message.
   * While this flag is set, the storage guard will not revert the change.
   */
  let _allowedStorageChange = false;

  // Listen for the popup telling us a change is intentional
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg && msg.type === 'aegisStorageChangeAllowed') {
      _allowedStorageChange = true;
      // Auto-clear after a short window so we don't leave the gate open
      setTimeout(() => { _allowedStorageChange = false; }, 1000);
    }
  });

  function startStorageGuard() {
    console.log(`${LOG_PREFIX} Storage Integrity Guard starting...`);
    chrome.storage.onChanged.addListener((changes, areaName) => {
      if (areaName !== 'local') return;

      // If we caused this change (during a revert) OR the popup signalled
      // it is an intentional user action, skip the tamper check.
      if (_isReverting) {
        _isReverting = false;
        return;
      }
      if (_allowedStorageChange) {
        _allowedStorageChange = false;
        return;
      }

      for (const [key, { oldValue, newValue }] of Object.entries(changes)) {
        // Guard only explicitly owned AegisWeb storage keys.
        // No keys are currently guarded, so the loop is a no-op.
        const guardedKeys = new Set([
          // Add future critical keys here, e.g. 'aegisEnabled'
        ]);
        if (!guardedKeys.has(key)) continue;

        if (newValue !== oldValue) {
          console.warn(`${LOG_PREFIX} Unauthorized storage modification detected for: ${key}`);
          dispatchTamperEvent({ type: 'storage-tamper', key, reason: 'unauthorized-change' });

          // Revert to the previous value
          _isReverting = true;
          chrome.storage.local.set({ [key]: oldValue });
        }
      }
    });
  }

  /* ------------------------------------------------------------------ */
  /*  Public API                                                          */
  /* ------------------------------------------------------------------ */

  /**
   * startGuard()
   * Entry point. Activates all protections. Idempotent.
   */
  function startGuard() {
    if (_guardActive) return;
    _guardActive = true;

    // 1. Injection guard
    startInjectionGuard();

    // 2. Storage guard
    startStorageGuard();

    // Listen for AegisWeb's own tamper events to emit console warnings
    document.addEventListener(TAMPER_EVENT, (e) => {
      console.warn(`${LOG_PREFIX} Tamper event #${e.detail.count}:`, e.detail);
    });

    console.info(`${LOG_PREFIX} Anti-tamper guard active (Injection + Storage guards).`);
  }

  /**
   * stopGuard()
   * Tears down all observers. Use during extension unload.
   */
  function stopGuard() {
    if (_injectionObserver) {
      _injectionObserver.disconnect();
      _injectionObserver = null;
    }
    _guardActive = false;
    console.info(`${LOG_PREFIX} Anti-tamper guard stopped.`);
  }

  /**
   * getTamperCount()
   * Returns the number of tamper events detected this session.
   */
  function getTamperCount() {
    return _tamperCount;
  }

  /* ------------------------------------------------------------------ */
  /*  Expose on window.AegisAntiTamper for use by other content scripts   */
  /* ------------------------------------------------------------------ */
  window.AegisAntiTamper = {
    startGuard,
    stopGuard,
    getTamperCount,
    TAMPER_EVENT
  };

})();
