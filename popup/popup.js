// --- STATE ---
let currentTabId = null;

// --- UTILS ---

function updateGauge(score) {
  // Score: 0-100, or null if unavailable
  const indicator = document.getElementById('gauge-indicator');
  const scoreVal = document.getElementById('score-val');
  const scoreText = document.getElementById('score-text');

  if (score === null || score === undefined) {
    indicator.style.left = '0%';
    scoreVal.textContent = '--';
    scoreVal.className = 'score-big';
    scoreVal.style.color = '#94a3b8';
    scoreText.textContent = 'Scan Unavailable';
    scoreText.style.color = '#94a3b8';
    return;
  }

  // Clamp
  score = Math.max(0, Math.min(100, score));

  // Position Indicator (0% to 100% of bar width)
  indicator.style.left = `${score}%`;

  scoreVal.textContent = Math.round(score);

  // Text & Color
  scoreVal.className = 'score-big';
  if (score >= 80) {
    scoreVal.classList.add('good');
    scoreText.textContent = 'Excellent Security';
    scoreText.style.color = 'var(--score-green)';
  } else if (score >= 60) {
    scoreVal.classList.add('good'); // Limeish
    scoreText.textContent = 'Good Security';
    scoreText.style.color = 'var(--score-lime)';
  } else if (score >= 40) {
    scoreText.textContent = 'Fair Security';
    scoreText.style.color = 'var(--score-yellow)';
  } else if (score >= 20) {
    scoreVal.classList.add('bad');
    scoreText.textContent = 'Poor Security';
    scoreText.style.color = 'var(--score-orange)';
  } else {
    scoreVal.classList.add('bad');
    scoreText.textContent = 'Critical Risk';
    scoreText.style.color = 'var(--score-red)';
  }
}

function updateSummary(counts) {
  document.getElementById('sum-total').textContent = counts.total;
  document.getElementById('sum-crit').textContent = counts.critical;
  document.getElementById('sum-med').textContent = counts.medium;
  document.getElementById('sum-low').textContent = counts.low;
  document.getElementById('sum-info').textContent = counts.info;
}

function updateCategories(findings) {
  const cats = {};
  findings.forEach(f => {
    const c = f.category || 'General';
    cats[c] = (cats[c] || 0) + 1;
  });

  const list = document.getElementById('categories-list');
  list.innerHTML = '';

  Object.keys(cats).slice(0, 6).forEach(cat => { // Limit to 6 for grid
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

    list.innerHTML += `
      <div class="cat-item">
        <span class="cat-icon">${icon}</span> ${DOMPurify.sanitize(cat)} 
        <span class="cat-count">${cats[cat]}</span>
      </div>
    `;
  });

  if (Object.keys(cats).length === 0) {
    list.innerHTML = '<div style="grid-column: span 2; padding:8px; text-align:center; font-size:11px; color:#9fa6b2;">No vulnerabilities categorized yet.</div>';
  }
}

// --- RENDERERS ---
function renderMonitor(result) {
  // Simulating a score based on passive risks for initial view
  let baseScore = 100;
  const risks = result.risks || [];
  baseScore -= (risks.length * 10);

  // Passive Findings to populate initial summary
  const findings = risks.map(r => ({
    title: r,
    severity: 'MEDIUM',
    category: 'Headers & CSP',
    description: 'Issue detected via passive header analysis.',
    remediation: 'Configure server security headers correctly.',
    location: 'Response Headers'
  }));

  const counts = { total: findings.length, critical: 0, medium: findings.length, low: 0, info: 0 };

  updateGauge(baseScore);
  updateSummary(counts);
  updateCategories(findings);
}

function renderScanner(report) {
  const findings = report.findings;

  // 1. Calc Score (Simple Weighted)
  let score = 100;
  const counts = { total: 0, critical: 0, medium: 0, low: 0, info: 0 };
  const penalisedTitles = new Set();

  findings.forEach(f => {
    counts.total++;
    const s = f.severity?.toUpperCase() || 'INFO';
    
    if (s === 'CRITICAL') { counts.critical++; }
    else if (s === 'HIGH') { counts.medium++; } // Map High->Med for UI simplicity
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

  updateGauge(score);
  updateSummary(counts);
  updateCategories(findings);
  
  document.getElementById('score-text').textContent = 'Scan Complete';
}

// --- MAIN ---
  document.addEventListener('DOMContentLoaded', () => {
  chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
    const tab = tabs && tabs[0];
    if (!tab) return;
    currentTabId = tab.id;

    if (!tab.url || tab.url.startsWith('chrome://') || tab.url.startsWith('edge://') || tab.url.startsWith('about:')) {
      updateGauge(null);
      updateSummary({ total: '--', critical: '--', medium: '--', low: '--', info: '--' });
      document.getElementById('categories-list').innerHTML = '<div style="grid-column: span 2; padding:8px; text-align:center; font-size:11px; color:#9fa6b2;">Scan unavailable for this page.</div>';
      return;
    }

    // Trigger Active Scan Immediately for accurate summary
    chrome.runtime.sendMessage({ type: 'startActiveScan', tabId: tab.id }, (resp) => {
      if (chrome.runtime.lastError) {
        console.error(chrome.runtime.lastError);
        updateGauge(null);
        updateSummary({ total: '--', critical: '--', medium: '--', low: '--', info: '--' });
        document.getElementById('categories-list').innerHTML = '<div style="grid-column: span 2; padding:8px; text-align:center; font-size:11px; color:#9fa6b2;">Scan unavailable for this page.</div>';
        return;
      }
      if (resp && resp.report) {
        renderScanner(resp.report);
      } else {
        updateGauge(null);
        updateSummary({ total: '--', critical: '--', medium: '--', low: '--', info: '--' });
        document.getElementById('categories-list').innerHTML = '<div style="grid-column: span 2; padding:8px; text-align:center; font-size:11px; color:#9fa6b2;">Scan unavailable for this page.</div>';
      }
    });

    // Dashboard Button
    document.getElementById('btn-dashboard').addEventListener('click', () => {
      const dashboardUrl = chrome.runtime.getURL(`dashboard/dashboard.html?tabId=${tab.id}`);
      chrome.tabs.create({ url: dashboardUrl });
    });

  });
});

// --- EXPORTS FOR TESTING ---
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    updateGauge,
    updateSummary,
    updateCategories
  };
}

/**
 * --- UI INTEGRITY GUARD (ANTI-TAMPER) ---
 * Watches the popup UI for manual tampering in DevTools.
 * Starts after a short delay so the scan results can load first.
 */
function startUIIntegrityGuard() {
  const container = document.body;
  if (!container) return;

  // Wait 3 seconds for the scan to finish loading before watching
  setTimeout(() => {
    console.info('[AegisWeb Anti-Tamper] Popup UI guard now active.');

    const _uiObserver = new MutationObserver((mutations) => {
      for (const mut of mutations) {
        // 1. Detect if text was EDITED
        if (mut.type === 'characterData' || (mut.type === 'childList' && mut.target.nodeType === Node.ELEMENT_NODE)) {
          const target = mut.target.parentElement || mut.target;
          const isCriticalUI = target.closest('#score-val, #score-text, #sum-total, #sum-crit, #sum-med, #sum-low, #sum-info, .cat-count, .sum-item, .cat-item, .card-title, .app-title, .score-label, .label');
          
          if (isCriticalUI) {
            console.warn('[AegisWeb Anti-Tamper] UI manipulation detected. Restoring...');
            location.reload();
            return;
          }
        }

        // 2. Detect if an element was DELETED (removedNodes)
        if (mut.type === 'childList' && mut.removedNodes.length > 0) {
          for (const node of mut.removedNodes) {
            if (node.nodeType === Node.ELEMENT_NODE) {
              if (node.id === 'score-text' || node.id === 'score-val' || node.classList.contains('sum-item') || node.classList.contains('cat-item')) {
                console.warn('[AegisWeb Anti-Tamper] UI removal detected. Restoring...');
                location.reload();
                return;
              }
            }
          }
        }
      }
    });

    _uiObserver.observe(container, {
      characterData: true,
      childList: true,
      subtree: true
    });
  }, 3000);
}

// Start the guard when the popup is ready
document.addEventListener('DOMContentLoaded', startUIIntegrityGuard);
