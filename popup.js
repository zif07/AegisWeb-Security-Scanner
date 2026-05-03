// --- STATE ---
let currentTabId = null;

// --- UTILS ---

function updateGauge(score) {
  // Score: 0-100
  const indicator = document.getElementById('gauge-indicator');
  const scoreVal = document.getElementById('score-val');
  const scoreText = document.getElementById('score-text');

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

    // Trigger Active Scan Immediately for accurate summary
    chrome.runtime.sendMessage({ type: 'startActiveScan', tabId: tab.id }, (resp) => {
      if (resp && resp.report) {
        renderScanner(resp.report);
      }
    });

    // Dashboard Button
    document.getElementById('btn-dashboard').addEventListener('click', () => {
      const dashboardUrl = chrome.runtime.getURL(`dashboard.html?tabId=${tab.id}`);
      chrome.tabs.create({ url: dashboardUrl });
    });
  });
});
