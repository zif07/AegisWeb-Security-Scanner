// --- RENDERERS ---
// Requires: KNOWLEDGE_BASE_ARTICLES, COUNTERMEASURES_DICT (global)

function renderReport(report, monitorResults = null) {
  // Update Target
  if (monitorResults && monitorResults.url) {
    document.getElementById('target-url-header').textContent = new URL(monitorResults.url).hostname;
  }

  if (!report) {
    const meterScoreText = document.getElementById('meter-score-text');
    if (meterScoreText) {
      meterScoreText.textContent = '--';
      meterScoreText.style.color = '#94a3b8';
    }
    const scoreEl = document.getElementById('overview-score');
    if (scoreEl) {
      scoreEl.textContent = '--';
      scoreEl.className = 'stat-value';
    }
    const scoreText = document.getElementById('score-text');
    if (scoreText) {
      scoreText.textContent = 'Scan Unavailable';
      scoreText.className = 'stat-trend';
      scoreText.style.color = '#94a3b8';
    }

    const findingsList = document.getElementById('vuln-findings-list');
    if (findingsList) {
      findingsList.innerHTML = '<div style="color:#94a3b8; font-weight:600; padding:10px;">Scan unavailable for this page.</div>';
    }
    return;
  }

  const findings = report.findings || [];

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

  // 1.5 Identified Technologies
  const techListEl = document.getElementById('identified-tech');
  if (techListEl) {
    techListEl.innerHTML = '';
    const techs = monitorResults ? (monitorResults.tech || []) : [];
    if (techs.length === 0) {
      techListEl.innerHTML = '<li><span style="color:#94a3b8">No specific frameworks detected</span></li>';
    } else {
      techs.forEach(t => {
        techListEl.innerHTML += `<li><span><span style="color:#3b82f6; margin-right:8px;">⚡</span> ${DOMPurify.sanitize(t)}</span></li>`;
      });
    }
  }

  // 2. Categories
  const catList = document.getElementById('vuln-categories');
  catList.innerHTML = '';
  Array.from(categoriesFound).forEach(cat => {
    let icon = '🛡';
    if (cat.includes('Cryptographic')) icon = '🔒';
    if (cat.includes('Misconfiguration')) icon = '📝';
    if (cat.includes('Injection')) icon = '💉';
    if (cat.includes('Authentication')) icon = '🔑';
    if (cat.includes('Insecure Design')) icon = '🔗';
    if (cat.includes('Integrity')) icon = '🎣';
    if (cat.includes('Access Control')) icon = '🚪';
    if (cat.includes('Supply Chain')) icon = '📦';
    if (cat.includes('Logging')) icon = '📊';
    if (cat.includes('Exceptional')) icon = '⚠️';

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

// --- EXPORTS FOR TESTING ---
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    renderReport
  };
}
