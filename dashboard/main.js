// --- STATE ---
let currentTabId = null;
let lastReport = null;
let lastMonitorResults = null;
let isRendering = false;
let pristineHTML = "";

// --- UTILS ---
function getQueryParam(name) {
  return new URLSearchParams(window.location.search).get(name);
}

// --- ANTI-TAMPERING (DOM INTEGRITY GUARD) ---
function startDashboardAntiTamper() {
  const targetNode = document.getElementById('main-content');
  if (!targetNode) return;

  const observer = new MutationObserver((mutationsList) => {
    if (isRendering || !pristineHTML) return;

    let tamperingDetected = false;
    for (const mutation of mutationsList) {
      if (mutation.type === 'characterData' || mutation.type === 'childList' || mutation.type === 'attributes') {
        tamperingDetected = true;
        break;
      }
    }

    if (tamperingDetected) {
      console.log('DOM Tampering Detected! Restoring original data...');
      isRendering = true;
      targetNode.innerHTML = pristineHTML;
      
      // If the meter needle was reset by innerHTML, re-apply the rotation
      if (lastReport) {
        let score = 100;
        const penalisedTitles = new Set();
        (lastReport.findings || []).forEach(f => {
          const s = f.severity?.toUpperCase() || 'INFO';
          if (!penalisedTitles.has(f.title)) {
            penalisedTitles.add(f.title);
            if (s === 'CRITICAL') { score -= 20; }
            else if (s === 'HIGH') { score -= 15; }
            else if (s === 'MEDIUM') { score -= 10; }
            else if (s === 'LOW') { score -= 5; }
          }
        });
        score = Math.max(0, score);
        const meterNeedle = document.getElementById('meter-needle');
        if (meterNeedle) {
          const degrees = 180 + (score / 100) * 180;
          meterNeedle.style.transform = `rotate(${degrees}deg)`;
        }
      }

      setTimeout(() => { isRendering = false; }, 200);
    }
  });

  observer.observe(targetNode, {
    attributes: true,
    childList: true,
    characterData: true,
    subtree: true
  });
}

// --- MAIN ---
document.addEventListener('DOMContentLoaded', () => {
  // Start the guard
  startDashboardAntiTamper();

  const urlParam = getQueryParam('tabId');
  if (urlParam) {
     currentTabId = parseInt(urlParam, 10);
     
     // 1. Fetch Passive Monitor data immediately for the header/tech stack
     chrome.runtime.sendMessage({ type: 'getResultsForTab', tabId: currentTabId }, monitorResp => {
       if (chrome.runtime.lastError) {
         console.error(chrome.runtime.lastError);
       }
       const monitorResults = monitorResp && monitorResp.result ? monitorResp.result : null;
       
       // 2. We trigger Active Scan to ensure we have the absolute latest report
       chrome.runtime.sendMessage({ type: 'startActiveScan', tabId: currentTabId }, (resp) => {
          if (chrome.runtime.lastError) {
            console.error(chrome.runtime.lastError);
            document.getElementById('error').classList.remove('hidden');
            return;
          }
          if (resp && resp.report) {
            // Save data for the anti-tamper guard
            lastReport = resp.report;
            lastMonitorResults = monitorResults;
            
            isRendering = true;
            renderReport(resp.report, monitorResults);
            
            // Wait for SVG transitions and DOM updates to settle, then save the pristine state
            setTimeout(() => { 
              const targetNode = document.getElementById('main-content');
              if (targetNode) {
                pristineHTML = targetNode.innerHTML;
              }
              isRendering = false; 
            }, 300);
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

// --- EXPORTS FOR TESTING ---
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    getQueryParam
  };
}
