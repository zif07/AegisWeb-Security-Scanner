// --- STATE ---
let currentTabId = null;

// --- UTILS ---
function getQueryParam(name) {
  return new URLSearchParams(window.location.search).get(name);
}

// --- MAIN ---
document.addEventListener('DOMContentLoaded', () => {
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

// --- EXPORTS FOR TESTING ---
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    getQueryParam
  };
}
