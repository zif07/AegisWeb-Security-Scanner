// --- MAIN ENTRY POINT ---
// Requires detectTech from tech-detector.js and runActiveScan from active-scanner.js

function sendDetection() {
  chrome.runtime.sendMessage({
    type: 'techDetection',
    payload: {
      isSecureContext: window.isSecureContext,
      tech: detectTech()
    }
  });
}

// --- LISTENERS ---
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === 'runPageScan') {
    const findings = runActiveScan();
    sendResponse({ findings });
  }
});

// Init
detectTech();
sendDetection();
setTimeout(sendDetection, 2000);

// Start anti-tamper protection (Storage Integrity + Injection guards)
if (window.AegisAntiTamper) {
  window.AegisAntiTamper.startGuard();
}
