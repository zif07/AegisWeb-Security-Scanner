class AegisWebWidget {
  constructor() {
    this.container = document.createElement('div');
    this.container.id = 'aegisweb-floating-widget';
    this.container.style.position = 'fixed';
    this.container.style.bottom = '24px';
    this.container.style.right = '24px';
    this.container.style.zIndex = '2147483647'; // Max z-index
    
    // Use Shadow DOM to isolate styles
    this.shadowRoot = this.container.attachShadow({ mode: 'closed' });
    this.render();
    
    document.body.appendChild(this.container);
  }

  render() {
    this.shadowRoot.innerHTML = `
      <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&display=swap');

        :host {
          all: initial;
        }

        .widget-wrapper {
          display: flex;
          align-items: center;
          gap: 12px;
          font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        }
        
        /* Floating Action Button */
        .fab {
          width: 56px;
          height: 56px;
          border-radius: 50%;
          background: linear-gradient(135deg, #1e293b, #0f172a);
          border: 1px solid rgba(255, 255, 255, 0.1);
          box-shadow: 0 4px 20px rgba(0,0,0,0.4), inset 0 1px 1px rgba(255,255,255,0.1);
          display: flex;
          justify-content: center;
          align-items: center;
          cursor: pointer;
          transition: transform 0.25s cubic-bezier(0.34, 1.56, 0.64, 1), box-shadow 0.2s;
          position: relative;
          z-index: 2;
        }
        
        .fab:hover {
          transform: scale(1.08);
          box-shadow: 0 6px 25px rgba(0,0,0,0.5), inset 0 1px 1px rgba(255,255,255,0.15);
        }
        
        .fab:active {
          transform: scale(0.95);
        }

        .fab svg {
          width: 28px;
          height: 28px;
          fill: none;
          stroke: #38bdf8;
          stroke-width: 2;
          stroke-linecap: round;
          stroke-linejoin: round;
          transition: stroke 0.3s;
        }

        .fab.has-issues svg {
          stroke: #fbbf24; /* Warning yellow */
        }

        .fab.has-critical svg {
          stroke: #ef4444; /* Critical red */
        }

        /* Information Panel */
        .panel {
          background: rgba(15, 23, 42, 0.85);
          backdrop-filter: blur(12px);
          -webkit-backdrop-filter: blur(12px);
          border: 1px solid rgba(255, 255, 255, 0.1);
          border-radius: 16px;
          padding: 14px 20px;
          color: white;
          opacity: 0;
          transform: translateX(20px) scale(0.95);
          pointer-events: none;
          transition: all 0.3s cubic-bezier(0.34, 1.56, 0.64, 1);
          transform-origin: right center;
          box-shadow: 0 10px 30px rgba(0,0,0,0.3);
          white-space: nowrap;
          display: flex;
          flex-direction: column;
          gap: 4px;
        }

        .widget-wrapper.open .panel {
          opacity: 1;
          transform: translateX(0) scale(1);
          pointer-events: auto;
        }
        
        .panel-header {
          font-size: 15px;
          font-weight: 600;
          color: #f8fafc;
          display: flex;
          align-items: center;
          gap: 8px;
        }
        
        .panel-status {
          font-size: 13px;
          color: #94a3b8;
          font-weight: 400;
        }

        .indicator {
          width: 8px;
          height: 8px;
          border-radius: 50%;
          background: #10b981; /* Green */
          box-shadow: 0 0 8px #10b981;
          transition: all 0.3s;
        }

        .indicator.warning {
          background: #fbbf24;
          box-shadow: 0 0 8px #fbbf24;
        }

        .indicator.critical {
          background: #ef4444;
          box-shadow: 0 0 8px #ef4444;
        }
      </style>
      
      <div class="widget-wrapper" id="wrapper">
        <div class="panel">
          <div class="panel-header">
            <div class="indicator" id="indicator"></div>
            AegisWeb Scanner
          </div>
          <div class="panel-status" id="status">Ready</div>
        </div>
        <div class="fab" id="fab" title="Toggle AegisWeb Details">
          <svg viewBox="0 0 24 24">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          </svg>
        </div>
      </div>
    `;

    const fab = this.shadowRoot.getElementById('fab');
    const wrapper = this.shadowRoot.getElementById('wrapper');
    const statusText = this.shadowRoot.getElementById('status');
    const indicator = this.shadowRoot.getElementById('indicator');

    fab.addEventListener('click', () => {
      wrapper.classList.toggle('open');
      if (wrapper.classList.contains('open')) {
        this.updateStatus(statusText, indicator, fab);
      }
    });

    // Optionally auto-check once on load silently
    setTimeout(() => {
      try {
        chrome.runtime.sendMessage({ type: 'startActiveScan' }, (response) => {
          if (chrome.runtime.lastError) {
            // Ignore port closed errors
          }
          if (response && response.report && response.report.findings) {
            this.applyStatusClasses(response.report.findings, statusText, indicator, fab, true);
          } else if (typeof runActiveScan === 'function') {
            const findings = runActiveScan();
            this.applyStatusClasses(findings, statusText, indicator, fab, true);
          }
        });
      } catch (e) {}
    }, 2000);
  }

  updateStatus(statusEl, indicatorEl, fabEl) {
    statusEl.textContent = "Scanning page...";
    indicatorEl.className = "indicator"; // reset
    fabEl.className = "fab"; // reset

    setTimeout(() => {
      try {
        chrome.runtime.sendMessage({ type: 'startActiveScan' }, (response) => {
          if (chrome.runtime.lastError) {
            // Ignore
          }
          if (response && response.report && response.report.findings) {
            this.applyStatusClasses(response.report.findings, statusEl, indicatorEl, fabEl, false);
          } else if (typeof runActiveScan === 'function') {
            const findings = runActiveScan();
            this.applyStatusClasses(findings, statusEl, indicatorEl, fabEl, false);
          } else {
            statusEl.textContent = "Scanner module not loaded";
          }
        });
      } catch (e) {
        statusEl.textContent = "Error running scan";
      }
    }, 500); // Fake small delay for UI effect
  }

  applyStatusClasses(findings, statusEl, indicatorEl, fabEl, silent) {
    const total = findings.length;
    let hasCritical = false;
    let hasWarning = false;

    findings.forEach(f => {
      if (f.severity === 'CRITICAL' || f.severity === 'HIGH') hasCritical = true;
      if (f.severity === 'MEDIUM' || f.severity === 'LOW') hasWarning = true;
    });

    if (total === 0) {
      if(!silent) statusEl.textContent = "Secure: No threats detected";
      indicatorEl.className = "indicator"; // Green
      fabEl.className = "fab";
    } else {
      if(!silent) statusEl.textContent = `${total} vulnerability(s) found`;
      
      if (hasCritical) {
        indicatorEl.className = "indicator critical";
        fabEl.className = "fab has-critical";
      } else {
        indicatorEl.className = "indicator warning";
        fabEl.className = "fab has-issues";
      }
    }
  }

  destroy() {
    if (this.container.parentNode) {
      this.container.parentNode.removeChild(this.container);
    }
  }
}

let activeAegisWebWidget = null;

function checkAegisWebWidgetState() {
  if (!chrome.storage || !chrome.storage.local) return; // Fallback if API not available
  
  chrome.storage.local.get({ widgetEnabled: false }, (result) => {
    if (result.widgetEnabled) {
      if (!activeAegisWebWidget) {
        activeAegisWebWidget = new AegisWebWidget();
      }
    } else {
      if (activeAegisWebWidget) {
        activeAegisWebWidget.destroy();
        activeAegisWebWidget = null;
      }
    }
  });
}

// Initial check
checkAegisWebWidgetState();

// Listen for toggles
if (chrome.storage && chrome.storage.onChanged) {
  chrome.storage.onChanged.addListener((changes, namespace) => {
    if (namespace === 'local' && changes.widgetEnabled) {
      checkAegisWebWidgetState();
    }
  });
}
