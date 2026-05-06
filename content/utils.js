function createFinding(category, severity, title, description, location) {
  const owaspMap = {
    'Phishing': 'A08:2025 Software or Data Integrity Failures',
    'Authentication': 'A07:2025 Authentication Failures',
    'XSS & Injection': 'A05:2025 Injection',
    'Transport Security': 'A04:2025 Cryptographic Failures',
    'Iframe & External': 'A06:2025 Insecure Design',
    'Headers & CSP': 'A02:2025 Security Misconfiguration',
    'General Security': 'A02:2025 Security Misconfiguration',
    'Access Control': 'A01:2025 Broken Access Control',
    'Insecure Design': 'A06:2025 Insecure Design',
    'Logging & Monitoring': 'A09:2025 Security Logging and Alerting Failures',
    'Supply Chain': 'A03:2025 Software Supply Chain Failures'
  };
  return { category: owaspMap[category] || category, severity, title, description, location };
}

// UTILS
function levenshtein(a, b) {
  const matrix = [];
  for (let i = 0; i <= b.length; i++) matrix[i] = [i];
  for (let j = 0; j <= a.length; j++) matrix[0][j] = j;
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) == a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1
        );
      }
    }
  }
  return matrix[b.length][a.length];
}

// --- EXPORTS FOR TESTING ---
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    createFinding,
    levenshtein
  };
}
