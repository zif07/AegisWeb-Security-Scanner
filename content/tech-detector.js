// --- TECH DETECTION ---
function detectTech() {
  const tech = new Set();
  const lower = (s) => (s || '').toLowerCase();

  // 1. Meta Generator
  document.querySelectorAll('meta[name="generator"]').forEach(g => {
    if (g.content) tech.add(g.content);
  });

  // 2. Scripts/Links
  const sources = [
    ...Array.from(document.scripts).map(s => lower(s.src)),
    ...Array.from(document.querySelectorAll('link[rel="stylesheet"]')).map(l => lower(l.href))
  ];

  if (sources.some(s => s.includes('wp-content'))) tech.add('WordPress');
  if (sources.some(s => s.includes('jquery'))) tech.add('jQuery');
  if (sources.some(s => s.includes('bootstrap'))) tech.add('Bootstrap');
  if (sources.some(s => s.includes('fontawesome'))) tech.add('FontAwesome');
  if (sources.some(s => s.includes('react'))) tech.add('React');
  if (sources.some(s => s.includes('vue'))) tech.add('Vue.js');
  if (sources.some(s => s.includes('angular'))) tech.add('Angular');

  // 3. Global Vars / DOM
  if (document.querySelector('[data-reactroot]')) tech.add('React');
  if (window.React || window.ReactDOM) tech.add('React');
  if (window.Vue) tech.add('Vue.js');
  if (window.angular) tech.add('Angular');
  if (window.jQuery) {
    const v = window.jQuery.fn.jquery;
    tech.add(`jQuery ${v || ''}`.trim());
  }

  return Array.from(tech);
}

// --- EXPORTS FOR TESTING ---
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    detectTech
  };
}
