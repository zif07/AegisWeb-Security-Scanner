// Mock chrome APIs before requiring the module
global.chrome = {
  webRequest: { onHeadersReceived: { addListener: jest.fn() } },
  runtime: { onMessage: { addListener: jest.fn() } },
  tabs: { onRemoved: { addListener: jest.fn() } }
};

const { normalizeHeaders, computePassiveRisks } = require('../background.js');

describe('background.js utils', () => {
  test('normalizeHeaders converts names to lowercase', () => {
    const headers = [
      { name: 'Content-Type', value: 'text/html' },
      { name: 'X-Frame-Options', value: 'DENY' }
    ];
    const normalized = normalizeHeaders(headers);
    expect(normalized['content-type']).toBe('text/html');
    expect(normalized['x-frame-options']).toBe('DENY');
    expect(normalized['Content-Type']).toBeUndefined();
  });

  test('computePassiveRisks identifies missing security features', () => {
    const analysis = {
      https: false,
      hsts: { present: false },
      csp: false,
      xContentTypeOptions: false,
      xFrameOptions: false
    };
    const risks = computePassiveRisks(analysis);
    expect(risks).toContain('No HTTPS');
    expect(risks).toContain('Missing HSTS');
    expect(risks).toContain('Missing CSP');
    expect(risks.length).toBe(5);
  });
});
