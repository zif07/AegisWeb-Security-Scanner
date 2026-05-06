/**
 * @jest-environment jsdom
 */

// Mock chrome APIs before requiring the module
global.chrome = {
  runtime: {
    sendMessage: jest.fn(),
    onMessage: { addListener: jest.fn() }
  }
};

const { levenshtein, createFinding } = require('../content/utils.js');

describe('content.js utils', () => {
  test('levenshtein calculates correct edit distance', () => {
    expect(levenshtein('kitten', 'sitting')).toBe(3);
    expect(levenshtein('google.com', 'gogle.com')).toBe(1); // Typosquatting scenario
    expect(levenshtein('facebook.com', 'facebook.com')).toBe(0); // Identical
  });

  test('createFinding maps categories correctly to OWASP', () => {
    const finding = createFinding('Phishing', 'HIGH', 'Deceptive Link', 'Description', 'href');
    expect(finding.category).toBe('A08:2025 Software or Data Integrity Failures');
    expect(finding.severity).toBe('HIGH');
    expect(finding.title).toBe('Deceptive Link');
  });
});
