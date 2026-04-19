// test/classifier.test.js
'use strict';

const { classifyIncident } = require('../src/ai/classifier');

describe('AI Classifier', () => {
  test('returns fallback when AI not configured', async () => {
    const result = await classifyIncident({ type: 'BruteForceLogin', ip: '10.0.0.1' });
    expect(result.enabled).toBe(false);
    expect(result.severity).toBe('MEDIUM');
    expect(result.recommendation).toContain('AI not configured');
  });

  test('returns valid structure for any threat', async () => {
    const result = await classifyIncident({ type: 'TestThreat' });
    expect(result).toHaveProperty('enabled');
    expect(result).toHaveProperty('severity');
    expect(result).toHaveProperty('recommendation');
  });
});