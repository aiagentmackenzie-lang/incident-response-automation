// test/response.test.js
'use strict';

const { respondToThreat } = require('../src/response/actions');

describe('Response Actions', () => {
  let originalSimulate;

  beforeEach(() => {
    originalSimulate = process.env.SIMULATE_RESPONSE;
    process.env.SIMULATE_RESPONSE = 'true';
  });

  afterEach(() => {
    process.env.SIMULATE_RESPONSE = originalSimulate;
  });

  test('handles BruteForceLogin threat', async () => {
    // Should not throw
    await expect(respondToThreat({
      type: 'BruteForceLogin',
      ip: '10.0.0.1'
    })).resolves.toBeUndefined();
  });

  test('handles unknown threat type gracefully', async () => {
    await expect(respondToThreat({
      type: 'UnknownThreat',
      ip: '10.0.0.1'
    })).resolves.toBeUndefined();
  });

  test('handles null threat', async () => {
    await expect(respondToThreat(null)).resolves.toBeUndefined();
  });
});