// test/response.test.js
'use strict';

const { respondToThreat } = require('../src/response/actions');

describe('Response Actions', () => {
  const originalSimulate = process.env.SIMULATE_RESPONSE;

  afterEach(() => {
    process.env.SIMULATE_RESPONSE = originalSimulate;
  });

  test('handles BruteForceLogin threat in simulate mode', async () => {
    process.env.SIMULATE_RESPONSE = 'true';
    // Should not throw
    await expect(respondToThreat({
      type: 'BruteForceLogin',
      ip: '10.0.0.1'
    })).resolves.toBeUndefined();
  });

  test('handles BruteForceLogin threat in real mode', async () => {
    process.env.SIMULATE_RESPONSE = 'false';
    // Real mode — currently logs [ACTION] instead of [SIMULATE]
    const logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
    await respondToThreat({
      type: 'BruteForceLogin',
      ip: '10.0.0.2'
    }, false);
    expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('[ACTION]'));
    logSpy.mockRestore();
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

  test('respects SIMULATE_RESPONSE at call time', async () => {
    process.env.SIMULATE_RESPONSE = 'true';
    const logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
    await respondToThreat({ type: 'BruteForceLogin', ip: '10.0.0.3' }, false);
    expect(logSpy).toHaveBeenCalledWith(expect.stringContaining('[SIMULATE]'));
    logSpy.mockRestore();

    // Now switch to real mode
    process.env.SIMULATE_RESPONSE = 'false';
    const logSpy2 = jest.spyOn(console, 'log').mockImplementation(() => {});
    await respondToThreat({ type: 'BruteForceLogin', ip: '10.0.0.4' }, false);
    expect(logSpy2).toHaveBeenCalledWith(expect.stringContaining('[ACTION]'));
    logSpy2.mockRestore();
  });
});