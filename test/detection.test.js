// test/detection.test.js
'use strict';

const { createDetector } = require('../src/detection/rules');

function buildLog(ip, event, ts) {
  return { ip, event, timestamp: ts ? new Date(ts) : new Date() };
}

describe('Detection Rules', () => {
  let detector;

  beforeEach(() => {
    detector = createDetector({ bruteForceThreshold: 10 });
  });

  test('detects brute force after threshold', () => {
    const ip = '10.0.0.1';
    let threat = null;

    // Send 9 failed logins — should not trigger
    for (let i = 0; i < 9; i++) {
      threat = detector.detectAll(buildLog(ip, 'failed login'));
      expect(threat).toBeNull();
    }

    // 10th failed login — should trigger
    threat = detector.detectAll(buildLog(ip, 'failed login'));
    expect(threat).not.toBeNull();
    expect(threat.type).toBe('BruteForceLogin');
    expect(threat.ip).toBe(ip);
    expect(threat.count).toBe(10);
    expect(threat.source).toBe('bruteForceRule');
  });

  test('does not spam alerts after threshold (dedup)', () => {
    const ip = '10.0.0.2';
    // Trigger the rule
    for (let i = 0; i < 10; i++) {
      detector.detectAll(buildLog(ip, 'failed login'));
    }
    // Next failed login should NOT re-trigger (counter was reset)
    const threat = detector.detectAll(buildLog(ip, 'failed login'));
    expect(threat).toBeNull();
  });

  test('re-triggers after counter resets and re-accumulates', () => {
    const ip = '10.0.0.3';
    // Trigger once
    for (let i = 0; i < 10; i++) {
      detector.detectAll(buildLog(ip, 'failed login'));
    }
    // Counter was reset, need 10 more to re-trigger
    let threat = null;
    for (let i = 0; i < 9; i++) {
      threat = detector.detectAll(buildLog(ip, 'failed login'));
      expect(threat).toBeNull();
    }
    threat = detector.detectAll(buildLog(ip, 'failed login'));
    expect(threat).not.toBeNull();
    expect(threat.count).toBe(10);
  });

  test('ignores non-failed-login events', () => {
    const result = detector.detectAll(buildLog('10.0.0.1', 'successful login'));
    expect(result).toBeNull();
  });

  test('ignores page view events', () => {
    const result = detector.detectAll(buildLog('10.0.0.1', 'page view'));
    expect(result).toBeNull();
  });

  test('ignores malformed logs', () => {
    expect(detector.detectAll(null)).toBeNull();
    expect(detector.detectAll({ ip: '10.0.0.1' })).toBeNull();
    expect(detector.detectAll({})).toBeNull();
  });

  test('tracks IPs independently', () => {
    const ip1 = '10.0.0.1';
    const ip2 = '10.0.0.2';
    // 5 from each
    for (let i = 0; i < 5; i++) {
      detector.detectAll(buildLog(ip1, 'failed login'));
      detector.detectAll(buildLog(ip2, 'failed login'));
    }
    // Neither should trigger yet
    expect(detector.detectAll(buildLog(ip1, 'failed login'))).toBeNull();
    // 5 more from ip2 to trigger
    for (let i = 0; i < 4; i++) {
      detector.detectAll(buildLog(ip2, 'failed login'));
    }
    const threat = detector.detectAll(buildLog(ip2, 'failed login'));
    expect(threat).not.toBeNull();
    expect(threat.ip).toBe(ip2);
  });
});