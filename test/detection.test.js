// test/detection.test.js
'use strict';

const { createDetector } = require('../src/detection/rules');

// Use public IPs (203.0.113.x = TEST-NET-3, RFC 5737) to avoid SuspiciousIP triggering
function buildLog(ip, event, ts, extra = {}) {
  return { ip, event, timestamp: ts ? new Date(ts) : new Date(), ...extra };
}

describe('Detection Rules', () => {
  let detector;

  beforeEach(() => {
    detector = createDetector({ bruteForceThreshold: 10, spikeThreshold: 100 });
  });

  describe('BruteForceLogin', () => {
    test('detects brute force after threshold', () => {
      const ip = '203.0.113.1';
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
      const ip = '203.0.113.2';
      // Trigger the rule
      for (let i = 0; i < 10; i++) {
        detector.detectAll(buildLog(ip, 'failed login'));
      }
      // Next failed login should NOT re-trigger (counter was reset)
      const threat = detector.detectAll(buildLog(ip, 'failed login'));
      expect(threat).toBeNull();
    });

    test('re-triggers after counter resets and re-accumulates', () => {
      const ip = '203.0.113.3';
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
      const result = detector.detectAll(buildLog('203.0.113.1', 'successful login'));
      expect(result).toBeNull();
    });

    test('ignores page view events', () => {
      const result = detector.detectAll(buildLog('203.0.113.1', 'page view'));
      expect(result).toBeNull();
    });

    test('ignores malformed logs', () => {
      expect(detector.detectAll(null)).toBeNull();
      expect(detector.detectAll({ ip: '203.0.113.1' })).toBeNull();
      expect(detector.detectAll({})).toBeNull();
    });

    test('tracks IPs independently', () => {
      const ip1 = '203.0.113.1';
      const ip2 = '203.0.113.2';
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

  describe('EventSpike', () => {
    test('detects event spike after threshold', () => {
      const ip = '203.0.113.5';
      const spikeDetector = createDetector({ spikeThreshold: 5 });
      let threat = null;

      // 4 events — no spike
      for (let i = 0; i < 4; i++) {
        threat = spikeDetector.detectAll(buildLog(ip, 'page view'));
        expect(threat).toBeNull();
      }

      // 5th event — spike detected
      threat = spikeDetector.detectAll(buildLog(ip, 'page view'));
      expect(threat).not.toBeNull();
      expect(threat.type).toBe('EventSpike');
      expect(threat.ip).toBe(ip);
      expect(threat.source).toBe('spikeRule');
    });

    test('does not trigger spike for normal traffic', () => {
      const ip = '203.0.113.6';
      for (let i = 0; i < 3; i++) {
        const result = detector.detectAll(buildLog(ip, 'page view'));
        expect(result).toBeNull();
      }
    });
  });

  describe('SuspiciousIP', () => {
    test('detects loopback IP as suspicious', () => {
      const threat = detector.detectAll(buildLog('127.0.0.1', 'page view'));
      expect(threat).not.toBeNull();
      expect(threat.type).toBe('SuspiciousIP');
      expect(threat.ip).toBe('127.0.0.1');
      expect(threat.source).toBe('suspiciousIPRule');
    });

    test('detects private range IPs as suspicious', () => {
      const threat = detector.detectAll(buildLog('10.0.0.1', 'successful login'));
      expect(threat).not.toBeNull();
      expect(threat.type).toBe('SuspiciousIP');
      expect(threat.reason).toBe('private_range');
    });

    test('detects 192.168.x.x as suspicious', () => {
      const threat = detector.detectAll(buildLog('192.168.1.1', 'page view'));
      expect(threat).not.toBeNull();
      expect(threat.type).toBe('SuspiciousIP');
    });

    test('detects link-local as suspicious', () => {
      const threat = detector.detectAll(buildLog('169.254.1.1', 'GET /'));
      expect(threat).not.toBeNull();
      expect(threat.type).toBe('SuspiciousIP');
    });

    test('does not flag public IPs as suspicious', () => {
      const threat = detector.detectAll(buildLog('203.0.113.5', 'page view'));
      expect(threat).toBeNull();
    });

    test('allows custom suspicious IPs', () => {
      const customDetector = createDetector({ suspiciousIPs: ['1.2.3.4'] });
      const threat = customDetector.detectAll(buildLog('1.2.3.4', 'page view'));
      expect(threat).not.toBeNull();
      expect(threat.type).toBe('SuspiciousIP');
    });

    test('deduplicates SuspiciousIP alerts per IP', () => {
      const ip = '127.0.0.1';
      const first = detector.detectAll(buildLog(ip, 'page view'));
      expect(first).not.toBeNull();
      expect(first.type).toBe('SuspiciousIP');
      // Second event from same IP should not re-alert
      const second = detector.detectAll(buildLog(ip, 'page view'));
      expect(second).toBeNull();
    });
  });

  describe('UnauthorizedAccess', () => {
    test('detects failed login to admin endpoint', () => {
      const threat = detector.detectAll(buildLog('203.0.113.5', 'failed login to /admin'));
      expect(threat).not.toBeNull();
      expect(threat.type).toBe('UnauthorizedAccess');
      expect(threat.pattern).toBe('admin');
    });

    test('detects 403 status to .env', () => {
      const threat = detector.detectAll(buildLog('203.0.113.5', 'GET /.env', new Date(), { status: 403 }));
      expect(threat).not.toBeNull();
      expect(threat.type).toBe('UnauthorizedAccess');
    });

    test('detects 401 status to wp-login', () => {
      const threat = detector.detectAll(buildLog('203.0.113.5', 'POST /wp-login.php', new Date(), { status: 401 }));
      expect(threat).not.toBeNull();
      expect(threat.type).toBe('UnauthorizedAccess');
    });

    test('does not flag successful login to normal path', () => {
      const threat = detector.detectAll(buildLog('203.0.113.5', 'successful login'));
      expect(threat).toBeNull();
    });

    test('does not flag failed login to non-sensitive path', () => {
      const threat = detector.detectAll(buildLog('203.0.113.5', 'failed login to /home'));
      expect(threat).toBeNull();
    });
  });

  describe('Priority order', () => {
    test('BruteForceLogin takes priority over SuspiciousIP for private IPs', () => {
      // Private IP (10.0.0.x triggers SuspiciousIP) but brute force should take priority
      const ip = '10.0.0.99';
      const bruteDetector = createDetector({ bruteForceThreshold: 3 });
      for (let i = 0; i < 2; i++) {
        bruteDetector.detectAll(buildLog(ip, 'failed login'));
      }
      // 3rd failed login — BruteForceLogin should win
      const threat = bruteDetector.detectAll(buildLog(ip, 'failed login'));
      expect(threat.type).toBe('BruteForceLogin');
    });
  });
});