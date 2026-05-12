// src/detection/rules.js
'use strict';

const { TimeWindowCounter } = require('./stateStore');

const DEFAULT_WINDOW_MS = (parseInt(process.env.TIME_WINDOW_SECONDS, 10) || 60) * 1000;
const DEFAULT_BRUTE_THRESHOLD = parseInt(process.env.BRUTE_FORCE_THRESHOLD, 10) || 10;
const DEFAULT_SPIKE_THRESHOLD = parseInt(process.env.SPIKE_THRESHOLD, 10) || 100;

// Known malicious / suspicious IP ranges (RFC 5737 test ranges + link-local + common scanner IPs)
const SUSPICIOUS_IPS = new Set([
  '0.0.0.0',
  '127.0.0.1'  // loopback appearing in external logs is suspicious
]);
const SUSPICIOUS_RANGES = [
  { network: '10.0.0.0', mask: '255.0.0.0' },   // private — unexpected in external logs
  { network: '192.168.0.0', mask: '255.255.0.0' }, // private — unexpected from external
  { network: '169.254.0.0', mask: '255.255.0.0' }   // link-local
];

// Endpoints considered sensitive for unauthorized access detection
const SENSITIVE_PATTERNS = [
  /admin/i,
  /wp-admin/i,
  /\.env/i,
  /wp-login/i,
  /phpmyadmin/i,
  /console/i,
  /manager/i,
  /actuator/i
];

/**
 * Create a detection engine with its own state (testable + no cross-contamination)
 * @param {object} [opts]
 * @param {number} [opts.timeWindowMs]
 * @param {number} [opts.bruteForceThreshold]
 * @param {number} [opts.spikeThreshold]
 * @param {string[]} [opts.suspiciousIPs] - additional IPs to flag
 * @param {RegExp[]} [opts.sensitivePatterns] - additional sensitive endpoint patterns
 * @returns {{ detectAll: function, detectBruteForce: function, detectSpike: function, detectSuspiciousIP: function, detectUnauthorizedAccess: function, threshold: number }}
 */
function createDetector(opts = {}) {
  const windowMs = opts.timeWindowMs || DEFAULT_WINDOW_MS;
  const bruteThreshold = opts.bruteForceThreshold || DEFAULT_BRUTE_THRESHOLD;
  const spikeThreshold = opts.spikeThreshold || DEFAULT_SPIKE_THRESHOLD;
  const bruteCounter = new TimeWindowCounter(windowMs);
  const spikeCounter = new TimeWindowCounter(windowMs);

  const suspiciousIPs = new Set(SUSPICIOUS_IPS);
  if (opts.suspiciousIPs) {
    opts.suspiciousIPs.forEach(ip => suspiciousIPs.add(ip));
  }
  const sensitivePatterns = [...SENSITIVE_PATTERNS, ...(opts.sensitivePatterns || [])];
  const alertedIPs = new Set(); // Deduplicate SuspiciousIP alerts per IP

  /**
   * Detect brute-force login attempts.
   * Triggers when bruteThreshold failed logins from the same IP occur within windowMs.
   */
  function detectBruteForce(log) {
    if (!log || !log.event) return null;
    if (!/failed login/i.test(log.event)) return null;

    const count = bruteCounter.add(log.ip, log.timestamp);
    if (count >= bruteThreshold) {
      bruteCounter.reset(log.ip); // Alert once, then reset to avoid spam
      return {
        type: 'BruteForceLogin',
        ip: log.ip,
        count,
        timestamp: log.timestamp,
        source: 'bruteForceRule'
      };
    }
    return null;
  }

  /**
   * Detect request / event spikes from a single IP.
   * Triggers when spikeThreshold events (any type) from the same IP within windowMs.
   */
  function detectSpike(log) {
    if (!log || !log.ip) return null;
    if (!log.timestamp || !(log.timestamp instanceof Date)) return null;

    const count = spikeCounter.add(log.ip, log.timestamp);
    if (count >= spikeThreshold) {
      spikeCounter.reset(log.ip);
      return {
        type: 'EventSpike',
        ip: log.ip,
        count,
        timestamp: log.timestamp,
        source: 'spikeRule'
      };
    }
    return null;
  }

  /**
   * Detect access from suspicious IPs (known malicious ranges, loopback, link-local).
   * Alerts once per IP, then suppresses to avoid alert spam.
   */
  function detectSuspiciousIP(log) {
    if (!log || !log.ip) return null;
    if (!log.timestamp || !(log.timestamp instanceof Date)) return null;

    // Exact match on known-bad IPs
    if (suspiciousIPs.has(log.ip)) {
      if (alertedIPs.has(log.ip)) return null;
      alertedIPs.add(log.ip);
      return {
        type: 'SuspiciousIP',
        ip: log.ip,
        timestamp: log.timestamp,
        source: 'suspiciousIPRule'
      };
    }

    // Private / link-local ranges from external-facing logs are suspicious
    if (log.ip.startsWith('10.') || log.ip.startsWith('192.168.') || log.ip.startsWith('169.254.')) {
      if (alertedIPs.has(log.ip)) return null;
      alertedIPs.add(log.ip);
      return {
        type: 'SuspiciousIP',
        ip: log.ip,
        reason: 'private_range',
        timestamp: log.timestamp,
        source: 'suspiciousIPRule'
      };
    }

    return null;
  }

  /**
   * Detect unauthorized access patterns (403/401 to sensitive endpoints).
   */
  function detectUnauthorizedAccess(log) {
    if (!log || !log.event) return null;
    if (!log.timestamp || !(log.timestamp instanceof Date)) return null;

    // Check for failed auth status codes or failed login to sensitive paths
    const hasAuthFailure = /failed login/i.test(log.event) ||
      (log.status && (log.status === 401 || log.status === 403));

    if (!hasAuthFailure) return null;

    // Check if the event or a path field matches sensitive patterns
    const textToCheck = [log.event, log.path, log.raw].filter(Boolean).join(' ');
    for (const pattern of sensitivePatterns) {
      if (pattern.test(textToCheck)) {
        return {
          type: 'UnauthorizedAccess',
          ip: log.ip,
          event: log.event,
          pattern: pattern.source,
          timestamp: log.timestamp,
          source: 'unauthorizedAccessRule'
        };
      }
    }
    return null;
  }

  /**
   * Run all detectors. Returns the first threat found, or null.
   * Priority order: brute force > spike > suspicious IP > unauthorized access
   */
  function detectAll(log) {
    const detectors = [detectBruteForce, detectSpike, detectSuspiciousIP, detectUnauthorizedAccess];
    for (const fn of detectors) {
      const threat = fn(log);
      if (threat) return threat;
    }
    return null;
  }

  return {
    detectAll,
    detectBruteForce,
    detectSpike,
    detectSuspiciousIP,
    detectUnauthorizedAccess,
    threshold: bruteThreshold
  };
}

// Default singleton for CLI usage (backward compat)
const defaultDetector = createDetector();
const detectAll = defaultDetector.detectAll;

module.exports = { detectAll, createDetector };