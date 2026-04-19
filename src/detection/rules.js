// src/detection/rules.js
'use strict';

const { TimeWindowCounter } = require('./stateStore');

const DEFAULT_WINDOW_MS = (process.env.TIME_WINDOW_SECONDS || 60) * 1000;
const DEFAULT_THRESHOLD = Number(process.env.BRUTE_FORCE_THRESHOLD || 10);

/**
 * Create a detection engine with its own state (testable + no cross-contamination)
 * @param {object} [opts]
 * @param {number} [opts.timeWindowMs]
 * @param {number} [opts.bruteForceThreshold]
 * @returns {{ detectAll: function, detectBruteForce: function }}
 */
function createDetector(opts = {}) {
  const windowMs = opts.timeWindowMs || DEFAULT_WINDOW_MS;
  const threshold = opts.bruteForceThreshold || DEFAULT_THRESHOLD;
  const counter = new TimeWindowCounter(windowMs);

  function detectBruteForce(log) {
    if (!log || !log.event) return null;
    if (!/failed login/i.test(log.event)) return null;

    const count = counter.add(log.ip, log.timestamp);
    if (count >= threshold) {
      counter.reset(log.ip); // Alert once, then reset to avoid spam
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

  function detectAll(log) {
    const detectors = [detectBruteForce];
    for (const fn of detectors) {
      const threat = fn(log);
      if (threat) return threat;
    }
    return null;
  }

  return { detectAll, detectBruteForce };
}

// Default singleton for CLI usage (backward compat)
const defaultDetector = createDetector();
const detectAll = defaultDetector.detectAll;

module.exports = { detectAll, createDetector };