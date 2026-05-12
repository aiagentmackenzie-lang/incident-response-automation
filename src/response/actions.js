// src/response/actions.js
'use strict';

const { securityLogger } = require('../utils/logger');

function isSimulate() {
  return process.env.SIMULATE_RESPONSE !== 'false';
}

function logAction(action, payload) {
  securityLogger.info({
    type: 'response_action',
    action,
    payload
  });
}

async function blockIP(ip, jsonMode) {
  const simulate = isSimulate();
  logAction('block_ip', { ip, simulate });

  if (jsonMode) {
    // JSON mode: no console output, action logged to file only
    return;
  }

  if (simulate) {
    console.log(`  ⛔ [SIMULATE] Would block IP: ${ip}`);
  } else {
    console.log(`  🔴 [ACTION] Blocking IP: ${ip}`);
  }
}

async function respondToThreat(threat, jsonMode = false) {
  if (!threat) return;

  switch (threat.type) {
    case 'BruteForceLogin':
    case 'SuspiciousIP':
    case 'EventSpike':
      await blockIP(threat.ip, jsonMode);
      break;
    case 'UnauthorizedAccess':
      await blockIP(threat.ip, jsonMode);
      logAction('unauthorized_access_alert', { ip: threat.ip, pattern: threat.pattern, event: threat.event });
      break;
    default:
      logAction('no_playbook', { threat });
      if (!jsonMode) {
        console.log(`  ⚠️  No playbook for threat type: ${threat.type}`);
      }
  }
}

module.exports = { respondToThreat };