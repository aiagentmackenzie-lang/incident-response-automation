// src/response/actions.js
'use strict';

const { securityLogger } = require('../utils/logger');

const SIMULATE = process.env.SIMULATE_RESPONSE !== 'false';

function logAction(action, payload) {
  securityLogger.info({
    type: 'response_action',
    action,
    payload
  });
}

async function blockIP(ip, jsonMode) {
  logAction('block_ip', { ip, simulate: SIMULATE });

  if (jsonMode) {
    // JSON mode: no console output, action logged to file only
    return;
  }

  if (SIMULATE) {
    console.log(`  ⛔ [SIMULATE] Would block IP: ${ip}`);
  } else {
    console.log(`  🔴 [ACTION] Blocking IP: ${ip}`);
  }
}

async function respondToThreat(threat, jsonMode = false) {
  if (!threat) return;

  switch (threat.type) {
    case 'BruteForceLogin':
      await blockIP(threat.ip, jsonMode);
      break;
    default:
      logAction('no_playbook', { threat });
      if (!jsonMode) {
        console.log(`  ⚠️  No playbook for threat type: ${threat.type}`);
      }
  }
}

module.exports = { respondToThreat };