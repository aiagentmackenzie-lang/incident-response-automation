// src/response/actions.js
'use strict';

const { securityLogger } = require('../utils/logger');
const firewall = require('./integrations/firewall');
const path = require('path');
const fs = require('fs');

// Load config (local.json overrides default.json)
let responseConfig = { simulate: true };
try {
  const fileConfig = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../config/local.json'), 'utf8'));
  if (fileConfig.response) responseConfig = fileConfig.response;
} catch {
  try {
    const fileConfig = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../config/default.json'), 'utf8'));
    if (fileConfig.response) responseConfig = fileConfig.response;
  } catch { /* no config file available */ }
}

function isSimulate() {
  // env var overrides config file
  if (process.env.SIMULATE_RESPONSE === 'false') return false;
  if (process.env.SIMULATE_RESPONSE === 'true') return true;
  return responseConfig.simulate !== false;
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

  if (!simulate) {
    try {
      await firewall.blockIP(ip);
    } catch (err) {
      securityLogger.error({ action: 'block_ip_failed', ip, error: err.message });
    }
  }

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