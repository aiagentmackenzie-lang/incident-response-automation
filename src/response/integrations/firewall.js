// src/response/integrations/firewall.js
'use strict';

/**
 * Firewall integration stub
 * Real implementation would use iptables, cloud provider APIs, or WAF rules
 */

async function blockIP(ip) {
  // Stub for firewall integration
  throw new Error('Real firewall integration not implemented');
}

async function unblockIP(ip) {
  // Stub for firewall integration
  throw new Error('Real firewall integration not implemented');
}

module.exports = { blockIP, unblockIP };
