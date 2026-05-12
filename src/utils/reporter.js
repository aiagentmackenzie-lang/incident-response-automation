// src/utils/reporter.js
'use strict';

const { securityLogger } = require('./logger');

function reportIncident(threat, classification) {
  const payload = {
    type: threat.type,
    ip: threat.ip,
    timestamp: threat.timestamp,
    classification
  };

  securityLogger.info({
    event: 'incident_detected',
    ...payload
  });

  console.log('');
  console.log('╔══════════════════════════════════════╗');
  console.log('║       INCIDENT DETECTED              ║');
  console.log('╠══════════════════════════════════════╣');
  console.log(`║  Type:     ${pad(threat.type, 25)}║`);
  console.log(`║  IP:       ${pad(threat.ip, 25)}║`);
  console.log(`║  Count:    ${pad(String(threat.count ?? 'n/a'), 25)}║`);
  console.log(`║  Time:     ${pad(threat.timestamp?.toISOString?.() ?? 'n/a', 25)}║`);
  if (threat.reason) {
    console.log(`║  Reason:   ${pad(threat.reason, 25)}║`);
  }
  if (threat.pattern) {
    console.log(`║  Pattern:  ${pad(threat.pattern, 25)}║`);
  }
  if (classification) {
    console.log('╠══════════════════════════════════════╣');
    console.log(`║  Severity: ${pad(classification.severity, 25)}║`);
    console.log(`║  Advice:   ${pad(truncate(classification.recommendation, 25), 25)}║`);
  }
  console.log('╚══════════════════════════════════════╝');
}

function reportScanSummary(stats) {
  console.log('');
  console.log('═══════════════════════════════════════');
  console.log('  SCAN COMPLETE');
  console.log('───────────────────────────────────────');
  console.log(`  Lines processed:  ${stats.totalLines}`);
  console.log(`  Lines parsed:     ${stats.parsed}`);
  console.log(`  Lines skipped:    ${stats.rejected}`);
  console.log(`  Incidents:        ${stats.incidents}`);
  if (stats.ipBreakdown && Object.keys(stats.ipBreakdown).length > 0) {
    console.log('───────────────────────────────────────');
    console.log('  Top IPs by failed logins:');
    const sorted = Object.entries(stats.ipBreakdown)
      .sort((a, b) => {
        const aF = typeof a[1] === 'object' ? (a[1].failed || 0) : a[1];
        const bF = typeof b[1] === 'object' ? (b[1].failed || 0) : b[1];
        return bF - aF;
      })
      .slice(0, 10);
    for (const [ip, data] of sorted) {
      const failed = typeof data === 'object' ? (data.failed || 0) : data;
      const other = typeof data === 'object' ? (data.other || 0) : 0;
      const flag = failed >= (stats.threshold || 10) ? ' ALERT' : '';
      const extra = other > 0 ? ` + ${other} other` : '';
      console.log(`    ${ip}: ${failed} failed logins${extra}${flag}`);
    }
  }
  console.log('═══════════════════════════════════════');
}

function pad(str, len) {
  const s = String(str);
  return s.length >= len ? s.slice(0, len) : s + ' '.repeat(len - s.length);
}

function truncate(str, max) {
  const s = String(str);
  return s.length > max ? s.slice(0, max - 2) + '..' : s;
}

module.exports = { reportIncident, reportScanSummary };