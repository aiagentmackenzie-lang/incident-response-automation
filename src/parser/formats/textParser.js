// src/parser/formats/textParser.js
'use strict';

/**
 * Parse a text log line
 * Format: "192.168.1.1 - failed login - 2026-03-29T12:34:56Z"
 * @param {string} line
 * @returns {Object|null}
 */
function parseTextLine(line) {
  const parts = line.split(' - ');
  if (parts.length < 3) {
    return null;
  }

  const [ip, event, ts] = parts;
  const timestamp = new Date(ts.trim());
  if (Number.isNaN(timestamp.getTime())) return null;

  return {
    ip: ip.trim(),
    event: event.trim(),
    timestamp,
    raw: line
  };
}

module.exports = { parseTextLine };
