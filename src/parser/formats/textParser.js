// src/parser/formats/textParser.js
'use strict';

/**
 * Parse a text log line.
 * Format: "192.168.1.1 - failed login - 2026-03-29T12:34:56Z"
 * Supports events containing " - " by joining middle segments.
 * @param {string} line
 * @returns {Object|null}
 */
function parseTextLine(line) {
  const parts = line.split(' - ');
  if (parts.length < 3) {
    return null;
  }

  const ip = parts[0].trim();
  const ts = parts[parts.length - 1].trim();
  const event = parts.slice(1, -1).join(' - ').trim();

  const timestamp = new Date(ts);
  if (Number.isNaN(timestamp.getTime())) return null;

  return {
    ip,
    event,
    timestamp,
    raw: line
  };
}

module.exports = { parseTextLine };