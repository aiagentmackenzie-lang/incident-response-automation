// src/parser/formats/jsonParser.js
'use strict';

/**
 * Parse a JSON log line
 * @param {string} line
 * @returns {Object|null}
 */
function parseJsonLine(line) {
  try {
    const obj = JSON.parse(line);
    if (!obj.timestamp || !obj.ip || !obj.event) return null;
    return {
      ip: obj.ip,
      event: obj.event,
      timestamp: new Date(obj.timestamp),
      status: obj.status,
      user: obj.user,
      raw: line
    };
  } catch {
    return null;
  }
}

module.exports = { parseJsonLine };
