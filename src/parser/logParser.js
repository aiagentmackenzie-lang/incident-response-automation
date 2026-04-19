// src/parser/logParser.js
'use strict';

const { parseTextLine } = require('./formats/textParser');
const { parseJsonLine } = require('./formats/jsonParser');

/**
 * @typedef {Object} ParsedLog
 * @property {string} ip
 * @property {string} event
 * @property {Date} timestamp
 * @property {number} [status]
 * @property {string} [user]
 * @property {string} [raw]
 */

/**
 * Build a parser function for the given format
 * @param {string} format - 'text' or 'json'
 * @returns {Function}
 */
function buildParser(format) {
  if (format === 'json') return parseJsonLine;
  return parseTextLine;
}

module.exports = { buildParser };
