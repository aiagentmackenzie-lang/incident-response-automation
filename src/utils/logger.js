// src/utils/logger.js
'use strict';

const path = require('path');
const { createLogger, format, transports } = require('winston');

const LOG_FILE = path.resolve(__dirname, '../../security-events.log');

const securityLogger = createLogger({
  level: 'info',
  format: format.combine(format.timestamp(), format.json()),
  transports: [
    new transports.File({ filename: LOG_FILE })
  ],
  // Console transport added only when explicitly requested
});

module.exports = { securityLogger };