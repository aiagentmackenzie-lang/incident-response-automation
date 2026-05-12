// src/utils/logger.js
'use strict';

const path = require('path');
const { createLogger, format, transports } = require('winston');

const LOG_FILE = path.resolve(__dirname, '../../security-events.log');

const securityLogger = createLogger({
  level: 'info',
  format: format.combine(format.timestamp(), format.json()),
  transports: [
    new transports.File({
      filename: LOG_FILE,
      maxsize: 10_485_760, // 10 MB
      maxFiles: 5
    })
  ],
  // Console transport added only when explicitly requested
});

module.exports = { securityLogger };