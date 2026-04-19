// src/index.js
'use strict';

const { buildParser } = require('./parser/logParser');
const { detectAll } = require('./detection/rules');
const { TimeWindowCounter } = require('./detection/stateStore');
const { respondToThreat } = require('./response/actions');
const { classifyIncident } = require('./ai/classifier');
const { reportIncident } = require('./utils/reporter');
const { securityLogger } = require('./utils/logger');

module.exports = {
  // Parser
  buildParser,
  // Detection
  detectAll,
  TimeWindowCounter,
  // Response
  respondToThreat,
  // AI
  classifyIncident,
  // Utils
  reportIncident,
  securityLogger
};
