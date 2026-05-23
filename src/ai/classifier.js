// src/ai/classifier.js
'use strict';

const fetch = require('node-fetch');
const path = require('path');
const fs = require('fs');

/**
 * Classification configuration sources (priority: env var > local.json > default.json):
 *   AI_ENABLED     – 'true' to enable
 *   AI_ENDPOINT    – LLM API endpoint
 *   AI_MODEL       – model identifier
 *   AI_API_KEY     – API key (or use apiKeyEnvVar in config to name a different env var)
 *
 *   Config file keys under "ai":
 *     enabled, endpoint, model, apiKeyEnvVar
 */

// Load config (local.json overrides default.json)
let fileConfig = {};
try {
  fileConfig = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../config/local.json'), 'utf8'));
} catch {
  try {
    fileConfig = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../config/default.json'), 'utf8'));
  } catch { /* no config file available */ }
}

function resolveConfig() {
  const ai = fileConfig.ai || {};
  const enabled = process.env.AI_ENABLED === 'true' || ai.enabled === true;
  const endpoint = process.env.AI_ENDPOINT || ai.endpoint || null;
  const model = process.env.AI_MODEL || ai.model || null;
  // If apiKeyEnvVar is set in config, read the key from that env var name; otherwise fall back to AI_API_KEY
  const apiKeyEnvName = ai.apiKeyEnvVar || 'AI_API_KEY';
  const apiKey = process.env[apiKeyEnvName] || process.env.AI_API_KEY || null;
  return { enabled, endpoint, model, apiKey };
}

async function classifyIncident(threat) {
  const { enabled, endpoint, model, apiKey } = resolveConfig();

  if (!enabled || !endpoint || !model || !apiKey) {
    return {
      enabled: false,
      severity: 'MEDIUM',
      recommendation: 'Review incident manually; AI not configured.'
    };
  }

  const body = {
    model,
    messages: [
      {
        role: 'system',
        content:
          'You are a SOC analyst. Classify the severity of this incident and recommend containment steps in under 80 words.'
      },
      {
        role: 'user',
        content: JSON.stringify(threat)
      }
    ]
  };

  const res = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${apiKey}`
    },
    body: JSON.stringify(body),
    timeout: 15000
  }).catch((err) => {
    return {
      ok: false,
      status: 0,
      _error: err.message
    };
  });

  if (!res.ok) {
    const errorDetail = res._error || `HTTP ${res.status}`;
    return {
      enabled: true,
      severity: 'UNKNOWN',
      recommendation: `AI error: ${errorDetail}`
    };
  }

  const data = await res.json();
  const content = data.choices?.[0]?.message?.content || '';

  // Lightweight extraction protocol; in a real deployment, force a JSON schema.
  return {
    enabled: true,
    severity: /high/i.test(content) ? 'HIGH' : 'MEDIUM',
    recommendation: content.trim()
  };
}

module.exports = { classifyIncident };