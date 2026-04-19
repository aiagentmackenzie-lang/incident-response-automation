// src/ai/classifier.js
'use strict';

const fetch = require('node-fetch');

const AI_ENABLED = process.env.AI_ENABLED === 'true';
const AI_ENDPOINT = process.env.AI_ENDPOINT;
const AI_MODEL = process.env.AI_MODEL;
const AI_API_KEY = process.env.AI_API_KEY;

async function classifyIncident(threat) {
  if (!AI_ENABLED || !AI_ENDPOINT || !AI_MODEL || !AI_API_KEY) {
    return {
      enabled: false,
      severity: 'MEDIUM',
      recommendation: 'Review incident manually; AI not configured.'
    };
  }

  const body = {
    model: AI_MODEL,
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

  const res = await fetch(AI_ENDPOINT, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${AI_API_KEY}`
    },
    body: JSON.stringify(body)
  });

  if (!res.ok) {
    return {
      enabled: true,
      severity: 'UNKNOWN',
      recommendation: `AI error: ${res.status}`
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
