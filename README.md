# 🚨 Incident Response Automation Tool

An automated incident response and triage system that ingests logs, detects threats, and triggers responses in near real time, designed as a compact SOAR-style platform for modern defensive engineering.

This project is a lightweight Security Orchestration, Automation, and Response (SOAR) engine focused on **log-driven incident response** for small environments, labs, and blue-team portfolios. It connects log sources to a detection engine, optional AI-based classification, and a response layer that can both **simulate** and **execute** real containment actions.

The design emphasizes:

- **Structured logging and normalization** to make logs machine-readable and easy to correlate.
- **Rule-based detection** with clear, auditable logic, plus hooks for more advanced analytics later.
- **AI-assisted triage** as an enrichment layer, never a silent decision maker.
- **Safe automation patterns** with human-in-the-loop for high-risk actions, reflecting SOAR best practices.

***

## 🔎 Executive Overview

This tool demonstrates SOC-style thinking: detection, enrichment, containment, and reporting. It provides a clean, extensible Node.js codebase using structured logs and modular components, supporting both batch analysis (files) and near real-time streaming (tail/watch mode).

## 🎯 Goals and Non-Goals

### Goals

- Demonstrate **SOC-style thinking**: detection, enrichment, containment, and reporting.
- Provide a clean, extensible Node.js codebase using structured logs and modular components.
- Support both **batch analysis** (files) and **near real-time streaming** (tail/watch mode).
- Make AI triage pluggable (OpenRouter / Claude or any HTTP LLM backend).

### Non-Goals

- Not a full SIEM replacement; assumes upstream log collection.
- Not a full enterprise SOAR; focuses on a few high-value playbooks (e.g., brute force, abusive IPs).
- Not a general anomaly detection engine; relies on explicit rules plus optional AI guidance.

## 🧠 Feature Set

- **Log ingestion**
  - File-based (batch processing).
  - Streaming / tail-mode for near real-time.
  - Pluggable parsers (syslog-style, JSON logs, custom text formats).

- **Detection engine**
  - Rule-based correlation and thresholds (e.g., brute force, request spikes).
  - Sliding time-window logic (e.g., N events in T seconds).
  - Stateful tracking per principal (IP, user, API key).

- **Classification layer (AI-assisted, optional)**
  - Severity scoring and confidence.
  - Recommendations for containment.
  - Explanation of reasoning to support analyst review (no silent auto-block without logs).

- **Response engine**
  - Simulated or real IP blocking (e.g., iptables, cloud firewall APIs).
  - Local process kill and session flagging.
  - Webhook notifications (Slack, Teams, custom HTTP endpoint).

- **Reporting & observability**
  - Structured security event log (JSON) for downstream SIEM ingestion.
  - Incident timeline and summary artifacts per case.
  - CLI summaries and machine-readable outputs.

## 🔐 Detection Use Cases

Baseline rules are intentionally opinionated, mapping directly to classic SOC playbooks:

- **Brute-force authentication attempts**
  - Multiple failed logins from same IP or user within a rolling time window.
  - Optional thresholds per environment (lab vs. production).

- **Suspicious IP behavior**
  - Access from known malicious ranges (via threat-intel feed or static list).
  - Geo-anomalies (e.g., impossible travel patterns) when data is available.

- **Request / event spikes**
  - Sudden volume jump per IP, user, or endpoint—candidate DoS/credential stuffing.

- **Unauthorized access patterns**
  - Repeated 403/401 errors to sensitive endpoints.
  - Access attempts to decommissioned APIs or honeypot paths.

Each rule is implemented as a pure function that consumes normalized log events and emits either `null` or a `DetectionEvent` structure.

## 🏗️ High-Level Architecture

```
┌──────────────────────────┐
│        Log Sources       │
│  (files, streams, APIs)  │
└────────────┬─────────────┘
             │ normalized events
             ▼
┌──────────────────────────┐
│       Log Parser         │
│  (format → structured)   │
└────────────┬─────────────┘
             │ events
             ▼
┌──────────────────────────┐
│    Detection Engine      │
│ (rules, thresholds, etc) │
└────────────┬─────────────┘
             │ threats
             ▼
┌──────────────────────────┐
│   Classification Layer   │
│    (AI optional)         │
└────────────┬─────────────┘
             │ enriched incidents
             ▼
┌──────────────────────────┐
│     Response Engine      │
│ (block, kill, notify)    │
└────────────┬─────────────┘
             │ actions + logs
             ▼
┌──────────────────────────┐
│   Reporting & Alerts     │
│ (timeline, reports, CLI) │
└──────────────────────────┘
```

## 📁 Repository Structure

```
incident-response/
├── src/
│   ├── parser/
│   │   ├── logParser.js
│   │   └── formats/
│   │       ├── textParser.js
│   │       └── jsonParser.js
│   ├── detection/
│   │   ├── rules.js
│   │   └── stateStore.js
│   ├── response/
│   │   ├── actions.js
│   │   └── integrations/
│   │       └── firewall.js
│   ├── ai/
│   │   └── classifier.js
│   ├── utils/
│   │   ├── reporter.js
│   │   └── logger.js
│   ├── config/
│   │   └── default.json
│   ├── cli/
│   │   └── index.js
│   └── index.js
├── test/
│   └── detection.test.js
├── logs/
│   └── sample-auth.log
├── package.json
└── README.md
```

## 🛠️ Tech Stack

- **Runtime**: Node.js (LTS)
- **Logging**: Winston for structured JSON security logs
- **CLI**: Node streams + `readline` for efficient file and tail processing
- **Testing**: Jest for unit tests
- **AI integration**: Any HTTP LLM provider (e.g., via OpenRouter) with per-environment API keys

## ⚙️ Installation & Setup

```bash
# Clone the repo
git clone https://github.com/your-org/incident-response.git
cd incident-response

# Install dependencies
npm install

# Copy and edit configuration
cp src/config/default.json src/config/local.json
```

Example `src/config/default.json`:

```json
{
  "logFormat": "text",
  "timeWindowSeconds": 60,
  "bruteForceThreshold": 10,
  "spikeThreshold": 100,
  "ai": {
    "enabled": false,
    "endpoint": "https://openrouter.ai/api/v1/chat/completions",
    "model": "your-model-id",
    "apiKeyEnvVar": "OPENROUTER_API_KEY"
  },
  "response": {
    "simulate": true,
    "webhookUrl": null
  }
}
```

Never hard-code secrets (API keys, webhook URLs); load them via environment variables or a secrets manager.

## 🧪 Example Usage

### Analyze a log file (batch)

```bash
node src/cli/index.js --file logs/auth.log
```

### Near real-time monitoring (tail mode)

```bash
node src/cli/index.js --file logs/auth.log --watch
```

### JSON output (for piping into other tools)

```bash
node src/cli/index.js --file logs/auth.log --json | jq
```

## 🧱 Core Components

### 1. Log Parser

Parses raw log lines into structured events:

```javascript
// Text format: "192.168.1.1 - failed login - 2026-03-29T12:34:56Z"
const { buildParser } = require('./src/parser/logParser');
const parse = buildParser('text');
const event = parse('192.168.1.1 - failed login - 2026-03-29T12:34:56Z');
// → { ip: '192.168.1.1', event: 'failed login', timestamp: Date, raw: '...' }
```

### 2. Detection Engine

Sliding window counter for brute force detection:

```javascript
const { detectAll } = require('./src/detection/rules');

// After 10 failed logins from same IP within 60 seconds
detectAll({ ip: '10.0.0.1', event: 'failed login', timestamp: new Date() });
// → { type: 'BruteForceLogin', ip: '10.0.0.1', count: 10, ... }
```

### 3. Response Actions

Simulated or real blocking:

```javascript
const { respondToThreat } = require('./src/response/actions');

// SIMULATE_RESPONSE=true (default)
await respondToThreat({ type: 'BruteForceLogin', ip: '10.0.0.1' });
// → [SIMULATE] Would block IP: 10.0.0.1
```

### 4. AI Classification (Optional)

Enrich incidents with LLM analysis:

```javascript
const { classifyIncident } = require('./src/ai/classifier');

const classification = await classifyIncident(threat);
// → { enabled: false, severity: 'MEDIUM', 
//     recommendation: 'Review incident manually; AI not configured.' }
```

## 📊 Example Output

```text
[INFO] incident_detected {"type":"BruteForceLogin","ip":"192.168.1.10", ...}

=== INCIDENT DETECTED ===
Type: BruteForceLogin
IP: 192.168.1.10
Count: 25
Severity: MEDIUM
Advice: Multiple failed logins from a single IP within 60 seconds. Block IP and investigate associated accounts.
[SIMULATE] Would block IP: 192.168.1.10
```

## 🔒 Security & Privacy Considerations

- **Least privilege**: If integrating with real firewalls or infrastructure APIs, run this tool with scoped credentials only.
- **Environment separation**: Maintain separate configs for lab, staging, and production.
- **Log hygiene**: Avoid storing full secrets, access tokens, or highly sensitive PII in incident logs.
- **Safe automation**: Start in **simulate** mode, collect evidence, then selectively enable real actions.
- **Auditability**: Every automated action is logged with a timestamp, input threat, and outcome.

## ✅ Testing Strategy

```bash
# Run all tests
npm test

# Run with coverage
npm test -- --coverage
```

Example test:

```javascript
const { detectAll } = require('../src/detection/rules');

function buildLog(ip, event, ts) {
  return { ip, event, timestamp: ts ? new Date(ts) : new Date() };
}

test('detects brute force after threshold', () => {
  const ip = '10.0.0.1';
  let threat = null;
  for (let i = 0; i < 9; i++) {
    threat = detectAll(buildLog(ip, 'failed login'));
    expect(threat).toBeNull();
  }
  threat = detectAll(buildLog(ip, 'failed login'));
  expect(threat).not.toBeNull();
  expect(threat.type).toBe('BruteForceLogin');
});
```

## 🚀 Upgrade Path

Next steps to turn this into a flagship portfolio project:

1. **Real-time multi-source ingestion**
   - Add TCP/UDP listeners for syslog.
   - Add HTTP ingestion endpoints for app logs.
   - Feed into a queue (e.g., Kafka, Redis streams) before detection.

2. **Threat intelligence enrichment**
   - Integrate free or paid IP/domain reputation feeds.

3. **Dashboard & case management**
   - Build a small web UI showing active incidents and timelines.

4. **Additional playbooks**
   - Suspicious admin activity.
   - API key abuse detection.
   - RDP/SSH brute force from network perimeter logs.

5. **Hardening & deployment**
   - Containerize with a minimal base image.
   - Add CI to run tests, SAST, and dependency checks.
   - Provide Kubernetes manifests or Docker Compose.

## 📄 License

MIT

---

## References

1. [Automating Incident Response: Building Effective SOAR Playbooks](https://johnpemberton.dev/blog/automating-incident-response-soar-playbooks)
2. [What Is SOAR? 4 Core Components, Use Cases & Best Practices](https://radiantsecurity.ai/learn/what-is-soar-4-core-components-use-cases-and-critical-best-practices/)
3. [Key SOAR Capabilities - Exabeam](https://www.exabeam.com/explainers/siem-security/incident-response-and-automation/)
4. [NodeJS Security Cheat Sheet](https://pentest.y-security.de/OWASP%20Cheat%20Sheet%20Series/Nodejs_Security_Cheat_Sheet/)
5. [Nodejs Security - OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)
6. [Structured logging - ClickHouse](https://clickhouse.com/resources/engineering/structured-logging)
7. [Structured Logging: Best Practices & JSON Examples - Uptrace](https://uptrace.dev/glossary/structured-logging)
8. [What is structured logging? - Nxlog](https://nxlog.co/whitepapers/structured-logging)
9. [Log Format Standards: JSON, XML, and Key-Value Explained - Last9](https://last9.io/blog/log-format/)
10. [Security Orchestration Automation and Response (SOAR): Full Guide - Cynet](https://www.cynet.com/incident-response/security-orchestration-automation-and-response-soar-a-quick-guide/)
11. [How to Secure Node.js APIs Against Common Vulnerabilities](https://oneuptime.com/blog/post/2026-01-06-nodejs-api-security-owasp-top-10/view)
12. [Cybersecurity Practices for Engineering Teams - LinkedIn](https://www.linkedin.com/top-content/engineering/systems-engineering-cybersecurity-measures/cybersecurity-practices-for-engineering-teams/)
13. [Secure Software Development Best Practices - Hyperproof](https://hyperproof.io/resource/secure-software-development-best-practices/)
14. [OWASP Node.js Best Practices Guide](https://www.nodejs-security.com/blog/owasp-nodejs-best-practices-guide)
