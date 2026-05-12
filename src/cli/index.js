// src/cli/index.js
'use strict';

const fs = require('fs');
const readline = require('readline');
const path = require('path');

const { buildParser } = require('../parser/logParser');
const { createDetector } = require('../detection/rules');
const { respondToThreat } = require('../response/actions');
const { reportIncident, reportScanSummary } = require('../utils/reporter');
const { classifyIncident } = require('../ai/classifier');

// Load config — local.json overrides default.json, with env vars as final overrides
let config = {};
try {
  try {
    config = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../config/local.json'), 'utf8'));
  } catch {
    config = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../config/default.json'), 'utf8'));
  }
} catch (err) {
  console.warn(`[WARN] Failed to load config, using defaults: ${err.message}`);
}

async function processLine(line, parse, detector, jsonMode, stats) {
  const log = parse(line);
  if (!log) {
    stats.rejected++;
    return null;
  }

  stats.parsed++;
  stats.ipBreakdown[log.ip] = stats.ipBreakdown[log.ip] || { failed: 0, other: 0 };
  if (/failed login/i.test(log.event)) {
    stats.ipBreakdown[log.ip].failed++;
  } else {
    stats.ipBreakdown[log.ip].other++;
  }

  const threat = detector.detectAll(log);
  if (!threat) return null;

  stats.incidents++;
  const classification = await classifyIncident(threat);

  if (jsonMode) {
    console.log(JSON.stringify({ threat, classification }));
  } else {
    reportIncident(threat, classification);
  }

  await respondToThreat(threat, jsonMode);
  return threat;
}

async function processFile(file, parse, detector, jsonMode, stats) {
  const stream = fs.createReadStream(file, { encoding: 'utf8' });
  const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });

  for await (const line of rl) {
    if (line.trim().length === 0) continue;
    stats.totalLines++;
    await processLine(line, parse, detector, jsonMode, stats).catch((err) => {
      console.error('Error processing line:', err.message);
    });
  }

  return stats.incidents;
}

function watchFile(file, parse, detector, jsonMode, stats) {
  let offset = 0;

  try {
    const stat = fs.statSync(file);
    offset = stat.size;
  } catch { /* file may not exist yet */ }

  if (!jsonMode) console.log(`[WATCH] Tailing ${file} from byte ${offset}... Press Ctrl+C to stop.`);

  const watcher = fs.watch(file, (eventType) => {
    if (eventType !== 'change') return;

    fs.stat(file, (err, stat) => {
      if (err) return;
      if (stat.size < offset) offset = 0;

      const tailStream = fs.createReadStream(file, { encoding: 'utf8', start: offset });
      let data = '';
      tailStream.on('data', (chunk) => { data += chunk; });
      tailStream.on('end', () => {
        offset = stat.size;
        const lines = data.split('\n');
        for (const line of lines) {
          if (line.trim().length === 0) continue;
          stats.totalLines++;
          processLine(line, parse, detector, jsonMode, stats).catch((err) => {
            console.error('Error processing tailed line:', err.message);
          });
        }
      });
    });
  });

  const cleanup = () => {
    watcher.close();
    if (!jsonMode) reportScanSummary({ ...stats, threshold: detector.threshold });
    process.exit(0);
  };
  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);
}

async function main() {
  const args = require('minimist')(process.argv.slice(2));
  const file = args.file || args._[0];
  const watch = Boolean(args.watch || args.w);
  const jsonMode = Boolean(args.json || args.j);

  if (!file) {
    console.error('Usage: node src/cli/index.js --file <logfile> [--watch] [--json]');
    console.error('  --file, -f   Log file to analyze');
    console.error('  --watch, -w  Tail mode: monitor file for new entries');
    console.error('  --json, -j   Output incidents as JSON (for piping)');
    process.exit(1);
  }

  if (!fs.existsSync(file)) {
    console.error(`Error: File not found: ${file}`);
    process.exit(1);
  }

  const format = process.env.LOG_FORMAT || config.logFormat || 'text';
  const parse = buildParser(format);
  const bruteForceThreshold = parseInt(config.bruteForceThreshold, 10) || 10;
  const spikeThreshold = parseInt(config.spikeThreshold, 10) || 100;
  const timeWindowSeconds = parseInt(config.timeWindowSeconds, 10) || 60;

  const detector = createDetector({
    timeWindowMs: timeWindowSeconds * 1000,
    bruteForceThreshold,
    spikeThreshold
  });

  const stats = {
    totalLines: 0,
    parsed: 0,
    rejected: 0,
    incidents: 0,
    ipBreakdown: {}
  };

  if (!jsonMode) {
    console.log(`═══════════════════════════════════════`);
    console.log(`  INCIDENT RESPONSE AUTOMATION TOOL`);
    console.log(`  File: ${file}`);
    console.log(`  Format: ${format} | Threshold: ${bruteForceThreshold} | Window: ${timeWindowSeconds}s`);
    console.log(`═══════════════════════════════════════`);
  }

  if (watch) {
    await processFile(file, parse, detector, jsonMode, stats);
    watchFile(file, parse, detector, jsonMode, stats);
  } else {
    await processFile(file, parse, detector, jsonMode, stats);
    if (jsonMode) {
      console.log(JSON.stringify({ summary: true, incidents: stats.incidents, parsed: stats.parsed, rejected: stats.rejected }));
    } else {
      reportScanSummary({ ...stats, threshold: bruteForceThreshold });
    }
  }
}

if (require.main === module) {
  main().catch((err) => {
    console.error('Fatal error', err);
    process.exit(1);
  });
}