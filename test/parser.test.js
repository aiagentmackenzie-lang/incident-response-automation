// test/parser.test.js
'use strict';

const { buildParser } = require('../src/parser/logParser');
const { parseTextLine } = require('../src/parser/formats/textParser');
const { parseJsonLine } = require('../src/parser/formats/jsonParser');

describe('Text Parser', () => {
  test('parses standard format', () => {
    const result = parseTextLine('192.168.1.1 - failed login - 2026-03-29T12:00:00Z');
    expect(result).not.toBeNull();
    expect(result.ip).toBe('192.168.1.1');
    expect(result.event).toBe('failed login');
    expect(result.timestamp).toBeInstanceOf(Date);
  });

  test('handles extra whitespace', () => {
    const result = parseTextLine('  192.168.1.1   -   failed login   -   2026-03-29T12:00:00Z  ');
    expect(result).not.toBeNull();
    expect(result.ip).toBe('192.168.1.1');
    expect(result.event).toBe('failed login');
  });

  test('rejects too few segments', () => {
    expect(parseTextLine('192.168.1.1 - something')).toBeNull();
    expect(parseTextLine('')).toBeNull();
  });

  test('rejects invalid timestamp', () => {
    expect(parseTextLine('192.168.1.1 - failed login - not-a-date')).toBeNull();
  });

  test('preserves raw line', () => {
    const line = '10.0.0.1 - page view - 2026-04-19T08:00:00Z';
    expect(parseTextLine(line).raw).toBe(line);
  });
});

describe('JSON Parser', () => {
  test('parses valid JSON with required fields', () => {
    const result = parseJsonLine('{"ip":"1.2.3.4","event":"failed login","timestamp":"2026-04-19T12:00:00Z"}');
    expect(result).not.toBeNull();
    expect(result.ip).toBe('1.2.3.4');
    expect(result.event).toBe('failed login');
  });

  test('preserves optional fields', () => {
    const result = parseJsonLine('{"ip":"1.2.3.4","event":"test","timestamp":"2026-04-19T12:00:00Z","status":403,"user":"admin"}');
    expect(result.status).toBe(403);
    expect(result.user).toBe('admin');
  });

  test('rejects missing required fields', () => {
    expect(parseJsonLine('{"ip":"1.2.3.4"}')).toBeNull();
    expect(parseJsonLine('{"ip":"1.2.3.4","event":"test"}')).toBeNull();
  });

  test('rejects invalid JSON', () => {
    expect(parseJsonLine('not json')).toBeNull();
  });
});

describe('buildParser', () => {
  test('returns text parser for text format', () => {
    const parse = buildParser('text');
    expect(parse('10.0.0.1 - failed login - 2026-04-19T12:00:00Z')).not.toBeNull();
  });

  test('returns JSON parser for json format', () => {
    const parse = buildParser('json');
    expect(parse('{"ip":"1.2.3.4","event":"test","timestamp":"2026-04-19T12:00:00Z"}')).not.toBeNull();
  });

  test('defaults to text parser', () => {
    const parse = buildParser('unknown');
    expect(parse).toBe(parseTextLine);
  });
});