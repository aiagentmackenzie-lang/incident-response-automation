// test/stateStore.test.js
'use strict';

const { TimeWindowCounter } = require('../src/detection/stateStore');

describe('TimeWindowCounter', () => {
  test('adds and counts timestamps', () => {
    const counter = new TimeWindowCounter(60000);
    const now = Date.now();
    expect(counter.add('ip1', new Date(now))).toBe(1);
    expect(counter.add('ip1', new Date(now + 1000))).toBe(2);
    expect(counter.add('ip2', new Date(now))).toBe(1);
  });

  test('expires old entries', () => {
    const counter = new TimeWindowCounter(5000);
    const base = Date.now();
    counter.add('ip1', new Date(base - 10000)); // too old
    expect(counter.add('ip1', new Date(base))).toBe(1); // old filtered out
  });

  test('reset with key removes only that key', () => {
    const counter = new TimeWindowCounter(60000);
    const now = Date.now();
    counter.add('ip1', new Date(now));
    counter.add('ip2', new Date(now));
    counter.reset('ip1');
    expect(counter.add('ip1', new Date(now))).toBe(1);
    expect(counter.add('ip2', new Date(now))).toBe(2); // ip2 untouched
  });

  test('reset without key clears all', () => {
    const counter = new TimeWindowCounter(60000);
    const now = Date.now();
    counter.add('ip1', new Date(now));
    counter.add('ip2', new Date(now));
    counter.reset();
    expect(counter.add('ip1', new Date(now))).toBe(1);
    expect(counter.add('ip2', new Date(now))).toBe(1);
  });

  test('reset with key "0" works (falsy edge case)', () => {
    const counter = new TimeWindowCounter(60000);
    const now = Date.now();
    counter.add('0', new Date(now)); // key '0' is falsy
    counter.reset('0');
    expect(counter.add('0', new Date(now))).toBe(1);
  });

  test('reset with empty string works', () => {
    const counter = new TimeWindowCounter(60000);
    const now = Date.now();
    counter.add('', new Date(now)); // key '' is falsy
    counter.reset('');
    expect(counter.add('', new Date(now))).toBe(1);
  });
});
