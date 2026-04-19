// src/detection/stateStore.js
'use strict';

class TimeWindowCounter {
  constructor(windowMs) {
    this.windowMs = windowMs;
    this.map = new Map();
  }

  add(key, timestamp) {
    const now = timestamp.getTime();
    const arr = this.map.get(key) || [];
    const cutoff = now - this.windowMs;
    const filtered = arr.filter((t) => t >= cutoff);
    filtered.push(now);
    this.map.set(key, filtered);
    return filtered.length;
  }

  reset(key) {
    if (key) {
      this.map.delete(key);
    } else {
      this.map.clear();
    }
  }
}

module.exports = { TimeWindowCounter };