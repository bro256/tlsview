import { test } from "node:test";
import assert from "node:assert/strict";
import { createWriter } from "../lib/writer.js";

// Timers that run only when fire() is called.
function fakeTimers() {
  let next = 1;
  const queue = new Map();
  return {
    setTimeout(fn) { queue.set(next, fn); return next++; },
    clearTimeout(id) { queue.delete(id); },
    async fire() {
      const fns = [...queue.values()];
      queue.clear();
      for (const fn of fns) await fn();
    },
    get size() { return queue.size; },
  };
}

test("many updates of a tab are flushed once", async () => {
  const timers = fakeTimers();
  const flushed = [];
  const w = createWriter(async (id) => flushed.push(id), 200, timers);
  for (let i = 0; i < 50; i++) w.schedule(7);
  assert.equal(timers.size, 1);
  await timers.fire();
  assert.deepEqual(flushed, [7]);
  assert.equal(w.isPending(7), false);
});

test("tabs are flushed separately", async () => {
  const timers = fakeTimers();
  const flushed = [];
  const w = createWriter(async (id) => flushed.push(id), 200, timers);
  w.schedule(1);
  w.schedule(2);
  w.schedule(1);
  await timers.fire();
  assert.deepEqual(flushed.sort(), [1, 2]);
});

test("now flushes at once and replaces the pending timer", async () => {
  const timers = fakeTimers();
  const flushed = [];
  const w = createWriter(async (id) => flushed.push(id), 200, timers);
  w.schedule(3);
  await w.schedule(3, true);
  assert.deepEqual(flushed, [3]);
  assert.equal(timers.size, 0);
});

test("cancel drops a scheduled flush", async () => {
  const timers = fakeTimers();
  const flushed = [];
  const w = createWriter(async (id) => flushed.push(id), 200, timers);
  w.schedule(4);
  w.cancel(4);
  await timers.fire();
  assert.deepEqual(flushed, []);
});

test("a failing flush is logged, not thrown, and later updates still work", async (t) => {
  const timers = fakeTimers();
  t.mock.method(console, "error", () => {});
  let calls = 0;
  const w = createWriter(async () => { calls++; if (calls === 1) throw new Error("x"); }, 200, timers);
  await w.schedule(5, true);
  w.schedule(5);
  await timers.fire();
  assert.equal(calls, 2);
  assert.equal(console.error.mock.callCount(), 1);
});
