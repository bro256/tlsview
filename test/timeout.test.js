import { test } from "node:test";
import assert from "node:assert/strict";
import { orTimeout } from "../lib/timeout.js";

test("passes on a value that arrives in time", async () => {
  assert.equal(await orTimeout(Promise.resolve("info"), 1000), "info");
});

test("passes on a rejection that arrives in time", async () => {
  await assert.rejects(orTimeout(Promise.reject(new Error("failed")), 1000), /failed/);
});

test("resolves with undefined when the promise never settles", async () => {
  assert.equal(await orTimeout(new Promise(() => {}), 5), undefined);
});

test("clears its timer once the promise settles", async () => {
  const cleared = [];
  const timers = { setTimeout: () => 42, clearTimeout: (t) => cleared.push(t) };
  await orTimeout(Promise.resolve(1), 1000, timers);
  assert.deepEqual(cleared, [42]);
});
