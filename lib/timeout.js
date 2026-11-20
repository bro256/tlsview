// Resolves with the promise's value, or with undefined if it has not
// settled after ms milliseconds. A rejection before that is passed on.
//   timers: { setTimeout, clearTimeout }, replaceable for tests.
export function orTimeout(promise, ms, timers = globalThis) {
  let timer;
  const timeout = new Promise((resolve) => {
    timer = timers.setTimeout(() => resolve(undefined), ms);
  });
  return Promise.race([promise, timeout]).finally(() => timers.clearTimeout(timer));
}
