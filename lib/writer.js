// Combines frequent updates of a tab into one call of flush(tabId).
//
// A page can produce hundreds of responses in a second. Instead of saving the
// tab's record and setting its icon after each one, schedule() starts a timer
// on the first update and later updates join it, so the tab is flushed at
// most once per delay.
//
//   flush:  async (tabId) => void; errors are logged, not thrown.
//   delay:  milliseconds an update may wait.
//   timers: { setTimeout, clearTimeout }, replaceable for tests.

export function createWriter(flush, delay, timers = globalThis) {
  const pending = new Map(); // tabId -> timer

  async function run(tabId) {
    pending.delete(tabId);
    try {
      await flush(tabId);
    } catch (e) {
      console.error("TLSView: could not update tab", tabId, e);
    }
  }

  return {
    // Flushes the tab within delay ms, or at once if now is true.
    schedule(tabId, now = false) {
      if (now) {
        timers.clearTimeout(pending.get(tabId));
        return run(tabId);
      }
      if (!pending.has(tabId)) {
        pending.set(tabId, timers.setTimeout(() => run(tabId), delay));
      }
      return undefined;
    },

    // Drops a scheduled flush, e.g. when the tab is closed.
    cancel(tabId) {
      timers.clearTimeout(pending.get(tabId));
      pending.delete(tabId);
    },

    isPending(tabId) {
      return pending.has(tabId);
    },
  };
}
