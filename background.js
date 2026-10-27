import { classifyGroup, describeGroup } from "./lib/classify.js";
import { newTabState, recordResponse } from "./lib/tabstate.js";

// Must match "host_permissions" in manifest.json.
const HOST_PERMISSIONS = { origins: ["*://*/*"] };

// Runs every time Firefox loads this script: on install, on browser start,
// and when an unloaded (idle) background page is woken by an event.
console.log("TLSView: background script loaded");

// ---------------------------------------------------------------------------
// Per-tab state
//
// This background script is an event page: Firefox unloads it after a few
// seconds without events, and all variables are lost. The Map below is a
// fast in-memory copy; storage.session holds the durable copy. Session
// storage lives in memory only (never written to disk) and is cleared when
// the browser closes.

const STORAGE_PREFIX = "tab:";
const tabStates = new Map(); // tabId -> state from lib/tabstate.js

// Reloads saved states after a restart of this script, and drops states of
// tabs that no longer exist. Every listener awaits this before using
// tabStates.
const ready = (async () => {
  const saved = await browser.storage.session.get(null);
  const openTabs = new Set((await browser.tabs.query({})).map((t) => t.id));
  const stale = [];
  for (const [key, state] of Object.entries(saved)) {
    if (!key.startsWith(STORAGE_PREFIX)) continue;
    const tabId = Number(key.slice(STORAGE_PREFIX.length));
    if (openTabs.has(tabId)) tabStates.set(tabId, state);
    else stale.push(key);
  }
  if (stale.length) await browser.storage.session.remove(stale);
  console.log(`TLSView: restored ${tabStates.size} tab state(s), dropped ${stale.length}`);
})();

function saveTabState(tabId) {
  const state = tabStates.get(tabId);
  return browser.storage.session.set({ [STORAGE_PREFIX + tabId]: state });
}

// ---------------------------------------------------------------------------
// Listeners must be registered synchronously at the top level, so Firefox
// can wake the background page for them after it has been unloaded.

browser.runtime.onInstalled.addListener((details) => {
  // details.reason: "install", "update", "browser_update" ...
  console.log("TLSView: onInstalled, reason =", details.reason);
});

// In Manifest V3, Firefox treats host permissions as optional: the user can
// withhold or revoke them. Without them, onHeadersReceived never fires.
browser.permissions.contains(HOST_PERMISSIONS).then((granted) => {
  if (!granted) {
    console.warn("TLSView: host permission missing; click the toolbar button to grant it");
  }
});

// permissions.request() needs a user action, such as this click, and must be
// called before any await. If already granted, it resolves without a prompt.
// The click also prints the current tab's state.
// Fires only while the action has no popup.
browser.action.onClicked.addListener((tab) => {
  browser.permissions.request(HOST_PERMISSIONS).then((granted) => {
    console.log("TLSView: host permission granted =", granted);
  });
  ready.then(() => {
    console.log(`TLSView: state of tab ${tab.id}`, tabStates.get(tab.id) ?? "(none)");
  });
});

// Fires once per response, after the response headers arrive and before
// the body is downloaded. Not fired for requests that fail before a response
// (DNS error, refused connection, failed TLS handshake).
//
// getSecurityInfo() works only inside this listener, and only when the
// listener is registered with "blocking". Being async, the listener returns
// a Promise, and Firefox holds the response until that Promise settles.
browser.webRequest.onHeadersReceived.addListener(
  async (details) => {
    let info;
    try {
      info = await browser.webRequest.getSecurityInfo(details.requestId, {});
    } catch (e) {
      console.error("TLSView: getSecurityInfo failed for", details.url, e);
      return;
    }
    if (!info) {
      // Returned when the request is no longer known to Firefox.
      console.warn("TLSView: no security info for", details.url);
      return;
    }

    // Requests not tied to a tab (tabId -1) are not recorded.
    if (details.tabId === -1) return;

    await ready;

    // A main_frame response starts a new page in the tab: start a new state.
    if (details.type === "main_frame" || !tabStates.has(details.tabId)) {
      tabStates.set(details.tabId, newTabState(null));
    }
    recordResponse(tabStates.get(details.tabId), details, info);
    await saveTabState(details.tabId);

    if (details.type === "main_frame") {
      console.log(
        `TLSView: [tab ${details.tabId}] new page`,
        info.state === "insecure"
          ? "insecure (no TLS)"
          : `${info.keaGroupName ?? "?"} [${describeGroup(classifyGroup(info.keaGroupName))}]`,
      );
    }
  },
  // Matches http, https, ws and wss URLs.
  { urls: ["*://*/*"] },
  ["blocking"],
);

// Closed tab: drop its state from memory and storage.
browser.tabs.onRemoved.addListener(async (tabId) => {
  await ready;
  tabStates.delete(tabId);
  await browser.storage.session.remove(STORAGE_PREFIX + tabId);
});
