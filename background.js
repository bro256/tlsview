import { newTabState, recordResponse, originOf, isFromCurrentPage, FORMAT } from "./lib/tabstate.js";
import { summarize } from "./lib/ladder.js";
import { iconFor, NOT_INSPECTABLE, RESTRICTED } from "./lib/icon.js";
import { isRestrictedUrl } from "./lib/restricted.js";
import { createWriter } from "./lib/writer.js";

// Must match "host_permissions" in manifest.json.
const HOST_PERMISSIONS = { origins: ["*://*/*"] };

// ---------------------------------------------------------------------------
// Per-tab state
//
// This background script is an event page: Firefox unloads it after 30
// seconds without events (extensions.background.idle.timeout), and all
// variables are lost. The 200 ms write delay below is far shorter. The Map below is a
// fast in-memory copy; storage.session holds the durable copy. Session
// storage lives in memory only (never written to disk) and is cleared when
// the browser closes.

const STORAGE_PREFIX = "tab:";
const tabStates = new Map(); // tabId -> state from lib/tabstate.js

// Reloads saved states after a restart of this script, and drops states of
// tabs that no longer exist. Every listener awaits this before using
// tabStates. Never rejects: if the saved states cannot be read, TLSView
// starts with none.
const ready = (async () => {
  try {
    const saved = await browser.storage.session.get(null);
    const openTabs = new Set((await browser.tabs.query({})).map((t) => t.id));
    const stale = [];
    for (const [key, state] of Object.entries(saved)) {
      if (!key.startsWith(STORAGE_PREFIX)) continue;
      const tabId = Number(key.slice(STORAGE_PREFIX.length));
      // Records in another format (e.g. from an earlier version) are
      // dropped, not reused.
      if (openTabs.has(tabId) && state?.format === FORMAT) tabStates.set(tabId, state);
      else stale.push(key);
    }
    if (stale.length) await browser.storage.session.remove(stale);
  } catch (e) {
    console.error("TLSView: could not restore saved tab states", e);
  }
})();

// Saves a tab's state and sets its icon. Called through the writer below,
// at most once per WRITE_DELAY_MS per tab. A tab dropped meanwhile is
// skipped, so a late flush cannot bring its record back.
async function flushTab(tabId) {
  const state = tabStates.get(tabId);
  if (!state) return;
  await browser.storage.session.set({ [STORAGE_PREFIX + tabId]: state });
  // Dropped while saving: remove what was just saved.
  if (!tabStates.has(tabId)) {
    await browser.storage.session.remove(STORAGE_PREFIX + tabId);
    return;
  }
  await updateIcon(tabId);
}

// Short enough for the popup and icon to follow a loading page, long
// enough to combine the many responses of one page.
const WRITE_DELAY_MS = 200;
const writer = createWriter(flushTab, WRITE_DELAY_MS);

async function dropTabState(tabId) {
  writer.cancel(tabId);
  tabStates.delete(tabId);
  await browser.storage.session.remove(STORAGE_PREFIX + tabId);
}

// ---------------------------------------------------------------------------
// Toolbar icon and tooltip, per tab. Firefox resets a tab's icon and title
// when the tab navigates, so they are set again with each flush and when the
// page has finished loading.

async function showIcon(tabId, icon) {
  try {
    await Promise.all([
      browser.action.setIcon({ tabId, path: icon.path }),
      browser.action.setTitle({ tabId, title: icon.title }),
    ]);
  } catch {
    // The tab was closed meanwhile.
  }
}

function updateIcon(tabId) {
  const state = tabStates.get(tabId) ?? newTabState();
  return showIcon(tabId, iconFor(summarize(state)));
}

// ---------------------------------------------------------------------------
// Listeners must be registered synchronously at the top level, so Firefox
// can wake the background page for them after it has been unloaded.

// In Manifest V3, Firefox treats host permissions as optional: the user can
// withhold or revoke them. Without them, onHeadersReceived never fires.
browser.permissions.contains(HOST_PERMISSIONS).then((granted) => {
  if (!granted) {
    console.warn("TLSView: host permission missing; open the TLSView popup to grant it");
  }
});

// Records one response in its tab's state. Runs after the response has been
// released, so it does not delay the page.
async function record(details, info) {
  await ready;
  // A main_frame response starts a new page in the tab: start a new state.
  if (details.type === "main_frame" || !tabStates.has(details.tabId)) {
    tabStates.set(details.tabId, newTabState());
  }
  const state = tabStates.get(details.tabId);
  // A late response for the previous page is not part of this one.
  if (!isFromCurrentPage(state, details)) return;
  recordResponse(state, details, info);
  // The page itself is saved at once, so the popup can show it; other
  // responses are combined.
  await writer.schedule(details.tabId, details.type === "main_frame");
}

// Fires once per response, after the response headers arrive and before
// the body is downloaded. Not fired for requests that fail before a response
// (DNS error, refused connection, failed TLS handshake).
//
// getSecurityInfo() works only inside this listener, and only when the
// listener is registered with "blocking". Being async, the listener returns
// a Promise, and Firefox holds the response until that Promise settles, so
// the listener waits for getSecurityInfo() only. It never changes, blocks
// or redirects a request.
browser.webRequest.onHeadersReceived.addListener(
  async (details) => {
    // Requests not tied to a tab (tabId -1) are not recorded.
    if (details.tabId === -1) return;
    let info;
    try {
      info = await browser.webRequest.getSecurityInfo(details.requestId, {});
    } catch (e) {
      console.error("TLSView: getSecurityInfo failed for", originOf(details.url), e);
      return;
    }
    // undefined when the request is no longer known to Firefox.
    if (!info) return;
    // Not awaited: the response does not wait for the record.
    record(details, info).catch((e) => console.error("TLSView: could not record a response", e));
  },
  // Matches http, https, ws and wss URLs.
  { urls: ["*://*/*"] },
  // responseHeaders: for the page's Strict-Transport-Security header.
  ["blocking", "responseHeaders"],
);

// Page finished loading: check that the record belongs to this page, then
// set the icon again (navigation reset it).
//
// tab.url is available only for pages the host permission covers (http,
// https). Without it the page cannot be inspected (about:, file:, ...).
// A record whose page origin differs from the tab's is from an earlier page:
// the current one sent no main_frame response we saw (for example, it was
// restored from the back/forward cache).
browser.tabs.onUpdated.addListener(
  async (tabId, changeInfo, tab) => {
    if (changeInfo.status !== "complete") return;
    await ready;
    const tabOrigin = tab.url ? originOf(tab.url) : null;
    if (!tabOrigin) {
      await dropTabState(tabId);
      await showIcon(tabId, NOT_INSPECTABLE);
      return;
    }
    if (isRestrictedUrl(tab.url)) {
      await dropTabState(tabId);
      await showIcon(tabId, RESTRICTED);
      return;
    }
    const state = tabStates.get(tabId);
    if (state && state.pageOrigin !== tabOrigin) {
      await dropTabState(tabId);
    }
    await updateIcon(tabId);
  },
  { properties: ["status"] },
);

// Closed tab: drop its state from memory and storage.
browser.tabs.onRemoved.addListener(async (tabId) => {
  await ready;
  await dropTabState(tabId);
});
