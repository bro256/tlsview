import { classifyGroup, describeGroup } from "./lib/classify.js";
import { newTabState, recordResponse, originOf, isFromCurrentPage } from "./lib/tabstate.js";
import { summarize } from "./lib/ladder.js";
import { iconFor, NOT_INSPECTABLE, RESTRICTED } from "./lib/icon.js";
import { isRestrictedUrl } from "./lib/restricted.js";

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
    // Records in an older shape (no setups) are dropped, not reused.
    if (openTabs.has(tabId) && state?.setups) tabStates.set(tabId, state);
    else stale.push(key);
  }
  if (stale.length) await browser.storage.session.remove(stale);
  console.log(`TLSView: restored ${tabStates.size} tab state(s), dropped ${stale.length}`);
})();

function saveTabState(tabId) {
  const state = tabStates.get(tabId);
  return browser.storage.session.set({ [STORAGE_PREFIX + tabId]: state });
}

async function dropTabState(tabId) {
  tabStates.delete(tabId);
  await browser.storage.session.remove(STORAGE_PREFIX + tabId);
}

// ---------------------------------------------------------------------------
// Toolbar icon and tooltip, per tab. Firefox resets a tab's icon and title
// when the tab navigates, so they are set again after each response and when
// the page has finished loading.

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

browser.runtime.onInstalled.addListener((details) => {
  // details.reason: "install", "update", "browser_update" ...
  console.log("TLSView: onInstalled, reason =", details.reason);
});

// In Manifest V3, Firefox treats host permissions as optional: the user can
// withhold or revoke them. Without them, onHeadersReceived never fires.
browser.permissions.contains(HOST_PERMISSIONS).then((granted) => {
  if (!granted) {
    console.warn("TLSView: host permission missing; open the TLSView popup to grant it");
  }
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
      tabStates.set(details.tabId, newTabState());
    }
    const state = tabStates.get(details.tabId);
    // A late response for the previous page is not part of this one.
    if (!isFromCurrentPage(state, details)) return;
    recordResponse(state, details, info);
    await saveTabState(details.tabId);
    // Not awaited: the response does not need to wait for the icon.
    updateIcon(details.tabId);

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
