"use strict";

// Must match "host_permissions" in manifest.json.
const HOST_PERMISSIONS = { origins: ["*://*/*"] };

// Runs every time Firefox loads this script: on install, on browser start,
// and when an unloaded (idle) background page is woken by an event.
console.log("TLSView: background script loaded");

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
// Fires only while the action has no popup.
browser.action.onClicked.addListener(() => {
  browser.permissions.request(HOST_PERMISSIONS).then((granted) => {
    console.log("TLSView: host permission granted =", granted);
  });
});

// Fires once per response, after the response headers arrive and before
// the body is downloaded. Not fired for requests that fail before a response
// (DNS error, refused connection, failed TLS handshake).
browser.webRequest.onHeadersReceived.addListener(
  (details) => {
    // tabId is -1 for requests not tied to a tab (extensions, updates, ...).
    const tab = details.tabId === -1 ? "no tab" : "tab " + details.tabId;
    console.log(
      `TLSView: [${tab}] ${details.type} ${details.method} ${details.statusCode}`,
      details.fromCache ? "(cache)" : "",
      details.url,
    );
  },
  // Matches http, https, ws and wss URLs.
  { urls: ["*://*/*"] },
);
