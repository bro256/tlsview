"use strict";

// Runs every time Firefox loads this script: on install, on browser start,
// and when an unloaded (idle) background page is woken by an event.
console.log("TLSView: background script loaded");

// Listeners must be registered synchronously at the top level, so Firefox
// can wake the background page for them after it has been unloaded.

browser.runtime.onInstalled.addListener((details) => {
  // details.reason: "install", "update", "browser_update" ...
  console.log("TLSView: onInstalled, reason =", details.reason);
});

// Fires only while the action has no popup.
browser.action.onClicked.addListener((tab) => {
  console.log("TLSView: toolbar button clicked, tab", tab.id, tab.url);
});
