import { classifyGroup, describeGroup } from "./lib/classify.js";

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
//
// getSecurityInfo() works only inside this listener, and only when the
// listener is registered with "blocking". Being async, the listener returns
// a Promise, and Firefox holds the response until that Promise settles.
browser.webRequest.onHeadersReceived.addListener(
  async (details) => {
    // tabId is -1 for requests not tied to a tab (extensions, updates, ...).
    const tab = details.tabId === -1 ? "no tab" : "tab " + details.tabId;

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

    // state: "secure", "weak", "broken" or "insecure" (no TLS).
    // For "insecure", the object contains only the state.
    const summary =
      info.state === "insecure"
        ? "insecure (no TLS)"
        : [
            info.state,
            info.protocolVersion,
            "group=" + (info.keaGroupName ?? "?"),
            "[" + describeGroup(classifyGroup(info.keaGroupName)) + "]",
            "sig=" + (info.signatureSchemeName ?? "?"),
          ].join(" ");

    console.log(
      `TLSView: [${tab}] ${details.type} ${summary}`,
      details.fromCache ? "(cache)" : "",
      details.url,
    );

    // The full object for the page itself, to explore every field.
    if (details.type === "main_frame") {
      console.log("TLSView: full securityInfo for", details.url, info);
    }
  },
  // Matches http, https, ws and wss URLs.
  { urls: ["*://*/*"] },
  ["blocking"],
);
