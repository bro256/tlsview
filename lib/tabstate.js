// Per-tab record of the TLS setups a page used.
//
// A setup is one combination of TLS version, key exchange group and cipher
// suite. Responses are grouped by setup, with the URLs that used it.
//
// Stores raw values reported by Firefox, not classifications, so the record
// stays correct if the classification logic changes.
//
// Privacy: URLs are stored without query string and fragment, where tokens
// and personal data usually are. The record is kept in storage.session
// (memory only, never written to disk) and deleted when the tab closes.
//
// Shape (plain objects only, so it can be saved with storage.session):
// {
//   pageOrigin: "https://example.com" or null if not seen,
//   mainFrame: {                       // the page itself, or null
//     state, protocolVersion, keaGroupName, cipherSuite, missingTls,
//     signatureSchemeName,
//     hsts, usedEch,                   // SecurityInfo, null if missing
//     hstsHeader,                      // Strict-Transport-Security value or null
//   },
//   setups: {
//     "<setup key>": {
//       state, protocolVersion, keaGroupName, cipherSuite,
//                                      // as reported; missing values are null
//       missingTls,                    // see setupOf()
//       count,                         // responses with this setup
//       fromCache,                     // of which served from the disk cache
//       signatures: { "<signatureSchemeName>": count },
//       origins: [...],  originsTruncated,   // distinct origins
//       urls: [...],     urlsTruncated,      // distinct origin + path
//     },
//   },
// }
// A *Truncated flag is true once an item was not stored because the list
// reached MAX_ITEMS.

import { hstsHeaderOf } from "./hsts.js";

export const MAX_ITEMS = 100;

function parse(url) {
  try {
    const u = new URL(url);
    // URL.origin is the string "null" for schemes without an origin.
    return u.origin === "null" ? null : u;
  } catch {
    return null;
  }
}

// Origin of a URL (scheme://host:port), or null.
export function originOf(url) {
  return parse(url)?.origin ?? null;
}

// Origin and path of a URL, without query string and fragment, or null.
export function urlWithoutQuery(url) {
  const u = parse(url);
  return u ? u.origin + u.pathname : null;
}

export function newTabState() {
  return { pageOrigin: null, mainFrame: null, setups: {} };
}

// The values that define a setup. For "insecure" (no TLS), Firefox reports
// only the state, so the other values are null.
//
// Firefox also reports "insecure" for some https responses, e.g. a request
// aborted before the connection was validated. missingTls marks those: an
// https or wss URL with state "insecure". They are not plain HTTP.
export function setupOf(info, url) {
  const state = info.state ?? null;
  return {
    state,
    protocolVersion: info.protocolVersion ?? null,
    keaGroupName: info.keaGroupName ?? null,
    cipherSuite: info.cipherSuite ?? null,
    missingTls: state === "insecure" && /^(https|wss):/i.test(url ?? ""),
  };
}

export function setupKey(setup) {
  return [setup.state, setup.protocolVersion, setup.keaGroupName, setup.cipherSuite,
    setup.missingTls ? "missing-tls" : ""].join("|");
}

// Adds item to list unless present; returns whether the list was full.
function addCapped(list, item) {
  if (list.includes(item)) return false;
  if (list.length >= MAX_ITEMS) return true;
  list.push(item);
  return false;
}

// Origin of the top-level document a request was made for, or null if not
// known. Uses onHeadersReceived details:
//   frameAncestors: frames from the immediate parent up to the top-level
//                   document; empty for requests made by the top-level one.
//   documentUrl:    the document the request was made from.
export function topDocumentOrigin(details) {
  const ancestors = details.frameAncestors;
  const url = ancestors && ancestors.length
    ? ancestors[ancestors.length - 1].url
    : details.documentUrl;
  return url ? originOf(url) : null;
}

// False for a response made for a different top-level page than the one
// recorded: for example, a slow response from the previous page arriving
// after the new page started. A main_frame response always starts a page.
// Responses from the same origin cannot be told apart this way and count.
export function isFromCurrentPage(state, details) {
  if (details.type === "main_frame" || !state.pageOrigin) return true;
  const top = topDocumentOrigin(details);
  return top === null || top === state.pageOrigin;
}

// Records one response in the tab state, in place. Returns the state.
//   response: { type, url, fromCache, responseHeaders } from onHeadersReceived details.
//   info:     SecurityInfo from getSecurityInfo().
export function recordResponse(state, response, info) {
  const origin = originOf(response.url);
  if (!origin) return state;

  const setup = setupOf(info, response.url);
  const entry = (state.setups[setupKey(setup)] ??= {
    ...setup,
    count: 0,
    fromCache: 0,
    signatures: {},
    origins: [],
    originsTruncated: false,
    urls: [],
    urlsTruncated: false,
  });

  entry.count += 1;
  if (response.fromCache) entry.fromCache += 1;
  if (info.signatureSchemeName) {
    entry.signatures[info.signatureSchemeName] = (entry.signatures[info.signatureSchemeName] ?? 0) + 1;
  }
  if (addCapped(entry.origins, origin)) entry.originsTruncated = true;
  if (addCapped(entry.urls, urlWithoutQuery(response.url))) entry.urlsTruncated = true;

  if (response.type === "main_frame") {
    state.pageOrigin = origin;
    state.mainFrame = {
      ...setup,
      signatureSchemeName: info.signatureSchemeName ?? null,
      hsts: info.hsts ?? null,
      usedEch: info.usedEch ?? null,
      hstsHeader: hstsHeaderOf(response.responseHeaders),
    };
  }
  return state;
}
