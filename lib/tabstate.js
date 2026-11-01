// Per-tab record of the TLS setups a page used.
//
// A setup is one combination of TLS version, key exchange group and cipher
// suite. Responses are grouped by setup, with the origins that used it.
//
// Stores raw values reported by Firefox, not classifications, so the record
// stays correct if the classification logic changes.
//
// Privacy: only origins are stored (scheme, host and port), never paths,
// query strings or fragments. TLS is negotiated per origin, so the origin is
// what a setup applies to. The record is kept in storage.session (memory
// only, never written to disk) and deleted when the tab closes.
//
// Shape (plain objects only, so it can be saved with storage.session):
// {
//   format: FORMAT,                    // records in another format are dropped
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
//       origins: { "<origin>": count },  // responses per origin, at most
//                                        // MAX_ITEMS origins
//       unlisted,                      // responses from origins beyond MAX_ITEMS
//     },
//   },
// }

import { hstsHeaderOf } from "./hsts.js";

export const MAX_ITEMS = 100;
export const FORMAT = 2;

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

export function newTabState() {
  return { format: FORMAT, pageOrigin: null, mainFrame: null, setups: {} };
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
    origins: {},
    unlisted: 0,
  });

  entry.count += 1;
  if (response.fromCache) entry.fromCache += 1;
  if (info.signatureSchemeName) {
    entry.signatures[info.signatureSchemeName] = (entry.signatures[info.signatureSchemeName] ?? 0) + 1;
  }
  if (origin in entry.origins || Object.keys(entry.origins).length < MAX_ITEMS) {
    entry.origins[origin] = (entry.origins[origin] ?? 0) + 1;
  } else {
    entry.unlisted += 1;
  }

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
