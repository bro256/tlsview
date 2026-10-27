// Per-tab record of the TLS connections a page used.
//
// Stores raw values reported by Firefox, not classifications, so the record
// stays correct if the classification logic changes. Stores origins
// (scheme://host:port) only, never full URLs: paths and query strings can
// contain personal data.
//
// Shape (plain objects only, so it can be saved with storage.session):
// {
//   pageOrigin: "https://example.com" or null if not seen,
//   mainFrame:  profile key of the page's own response, or null,
//   origins: {
//     "https://example.com": {
//       profiles: {
//         "<profile key>": {
//           state, protocolVersion, keaGroupName, signatureSchemeName,
//           cipherSuite,         // as reported; missing values are null
//           count,               // responses with this profile
//           fromCache,           // of which served from the disk cache
//         },
//       },
//     },
//   },
// }

// Origin of a URL, or null if it cannot be parsed.
export function originOf(url) {
  try {
    const origin = new URL(url).origin;
    // URL.origin is the string "null" for schemes without an origin.
    return origin === "null" ? null : origin;
  } catch {
    return null;
  }
}

export function newTabState(pageUrl) {
  return {
    pageOrigin: pageUrl ? originOf(pageUrl) : null,
    mainFrame: null,
    origins: {},
  };
}


// The TLS properties that distinguish one connection setup from another.
// For "insecure" (no TLS), Firefox reports only the state.
export function profileOf(info) {
  return {
    state: info.state ?? null,
    protocolVersion: info.protocolVersion ?? null,
    keaGroupName: info.keaGroupName ?? null,
    signatureSchemeName: info.signatureSchemeName ?? null,
    cipherSuite: info.cipherSuite ?? null,
  };
}

export function profileKey(profile) {
  return [
    profile.state,
    profile.protocolVersion,
    profile.keaGroupName,
    profile.signatureSchemeName,
    profile.cipherSuite,
  ].join("|");
}

// Records one response in the tab state, in place. Returns the state.
//   response: { type, url, fromCache } from onHeadersReceived details.
//   info:     SecurityInfo from getSecurityInfo().
export function recordResponse(state, response, info) {
  const origin = originOf(response.url);
  if (!origin) return state;

  const profile = profileOf(info);
  const key = profileKey(profile);

  const entry = (state.origins[origin] ??= { profiles: {} });
  const stats = (entry.profiles[key] ??= { ...profile, count: 0, fromCache: 0 });
  stats.count += 1;
  if (response.fromCache) stats.fromCache += 1;

  if (response.type === "main_frame") {
    state.pageOrigin = origin;
    state.mainFrame = key;
  }
  return state;
}

