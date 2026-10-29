// HTTP Strict Transport Security (HSTS, RFC 6797).
//
// Two sources, both for the page itself:
//   SecurityInfo hsts: whether Firefox already treated the host as HSTS
//     before the request was sent (from its preload list or an earlier
//     header). On a first visit it is false even if the site sends the
//     header, because the header has not been seen yet.
//   Strict-Transport-Security response header: the policy the site sends.
//     Firefox keeps only the first such header (RFC 6797, section 8.1).

const MAX_UINT64 = 2n ** 64n - 1n;

// Value of the Strict-Transport-Security header, or null.
// headers: onHeadersReceived details.responseHeaders ([{ name, value }]).
export function hstsHeaderOf(headers) {
  const header = (headers ?? []).find((h) => h.name.toLowerCase() === "strict-transport-security");
  return header?.value ?? null;
}

// Splits a header value into directives [{ name, value }], value null when
// absent. Returns null if the syntax is invalid. Same grammar as Firefox's
// nsSecurityHeaderParser: token [ "=" ( token / quoted-string ) ], separated
// by ";", with optional spaces and tabs.
function directivesOf(text) {
  const TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]*/;
  const SPACE = /^[ \t]*/;
  const QUOTED = /^"((?:[\t\n\r\x20\x21\x23-\x5b\x5d-\x7e]|\\[\x00-\x7f])*)"/;
  const directives = [];
  let rest = text;
  const skip = (re) => {
    const m = rest.match(re);
    rest = rest.slice(m[0].length);
    return m;
  };
  for (;;) {
    skip(SPACE);
    const name = skip(TOKEN)[0];
    skip(SPACE);
    let value = null;
    if (rest.startsWith("=")) {
      rest = rest.slice(1);
      skip(SPACE);
      const quoted = rest.match(QUOTED);
      if (quoted) {
        value = quoted[1];
        rest = rest.slice(quoted[0].length);
      } else if (rest.startsWith('"')) {
        return null;
      } else {
        value = skip(TOKEN)[0];
      }
      skip(SPACE);
    }
    directives.push({ name: name.toLowerCase(), value });
    if (!rest.startsWith(";")) break;
    rest = rest.slice(1);
  }
  return rest === "" ? directives : null;
}

// Parses a Strict-Transport-Security header value with Firefox's rules
// (nsSiteSecurityService.cpp): directive names are case-insensitive;
// max-age is required and must be a whole number of seconds; a repeated
// max-age or includeSubDomains, or includeSubDomains with a value, makes the
// header invalid; other directives are ignored.
// Returns { maxAge, includeSubDomains, preload }, or null if Firefox would
// ignore the header. "preload" is not part of RFC 6797 and Firefox ignores
// it; sites send it to ask for inclusion in browsers' HSTS preload lists.
export function parseHsts(value) {
  const directives = directivesOf(value);
  if (!directives) return null;
  let maxAge = null;
  let includeSubDomains = false;
  let preload = false;
  for (const { name, value: v } of directives) {
    if (name === "max-age") {
      if (maxAge !== null || v === null || !/^\d+$/.test(v) || BigInt(v) > MAX_UINT64) return null;
      maxAge = Number(v);
    } else if (name === "includesubdomains") {
      if (includeSubDomains || v !== null) return null;
      includeSubDomains = true;
    } else if (name === "preload") {
      preload = true;
    }
  }
  return maxAge === null ? null : { maxAge, includeSubDomains, preload };
}

// Text for the popup's HSTS row.
//   known:  SecurityInfo hsts (true, false, or null if not reported).
//   header: Strict-Transport-Security value, or null.
export function describeHsts(known, header) {
  if (header !== null) {
    const policy = parseHsts(header);
    if (!policy) return "Header sent, but invalid (Firefox ignores it)";
    if (policy.maxAge === 0) return "Header sent: max-age=0 (the site turns HSTS off)";
    const days = Math.floor(policy.maxAge / 86400);
    const parts = [`max-age=${policy.maxAge} (${days} ${days === 1 ? "day" : "days"})`];
    if (policy.includeSubDomains) parts.push("includeSubDomains");
    if (policy.preload) parts.push("preload");
    return "Header sent: " + parts.join("; ");
  }
  if (known === true) return "Known to Firefox; no header in this response";
  if (known === false) return "Not used";
  return "not reported";
}
