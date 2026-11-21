// Root certificates added to this computer.
//
// Public websites chain to a root built into Firefox. A chain that ends in a
// root added locally (by the user, by enterprise policy, or by security
// software) is either a private PKI, e.g. an intranet, or TLS interception,
// e.g. an inspection proxy or antivirus HTTPS scanning. TLSView cannot tell
// these apart; it reports the root's common name and lets the user judge.
//
// Server-side TLS termination (CDNs, load balancers, reverse proxies) uses
// publicly trusted certificates and is not detected: as far as the browser
// can tell, the terminating server is the site.

// Longest common name shown; longer names are cut and end in "...".
export const MAX_NAME = 64;

// Splits a distinguished name as Firefox formats it (nsIX509Cert.subjectName,
// e.g. 'CN=Contoso Root CA,O="Contoso, Ltd",C=LT') into [type, value] pairs.
// Separators inside double quotes or after a backslash do not split.
export function parseDn(dn) {
  const pairs = [];
  let part = "";
  let quoted = false;
  const flush = () => {
    const eq = part.indexOf("=");
    if (eq > 0) pairs.push([part.slice(0, eq).trim().toUpperCase(), unquote(part.slice(eq + 1).trim())]);
    part = "";
  };
  for (let i = 0; i < dn.length; i++) {
    const c = dn[i];
    if (c === "\\" && i + 1 < dn.length) {
      part += c + dn[++i];
    } else if (c === '"') {
      quoted = !quoted;
      part += c;
    } else if ((c === "," || c === "+") && !quoted) {
      flush();
    } else {
      part += c;
    }
  }
  flush();
  return pairs;
}

// Value without surrounding quotes and with backslash escapes resolved.
function unquote(value) {
  const inner = value.length >= 2 && value.startsWith('"') && value.endsWith('"')
    ? value.slice(1, -1)
    : value;
  return inner.replace(/\\(.)/g, "$1");
}

// First common name (CN) in a distinguished name, or null.
export function commonNameOf(dn) {
  if (typeof dn !== "string") return null;
  const cn = parseDn(dn).find(([type]) => type === "CN" || type === "2.5.4.3");
  return cn ? cn[1] : null;
}

// A name as shown: control characters become spaces (they would break the
// tooltip's lines), and long names are cut. Empty names become null.
export function displayName(name) {
  if (typeof name !== "string") return null;
  const clean = name.replace(/[\u0000-\u001f\u007f]/g, " ").trim();
  if (!clean) return null;
  return clean.length > MAX_NAME ? `${clean.slice(0, MAX_NAME - 3)}...` : clean;
}

// { commonName } of the root when the page's certificate chain ends in a
// root added to this computer, otherwise null.
//   info: SecurityInfo from getSecurityInfo() with certificateChain: true.
//         info.certificates is the chain Firefox verified, server
//         certificate first and root last; each has isBuiltInRoot.
// Returns null, not a guess, when the chain is not known:
//   - an overridden certificate error: Firefox reports only the server
//     certificate, without a verified chain;
//   - a list of one certificate: Firefox's fallback when it has no chain.
export function localRootOf(info) {
  if (info.isUntrusted || info.isDomainMismatch || info.isNotValidAtThisTime) return null;
  const chain = info.certificates;
  if (!Array.isArray(chain) || chain.length < 2) return null;
  const root = chain[chain.length - 1];
  if (root?.isBuiltInRoot !== false) return null;
  return { commonName: displayName(commonNameOf(root.subject)) };
}
