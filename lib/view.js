import { summarize, setupTitle, warningLines } from "./ladder.js";
import { originOf } from "./tabstate.js";
import { stepIconPath } from "./icon.js";
import { isRestrictedUrl } from "./restricted.js";
import { describeHsts } from "./hsts.js";
import { isRsaKeyTransport, forwardSecrecy, recordProtection, signatureKind, signatureIanaName } from "./classify.js";

// Everything the popup shows for one tab, as plain data. The popup only
// renders it, so all wording and decisions are here and unit-tested.
//
// buildView(state, tabUrl) returns one of:
//   { status: "not-inspectable", message, hint }
//   { status: "restricted", origin, message, hint }
//   { status: "not-seen", origin, message, hint }
//   { status: "ok", origin, page, warnings, setups, responses }
// page: { level, icon, headline, sections: [{ title, rows: [[term, value]] }] }
//   level: the page's step id (lib/ladder.js), used for the headline colour.
//
// Icon paths are relative to the extension root.

const PROTOCOL = {
  "TLSv1": "TLS 1.0",
  "TLSv1.1": "TLS 1.1",
  "TLSv1.2": "TLS 1.2",
  "TLSv1.3": "TLS 1.3",
};

export function protocolLabel(version) {
  if (!version) return "not reported";
  return PROTOCOL[version] ?? version;
}

// IANA reference as shown to users: brackets removed, and an approved
// Internet-Draft waiting for its RFC number ("RFC-ietf-tls-mlkem-10") shown
// as the draft it is, so it is not mistaken for a published RFC.
//   "[RFC 9846]; [RFC 8422]"   -> "RFC 9846; RFC 8422"
//   "[RFC-ietf-tls-mlkem-10]"  -> "draft-ietf-tls-mlkem (approved, not yet an RFC)"
export function referenceLabel(reference) {
  return reference
    .split(";")
    .map((part) => part.trim().replace(/^\[|\]$/g, ""))
    .map((ref) => {
      const pending = ref.match(/^RFC-(.+)-\d+$/);
      return pending ? `draft-${pending[1]} (approved, not yet an RFC)` : ref;
    })
    .join("; ");
}

// Key exchange as the IANA name, with Firefox's name when it differs, or
// the reported name alone when the registry does not know it.
function keyExchangeLabel(main) {
  if (isRsaKeyTransport(main)) return "RSA key transport";
  if (!main.keaGroupName) return "not reported";
  const iana = main.group.name;
  if (!iana) return main.keaGroupName;
  return iana === main.keaGroupName ? iana : `${iana} (Firefox: ${main.keaGroupName})`;
}

// One line describing the key exchange, or null when there is nothing known
// to describe. Wording follows RFC 9794.
export function keyExchangeType(group, protocolVersion) {
  const ref = group.reference ? ", " + referenceLabel(group.reference) : "";
  switch (group.mode) {
    case "hybrid":
      if (group.status === "obsolete") {
        const alg = group.pq.alg.replace(" (round 3)", " round 3");
        return `Obsolete pre-standard hybrid (${group.classical} + ${alg}); not supported by current Firefox`;
      }
      return `PQ/T hybrid: ${group.classical} (traditional) + ${group.pq.alg} (post-quantum)${ref}`;
    case "pq":
      return `Post-quantum: ${group.pq.alg}${ref}`;
    case "classical":
      // Firefox's "custom" (TLS 1.2 DHE with a custom prime) has only a description.
      return group.classical
        ? `Traditional: ${group.classical}${ref}`
        : `Traditional: ${group.description[0].toLowerCase()}${group.description.slice(1)}`;
    case "none":
      // RSA key transport exists only before TLS 1.3.
      return protocolVersion === "TLSv1.3"
        ? "No key exchange group reported"
        : "No key exchange group reported (for example, RSA key transport)";
    default:
      return null;
  }
}

// Headline of the page section, one per step.
export function headline(main) {
  switch (main.step) {
    case "insecure":
      return "No HTTPS: loaded over plain HTTP, without TLS";
    case "tls-legacy":
      return `${protocolLabel(main.protocolVersion)} · deprecated protocol`;
    case "tls12":
      return "TLS 1.2 · traditional key exchange (not post-quantum)";
    case "tls13-classical":
      return "TLS 1.3 · traditional key exchange (not post-quantum)";
    case "tls13-pq":
      return "TLS 1.3 · pure post-quantum key exchange";
    case "tls13-hybrid":
      return "TLS 1.3 · hybrid post-quantum key exchange";
    default:
      return "Key exchange not determined";
  }
}

// true -> "Used", false -> "Not used", missing -> "not reported".
// For ECH, true means the server accepted it (Firefox: isAcceptedEch).
function usedLabel(value) {
  if (value === true) return "Used";
  if (value === false) return "Not used";
  return "not reported";
}

// Handshake signature scheme as the IANA name, with Firefox's name, e.g.
// "ecdsa_secp256r1_sha256 (Firefox: ECDSA-P256-SHA256)", or the reported
// name alone when it has no IANA name.
function signatureLabel(name) {
  if (!name) return "not reported";
  const iana = signatureIanaName(name);
  return iana ? `${iana} (Firefox: ${name})` : name;
}

// Kind of the handshake signature, or null when not recognised.
function signatureType(name) {
  switch (signatureKind(name)) {
    case "traditional": return "Traditional";
    case "post-quantum": return "Post-quantum: ML-DSA, FIPS 204";
    default: return null;
  }
}

// true -> "Yes", false -> "No", null -> "not determined".
function yesNo(value) {
  if (value === true) return "Yes";
  if (value === false) return "No";
  return "not determined";
}

// The page's details in sections: the connection, the key exchange (what
// TLSView rates), authentication (the handshake signature), and extensions
// and headers (ECH, a TLS extension; HSTS, an HTTP header).
function pageView(main) {
  const view = {
    level: main.step,
    icon: stepIconPath(main.step, main.protocolVersion),
    headline: headline(main),
    sections: [],
  };
  if (main.step === "insecure") return view;

  const protection = recordProtection(main.cipherSuite);
  view.sections.push({ title: "Connection", rows: [
    ["Protocol", protocolLabel(main.protocolVersion)],
    ["Cipher suite", main.cipherSuite ?? "not reported"],
    ["Encryption", protection?.cipher ?? "not determined"],
    ["AEAD", yesNo(protection ? protection.aead : null)],
  ] });

  const keyExchange = [["Key exchange", keyExchangeLabel(main)]];
  if (!isRsaKeyTransport(main)) {
    const type = keyExchangeType(main.group, main.protocolVersion);
    if (type) keyExchange.push(["Type", type]);
  }
  keyExchange.push(["Forward secrecy", yesNo(forwardSecrecy(main))]);
  view.sections.push({ title: "Key exchange", rows: keyExchange });

  const authentication = [["Signature scheme", signatureLabel(main.signatureSchemeName)]];
  const signature = signatureType(main.signatureSchemeName);
  if (signature) authentication.push(["Type", signature]);
  view.sections.push({ title: "Authentication", rows: authentication });

  view.sections.push({ title: "Extensions and headers", rows: [
    ["ECH", usedLabel(main.usedEch)],
    ["HSTS", describeHsts(main.hsts ?? null, main.hstsHeader ?? null)],
  ] });
  return view;
}

function setupView(s) {
  return {
    icon: stepIconPath(s.step, s.protocolVersion),
    title: setupTitle(s),
    cipherSuite: s.cipherSuite,
    count: s.count,
    fromCache: s.fromCache,
    origins: s.origins.length,
    originsTruncated: s.originsTruncated,
    urls: s.urls,
    urlsTruncated: s.urlsTruncated,
  };
}

export function buildView(state, tabUrl) {
  const tabOrigin = tabUrl ? originOf(tabUrl) : null;
  if (!tabOrigin) {
    return {
      status: "not-inspectable",
      message: "This page cannot be inspected.",
      hint: "TLSView checks http and https pages only.",
    };
  }
  if (isRestrictedUrl(tabUrl)) {
    return {
      status: "restricted",
      origin: tabOrigin,
      message: "Firefox does not let extensions inspect this site.",
      hint: "Firefox protects some Mozilla sites, such as addons.mozilla.org, from all extensions.",
    };
  }
  // No record, or a record of an earlier page (see the origin check in
  // background.js): nothing to show for this page.
  if (!state || !state.mainFrame || state.pageOrigin !== tabOrigin) {
    return {
      status: "not-seen",
      origin: tabOrigin,
      message: "The page itself was not seen.",
      hint: "Reload the page to check it.",
    };
  }

  const summary = summarize(state);
  return {
    status: "ok",
    origin: state.pageOrigin,
    page: pageView(summary.main),
    warnings: warningLines(summary).map((line) => line.replace(/^Warning: /, "")),
    setups: summary.setups.map(setupView),
    responses: summary.responses,
  };
}

// "1 response", "3 responses"
export function plural(n, word) {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}
