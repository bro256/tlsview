import { test } from "node:test";
import assert from "node:assert/strict";
import { newTabState, recordResponse } from "../lib/tabstate.js";
import { buildView, protocolLabel, referenceLabel, plural } from "../lib/view.js";

const TLS13 = { state: "secure", protocolVersion: "TLSv1.3", cipherSuite: "TLS_AES_128_GCM_SHA256" };
const PQT = {
  ...TLS13, keaGroupName: "mlkem768x25519", signatureSchemeName: "ECDSA-P256-SHA256",
  hsts: true, usedEch: false,
};
const PURE = { ...TLS13, keaGroupName: "mlkem1024" };
const TRAD13 = { ...TLS13, keaGroupName: "x25519", signatureSchemeName: "RSA-PSS-SHA256" };
const NO_GROUP = { ...TLS13, keaGroupName: null };
const TLS12 = {
  state: "secure", protocolVersion: "TLSv1.2", keaGroupName: "P256",
  cipherSuite: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
};
const INSECURE = { state: "insecure" };

// All rows of the page section, in order, across its sub-sections.
const rows = (v) => v.page.sections.flatMap((section) => section.rows);

function tab(rows) {
  const s = newTabState();
  for (const [type, url, info, fromCache = false, responseHeaders = []] of rows) {
    recordResponse(s, { type, url, fromCache, responseHeaders }, info);
  }
  return s;
}

test("pages that cannot be inspected", () => {
  for (const url of [undefined, "about:addons", "file:///C:/x.html", "moz-extension://abc/popup.html"]) {
    assert.equal(buildView(null, url).status, "not-inspectable", String(url));
  }
});

test("restricted Mozilla sites", () => {
  const v = buildView(tab([["main_frame", "https://a.example/", PQT]]), "https://addons.mozilla.org/en-US/firefox/");
  assert.equal(v.status, "restricted");
  assert.equal(v.origin, "https://addons.mozilla.org");
  assert.equal(v.message, "Firefox does not let extensions inspect this site.");
});

test("page not seen: no record, no main frame, or a record of another origin", () => {
  assert.equal(buildView(null, "https://a.example/").status, "not-seen");
  assert.equal(buildView(tab([["image", "https://a.example/i.png", PQT]]), "https://a.example/").status, "not-seen");
  const other = tab([["main_frame", "https://a.example/", PQT]]);
  const v = buildView(other, "https://b.example/page");
  assert.equal(v.status, "not-seen");
  assert.equal(v.origin, "https://b.example");
  assert.equal(v.hint, "Reload the page to check it.");
});

test("page section for a hybrid post-quantum page", () => {
  const v = buildView(tab([["main_frame", "https://a.example/", PQT]]), "https://a.example/page?x=1");
  assert.equal(v.status, "ok");
  assert.equal(v.origin, "https://a.example");
  assert.equal(v.page.icon, "icons/step-pqt.svg");
  assert.equal(v.page.level, "tls13-hybrid");
  assert.equal(v.page.headline, "TLS 1.3 · hybrid post-quantum key exchange");
  assert.deepEqual(v.page.sections, [
    { title: "Connection", rows: [
      ["Protocol", "TLS 1.3"],
      ["Cipher suite", "TLS_AES_128_GCM_SHA256"],
      ["Encryption", "AES-128-GCM"],
      ["AEAD", "Yes"],
    ] },
    { title: "Key exchange", rows: [
      ["Key exchange", "X25519MLKEM768 (Firefox: mlkem768x25519)"],
      ["Type", "PQ/T hybrid: X25519 (traditional) + ML-KEM-768 (post-quantum), RFC 10024"],
      ["Forward secrecy", "Yes"],
    ] },
    { title: "Authentication", rows: [
      ["Signature scheme", "ecdsa_secp256r1_sha256 (Firefox: ECDSA-P256-SHA256)"],
      ["Type", "Traditional"],
    ] },
    { title: "Extensions and headers", rows: [
      ["ECH", "Not used"],
      ["HSTS", "Known to Firefox; no header in this response"],
    ] },
  ]);
  assert.deepEqual(v.warnings, []);
});

// Headline and key exchange type for every kind of page.
test("headline and key exchange type per step", () => {
  const cases = [
    [PURE, "TLS 1.3 · pure post-quantum key exchange",
      "Post-quantum: ML-KEM-1024, draft-ietf-tls-mlkem (approved, not yet an RFC)"],
    [TRAD13, "TLS 1.3 · traditional key exchange (not post-quantum)",
      "Traditional: X25519, RFC 9846; RFC 8422"],
    [TLS12, "TLS 1.2 · traditional key exchange (not post-quantum)",
      "Traditional: P-256, RFC 8422"],
    [{ ...TLS12, keaGroupName: "none" }, "TLS 1.2 · traditional key exchange (not post-quantum)",
      "No key exchange group reported (for example, RSA key transport)"],
    [{ ...TLS12, keaGroupName: "custom" }, "TLS 1.2 · traditional key exchange (not post-quantum)",
      "Traditional: finite field DH with a custom prime"],
    [{ state: "secure", protocolVersion: "TLSv1", keaGroupName: "P256" }, "TLS 1.0 · deprecated protocol",
      "Traditional: P-256, RFC 8422"],
    [{ ...TLS13, keaGroupName: "xyber768d00" }, "Key exchange not determined",
      "Obsolete pre-standard hybrid (X25519 + Kyber768 round 3); not supported by current Firefox"],
    [{ ...TLS12, keaGroupName: null, cipherSuite: "TLS_RSA_WITH_AES_128_GCM_SHA256" },
      "TLS 1.2 · traditional key exchange (not post-quantum)", undefined],
    [{ ...TLS13, keaGroupName: "none" }, "Key exchange not determined", "No key exchange group reported"],
    [NO_GROUP, "Key exchange not determined", undefined],
  ];
  for (const [info, expectedHeadline, expectedType] of cases) {
    const v = buildView(tab([["main_frame", "https://a.example/", info]]), "https://a.example/");
    assert.equal(v.page.headline, expectedHeadline, JSON.stringify(info));
    const type = rows(v).find(([term]) => term === "Type");
    assert.equal(type?.[1], expectedType, JSON.stringify(info));
  }
});

test("key exchange shows one name when IANA and Firefox names are equal", () => {
  const v = buildView(tab([["main_frame", "https://a.example/", TRAD13]]), "https://a.example/");
  assert.deepEqual(rows(v)[4], ["Key exchange", "x25519"]);
});

test("key exchange shows the reported name when the registry does not know it", () => {
  const v = buildView(tab([["main_frame", "https://a.example/", { ...TLS13, keaGroupName: "unknown group" }]]),
    "https://a.example/");
  assert.deepEqual(rows(v)[4], ["Key exchange", "unknown group"]);
});

test("page section for plain HTTP and for an unknown key exchange", () => {
  const http = buildView(tab([["main_frame", "http://a.example/", INSECURE]]), "http://a.example/");
  assert.equal(http.page.headline, "No HTTPS: loaded over plain HTTP, without TLS");
  assert.deepEqual(http.page.sections, []);

  const unknown = buildView(tab([["main_frame", "https://a.example/", NO_GROUP]]), "https://a.example/");
  assert.equal(unknown.page.icon, "icons/step-unknown.svg");
  assert.deepEqual(rows(unknown).map((r) => r[0]), ["Protocol", "Cipher suite", "Encryption", "AEAD", "Key exchange", "Forward secrecy", "Signature scheme", "ECH", "HSTS"]);
  assert.deepEqual(rows(unknown)[4], ["Key exchange", "not reported"]);
  assert.deepEqual(rows(unknown)[5], ["Forward secrecy", "not determined"]);
});

test("setups are listed lowest first with counts and origins", () => {
  const v = buildView(tab([
    ["main_frame", "https://a.example/", PQT],
    ["image", "https://a.example/i.png?v=2", PQT, true],
    ["script", "https://tracker.example/t.js", TLS12],
  ]), "https://a.example/");
  assert.equal(v.responses, 3);
  assert.equal(v.fromCache, 1);
  assert.deepEqual(v.setups.map((s) => s.title), ["TLS 1.2 · secp256r1", "TLS 1.3 · X25519MLKEM768 · hybrid post-quantum"]);
  const pqt = v.setups[1];
  assert.equal(pqt.icon, "icons/step-pqt.svg");
  assert.equal(pqt.cipherSuite, "TLS_AES_128_GCM_SHA256");
  assert.equal(pqt.count, 2);
  assert.equal(pqt.fromCache, 1);
  assert.deepEqual(pqt.origins, [{ name: "https://a.example", count: 2 }]);
  assert.equal(pqt.unlisted, 0);
  assert.equal(v.origins, 2);
  assert.equal(v.originsMore, false);
});

test("warnings without the 'Warning:' prefix", () => {
  const v = buildView(tab([
    ["main_frame", "https://a.example/", PQT],
    ["script", "https://b.example/x.js", TLS12],
    ["image", "https://c.example/i.png", NO_GROUP],
  ]), "https://a.example/");
  assert.deepEqual(v.warnings, [
    "some responses in this tab used a lower level than the page: TLS 1.2",
    "some responses in this tab could not be checked",
  ]);
});

test("labels", () => {
  assert.equal(protocolLabel("TLSv1"), "TLS 1.0");
  assert.equal(protocolLabel("TLSv1.3"), "TLS 1.3");
  assert.equal(protocolLabel("unknown"), "unknown");
  assert.equal(protocolLabel(null), "not reported");
  assert.equal(referenceLabel("[draft-tls-westerbaan-xyber768d00-02]; [RFC 10024]"),
    "draft-tls-westerbaan-xyber768d00-02; RFC 10024");
  assert.equal(referenceLabel("[RFC-ietf-tls-mlkem-10]"), "draft-ietf-tls-mlkem (approved, not yet an RFC)");
  assert.equal(referenceLabel("[draft-yang-tls-hybrid-sm2-mlkem-03]"), "draft-yang-tls-hybrid-sm2-mlkem-03");
  assert.equal(plural(1, "response"), "1 response");
  assert.equal(plural(2, "origin"), "2 origins");
});

test("HSTS row", () => {
  const sts = [{ name: "strict-transport-security", value: "max-age=31536000; includeSubDomains; preload" }];
  const sent = buildView(tab([["main_frame", "https://a.example/", { ...TRAD13, hsts: false }, false, sts]]), "https://a.example/");
  const row = (v, term) => rows(v).find(([t]) => t === term)[1];
  assert.equal(row(sent, "HSTS"), "Header sent: max-age=31536000 (365 days); includeSubDomains; preload");
  const none = buildView(tab([["main_frame", "https://a.example/", { ...TRAD13, hsts: false }]]), "https://a.example/");
  assert.equal(row(none, "HSTS"), "Not used");
});

test("ECH row", () => {
  const row = (info) => buildView(tab([["main_frame", "https://a.example/", info]]), "https://a.example/")
    .page.sections.flatMap((x) => x.rows).find(([t]) => t === "ECH")[1];
  assert.equal(row({ ...TRAD13, usedEch: true }), "Used");
  assert.equal(row({ ...TRAD13, usedEch: false }), "Not used");
  assert.equal(row(TRAD13), "not reported");
});

test("RSA key transport: key exchange row", () => {
  const info = { state: "secure", protocolVersion: "TLSv1.2", cipherSuite: "TLS_RSA_WITH_AES_128_GCM_SHA256" };
  const v = buildView(tab([["main_frame", "https://a.example/", info]]), "https://a.example/");
  assert.deepEqual(rows(v).slice(0, 6), [
    ["Protocol", "TLS 1.2"],
    ["Cipher suite", "TLS_RSA_WITH_AES_128_GCM_SHA256"],
    ["Encryption", "AES-128-GCM"],
    ["AEAD", "Yes"],
    ["Key exchange", "RSA key transport"],
    ["Forward secrecy", "No"],
  ]);
});

test("signature scheme: IANA name, Firefox name and type", () => {
  const auth = (info) => buildView(tab([["main_frame", "https://a.example/", info]]), "https://a.example/")
    .page.sections.find((x) => x.title === "Authentication").rows;
  assert.deepEqual(auth({ ...TRAD13, signatureSchemeName: "ML-DSA-65" }), [
    ["Signature scheme", "mldsa65 (Firefox: ML-DSA-65)"],
    ["Type", "Post-quantum: ML-DSA, FIPS 204"],
  ]);
  assert.deepEqual(auth({ ...TRAD13, signatureSchemeName: "RSA-PKCS1-SHA1MD5" }), [
    ["Signature scheme", "RSA-PKCS1-SHA1MD5"],
    ["Type", "Traditional"],
  ]);
  assert.deepEqual(auth({ ...TRAD13, signatureSchemeName: "unknown signature" }), [
    ["Signature scheme", "unknown signature"],
  ]);
  assert.deepEqual(auth({ ...TRAD13, signatureSchemeName: undefined }), [
    ["Signature scheme", "not reported"],
  ]);
});

test("origins are listed most responses first", () => {
  const v = buildView(tab([
    ["main_frame", "https://a.example/", PQT],
    ["script", "https://b.example/1.js", PQT],
    ["script", "https://b.example/2.js", PQT],
  ]), "https://a.example/");
  assert.deepEqual(v.setups[0].origins, [{ name: "https://b.example", count: 2 }, { name: "https://a.example", count: 1 }]);
});
