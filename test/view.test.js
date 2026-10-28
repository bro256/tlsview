import { test } from "node:test";
import assert from "node:assert/strict";
import { newTabState, recordResponse } from "../lib/tabstate.js";
import { buildView, protocolLabel, referenceLabel, plural } from "../lib/view.js";

const TLS13 = { state: "secure", protocolVersion: "TLSv1.3", cipherSuite: "TLS_AES_128_GCM_SHA256" };
const PQT = { ...TLS13, keaGroupName: "mlkem768x25519", signatureSchemeName: "ecdsa_secp256r1_sha256" };
const TRAD13 = { ...TLS13, keaGroupName: "x25519", signatureSchemeName: "rsa_pss_rsae_sha256" };
const NO_GROUP = { ...TLS13, keaGroupName: null };
const TLS12 = {
  state: "secure", protocolVersion: "TLSv1.2", keaGroupName: "P256",
  cipherSuite: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
};
const INSECURE = { state: "insecure" };

function tab(rows) {
  const s = newTabState();
  for (const [type, url, info, fromCache = false] of rows) {
    recordResponse(s, { type, url, fromCache }, info);
  }
  return s;
}

test("pages that cannot be inspected", () => {
  for (const url of [undefined, "about:addons", "file:///C:/x.html", "moz-extension://abc/popup.html"]) {
    assert.equal(buildView(null, url).status, "not-inspectable", String(url));
  }
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

test("page section for a PQ/T hybrid page", () => {
  const v = buildView(tab([["main_frame", "https://a.example/", PQT]]), "https://a.example/page?x=1");
  assert.equal(v.status, "ok");
  assert.equal(v.origin, "https://a.example");
  assert.equal(v.page.icon, "icons/step-pqt.svg");
  assert.equal(v.page.label, "TLS 1.3 · PQ/T hybrid");
  assert.deepEqual(v.page.rows, [
    ["Protocol", "TLS 1.3"],
    ["Key exchange", "X25519MLKEM768 (mlkem768x25519)"],
    ["Type", "PQ/T hybrid: X25519 + ML-KEM-768 (PQ component: NIST security category 3, FIPS 203)"],
    ["IANA", "Recommended: Y · RFC 10024"],
    ["Cipher suite", "TLS_AES_128_GCM_SHA256"],
    ["Signature", "ecdsa_secp256r1_sha256"],
  ]);
  assert.deepEqual(v.warnings, []);
});

test("key exchange shows one name when IANA and Firefox names are equal", () => {
  const v = buildView(tab([["main_frame", "https://a.example/", TRAD13]]), "https://a.example/");
  assert.deepEqual(v.page.rows[1], ["Key exchange", "x25519"]);
  assert.deepEqual(v.page.rows[3], ["IANA", "Recommended: Y · RFC 9846; RFC 8422"]);
});

test("page section for plain HTTP and for an unknown key exchange", () => {
  const http = buildView(tab([["main_frame", "http://a.example/", INSECURE]]), "http://a.example/");
  assert.equal(http.page.label, "No HTTPS");
  assert.deepEqual(http.page.rows, [["Encryption", "Not encrypted (no HTTPS)"]]);

  const unknown = buildView(tab([["main_frame", "https://a.example/", NO_GROUP]]), "https://a.example/");
  assert.equal(unknown.page.icon, "icons/step-unknown.svg");
  assert.deepEqual(unknown.page.rows.map((r) => r[0]), ["Protocol", "Key exchange", "Cipher suite", "Signature"]);
  assert.deepEqual(unknown.page.rows[1], ["Key exchange", "not reported"]);
});

test("setups are listed lowest first with counts and URLs", () => {
  const v = buildView(tab([
    ["main_frame", "https://a.example/", PQT],
    ["image", "https://a.example/i.png?v=2", PQT, true],
    ["script", "https://tracker.example/t.js", TLS12],
  ]), "https://a.example/");
  assert.equal(v.responses, 3);
  assert.deepEqual(v.setups.map((s) => s.title), ["TLS 1.2 · secp256r1", "TLS 1.3 · X25519MLKEM768 · PQ/T hybrid"]);
  const pqt = v.setups[1];
  assert.equal(pqt.icon, "icons/step-pqt.svg");
  assert.equal(pqt.cipherSuite, "TLS_AES_128_GCM_SHA256");
  assert.equal(pqt.count, 2);
  assert.equal(pqt.fromCache, 1);
  assert.equal(pqt.origins, 1);
  assert.deepEqual(pqt.urls, ["https://a.example/", "https://a.example/i.png"]);
  assert.equal(pqt.urlsTruncated, false);
});

test("warnings without the 'Warning:' prefix", () => {
  const v = buildView(tab([
    ["main_frame", "https://a.example/", PQT],
    ["script", "https://b.example/x.js", TLS12],
    ["image", "https://c.example/i.png", NO_GROUP],
  ]), "https://a.example/");
  assert.deepEqual(v.warnings, [
    "some responses in this tab have a lower protection level than the page",
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
  assert.equal(plural(1, "response"), "1 response");
  assert.equal(plural(2, "origin"), "2 origins");
});
