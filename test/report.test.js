import { test } from "node:test";
import assert from "node:assert/strict";
import { newTabState, recordResponse } from "../lib/tabstate.js";
import { buildView } from "../lib/view.js";
import { reportText } from "../lib/report.js";

const TLS13 = { state: "secure", protocolVersion: "TLSv1.3", cipherSuite: "TLS_AES_128_GCM_SHA256" };
const PQT = {
  ...TLS13, keaGroupName: "mlkem768x25519", signatureSchemeName: "ECDSA-P256-SHA256",
  hsts: false, usedEch: false,
};
const TLS12 = {
  state: "secure", protocolVersion: "TLSv1.2", keaGroupName: "P256",
  cipherSuite: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
};
const META = { version: "1.2.3", firefox: "145.0", time: new Date("2026-11-16T09:30:15.123Z") };

function view(rows) {
  const s = newTabState();
  for (const [type, url, info, fromCache = false] of rows) {
    recordResponse(s, { type, url, fromCache, responseHeaders: [] }, info);
  }
  return buildView(s, "https://a.example/");
}

test("report of a page with a lower-level response", () => {
  const text = reportText(view([
    ["main_frame", "https://a.example/secret/path?token=abc", PQT],
    ["image", "https://a.example/i.png", PQT, true],
    ["script", "https://b.example/t.js", TLS12],
  ]), META);
  assert.equal(text, [
    "TLSView report",
    "Page: https://a.example",
    "Time: 2026-11-16T09:30:15Z",
    "Checked with: Firefox 145.0, TLSView 1.2.3",
    "",
    "This page: TLS 1.3 · hybrid post-quantum key exchange",
    "  Connection",
    "    Protocol: TLS 1.3",
    "    Cipher suite: TLS_AES_128_GCM_SHA256",
    "    Encryption: AES-128-GCM",
    "    AEAD: Yes",
    "  Key exchange",
    "    Key exchange: X25519MLKEM768 (Firefox: mlkem768x25519)",
    "    Type: PQ/T hybrid: X25519 (traditional) + ML-KEM-768 (post-quantum), RFC 10024",
    "    Forward secrecy: Yes",
    "  Authentication",
    "    Signature scheme: ecdsa_secp256r1_sha256 (Firefox: ECDSA-P256-SHA256)",
    "    Type: Traditional",
    "    Certificate: Verified by Firefox",
    "  Extensions and headers",
    "    ECH: Not used",
    "    HSTS: Not used",
    "",
    "Warnings:",
    "  - some responses in this tab used a lower level than the page: TLS 1.2",
    "",
    "TLS setups in this tab: 2 origins · 3 responses (1 from cache)",
    "",
    "  TLS 1.2 · secp256r1",
    "    Cipher suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "    1 origin · 1 response",
    "      https://b.example  1",
    "",
    "  TLS 1.3 · X25519MLKEM768 · hybrid post-quantum",
    "    Cipher suite: TLS_AES_128_GCM_SHA256",
    "    1 origin · 2 responses (1 from cache)",
    "      https://a.example  2",
    "",
    "Only the key exchange is rated. Certificates are not validated by TLSView.",
    "A response from cache shows the connection that originally fetched it.",
  ].join("\n"));
});

test("report contains origins only, never paths or queries", () => {
  const text = reportText(view([["main_frame", "https://a.example/secret/path?token=abc", PQT]]), META);
  for (const secret of ["secret", "token", "abc", "?"]) assert.ok(!text.includes(secret), secret);
  assert.ok(!text.includes("Warnings:"));
});

test("report without a Firefox version, with certificate overrides", () => {
  const text = reportText(
    view([["main_frame", "https://a.example/", { ...PQT, isUntrusted: true }]]),
    { ...META, firefox: null },
  );
  assert.match(text, /^Checked with: TLSView 1\.2\.3$/m);
  assert.match(text, /^ {4}Certificate: Error overridden: not trusted\./m);
  assert.match(text, /^ {4}1 with an overridden certificate error$/m);
});
