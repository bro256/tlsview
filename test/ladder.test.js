import { test } from "node:test";
import assert from "node:assert/strict";
import { newTabState, recordResponse } from "../lib/tabstate.js";
import { STEPS, stepOf, summarize, setupTitle, describeSummary } from "../lib/ladder.js";

const TLS13 = { state: "secure", protocolVersion: "TLSv1.3", cipherSuite: "TLS_AES_128_GCM_SHA256" };
const HYBRID = { ...TLS13, keaGroupName: "mlkem768x25519", signatureSchemeName: "ecdsa_secp256r1_sha256" };
const PURE = { ...TLS13, keaGroupName: "mlkem1024" };
const CLASSICAL13 = { ...TLS13, keaGroupName: "x25519" };
const KYBER = { ...TLS13, keaGroupName: "xyber768d00" };
const NO_GROUP = { ...TLS13, keaGroupName: null };
const TLS12 = {
  state: "secure", protocolVersion: "TLSv1.2", keaGroupName: "P256",
  cipherSuite: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
};
const INSECURE = { state: "insecure" };

// Builds a tab state from [type, url, info] rows.
function tab(rows) {
  const s = newTabState();
  for (const [type, url, info] of rows) recordResponse(s, { type, url, fromCache: false }, info);
  return s;
}

test("stepOf places every kind of setup", () => {
  assert.equal(stepOf(INSECURE), "insecure");
  assert.equal(stepOf({ state: "secure", protocolVersion: "TLSv1" }), "tls-legacy");
  assert.equal(stepOf({ state: "secure", protocolVersion: "TLSv1.1" }), "tls-legacy");
  assert.equal(stepOf(TLS12), "tls12");
  assert.equal(stepOf(CLASSICAL13), "tls13-classical");
  assert.equal(stepOf(HYBRID), "tls13-hybrid");
  assert.equal(stepOf(KYBER), "tls13-hybrid");
  assert.equal(stepOf(PURE), "tls13-pq");
  assert.equal(stepOf(NO_GROUP), "unknown");
  assert.equal(stepOf({ ...TLS13, keaGroupName: "none" }), "unknown");
  assert.equal(stepOf({ ...TLS13, keaGroupName: "unknown group" }), "unknown");
  assert.equal(stepOf({ state: "secure", protocolVersion: "unknown", keaGroupName: "x25519" }), "unknown");
});

test("TLS 1.2 and earlier are placed by version, whatever the group", () => {
  assert.equal(stepOf({ ...TLS12, keaGroupName: "none" }), "tls12");
  assert.equal(stepOf({ ...TLS12, keaGroupName: null }), "tls12");
  assert.equal(stepOf({ ...TLS12, keaGroupName: "mlkem768x25519" }), "tls12");
});

test("hybrid and pure post-quantum share a rank", () => {
  const rank = (id) => STEPS.find((s) => s.id === id).rank;
  assert.equal(rank("tls13-hybrid"), rank("tls13-pq"));
  assert.equal(rank("unknown"), null);
});

test("empty tab", () => {
  const s = summarize(newTabState());
  assert.equal(s.main, null);
  assert.deepEqual(s.setups, []);
  assert.equal(s.lowest, null);
  assert.equal(s.warning, false);
  assert.equal(s.responses, 0);
});

test("setups are sorted lowest step first, then by count", () => {
  const s = summarize(tab([
    ["main_frame", "https://a.example/", HYBRID],
    ["image", "https://a.example/1.png", HYBRID],
    ["script", "https://b.example/x.js", TLS12],
    ["image", "https://c.example/i.png", CLASSICAL13],
    ["image", "http://d.example/i.png", INSECURE],
    ["image", "https://e.example/i.png", NO_GROUP],
  ]));
  assert.deepEqual(s.setups.map((x) => x.step),
    ["insecure", "tls12", "tls13-classical", "unknown", "tls13-hybrid"]);
  assert.equal(s.lowest, "insecure");
});

test("no warning when everything is on the page's step", () => {
  const s = summarize(tab([
    ["main_frame", "https://a.example/", HYBRID],
    ["image", "https://cdn.example/i.png", PURE],
  ]));
  assert.equal(s.main.step, "tls13-hybrid");
  assert.equal(s.warning, false);
});

test("warning when one response is on a lower step", () => {
  const rows = [["main_frame", "https://a.example/", HYBRID]];
  for (let i = 0; i < 100; i++) rows.push(["image", `https://a.example/${i}.png`, HYBRID]);
  rows.push(["script", "https://tracker.example/t.js", TLS12]);
  const s = summarize(tab(rows));
  assert.equal(s.warning, true);
  assert.equal(s.lowest, "tls12");
});

test("unknown setups warn only when the page is post-quantum", () => {
  assert.equal(summarize(tab([
    ["main_frame", "https://a.example/", HYBRID],
    ["image", "https://b.example/i.png", NO_GROUP],
  ])).warning, true);
  assert.equal(summarize(tab([
    ["main_frame", "https://a.example/", CLASSICAL13],
    ["image", "https://b.example/i.png", NO_GROUP],
  ])).warning, false);
});

test("no warning when the page's own step is unknown", () => {
  const s = summarize(tab([
    ["main_frame", "https://a.example/", NO_GROUP],
    ["image", "https://b.example/i.png", TLS12],
  ]));
  assert.equal(s.main.step, "unknown");
  assert.equal(s.hasUnknown, true);
  assert.equal(s.warning, false);
});

test("setup titles", () => {
  const title = (info) => summarize(tab([["main_frame", "https://a.example/", info]])).setups[0];
  assert.equal(setupTitle(title(HYBRID)), "TLS 1.3 · mlkem768x25519 · hybrid");
  assert.equal(setupTitle(title(KYBER)), "TLS 1.3 · xyber768d00 · hybrid, obsolete");
  assert.equal(setupTitle(title(PURE)), "TLS 1.3 · mlkem1024 · pure post-quantum");
  assert.equal(setupTitle(title(CLASSICAL13)), "TLS 1.3 · x25519 · classical");
  assert.equal(setupTitle(title(TLS12)), "TLS 1.2 · P256");
  assert.equal(setupTitle(title({ state: "secure", protocolVersion: "TLSv1.1" })), "TLS 1.1");
  assert.equal(setupTitle(title(INSECURE)), "No HTTPS");
  assert.equal(setupTitle(title(NO_GROUP)), "Not determined · TLSv1.3 · key exchange not reported");
});

test("describeSummary", () => {
  const text = describeSummary(summarize(tab([
    ["main_frame", "https://a.example/", HYBRID],
    ["script", "https://tracker.example/t.js", TLS12],
  ])));
  assert.equal(text, [
    "This page: TLS 1.3 · hybrid",
    "  Key exchange  mlkem768x25519 · hybrid: X25519 + ML-KEM-768 (PQ component: NIST security category 3, FIPS 203)",
    "                [RFC 10024] · Recommended: Y",
    "  Cipher suite  TLS_AES_128_GCM_SHA256",
    "  Signature     ecdsa_secp256r1_sha256",
    "TLS setups in this tab (2 responses):",
    "  TLS 1.2 · P256",
    "    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "    1 responses (0 from cache), 1 origin(s)",
    "  TLS 1.3 · mlkem768x25519 · hybrid",
    "    TLS_AES_128_GCM_SHA256",
    "    1 responses (0 from cache), 1 origin(s)",
    "Warning: part of this tab is, or may be, on a lower step than the page.",
  ].join("\n"));
});
