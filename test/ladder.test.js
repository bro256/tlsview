import { test } from "node:test";
import assert from "node:assert/strict";
import { newTabState, recordResponse } from "../lib/tabstate.js";
import { STEPS, rankOf, stepOf, summarize, setupTitle } from "../lib/ladder.js";

const TLS13 = { state: "secure", protocolVersion: "TLSv1.3", cipherSuite: "TLS_AES_128_GCM_SHA256" };
const HYBRID = { ...TLS13, keaGroupName: "mlkem768x25519", signatureSchemeName: "ECDSA-P256-SHA256" };
const PURE = { ...TLS13, keaGroupName: "mlkem1024" };
const TRAD13 = { ...TLS13, keaGroupName: "x25519" };
const KYBER = { ...TLS13, keaGroupName: "xyber768d00" };
const NO_GROUP = { ...TLS13, keaGroupName: null };
const TLS12 = {
  state: "secure", protocolVersion: "TLSv1.2", keaGroupName: "P256",
  cipherSuite: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
};
const INSECURE = { state: "insecure" };

// Builds a tab state from [type, url, info] rows.
// Responses without TLS are plain HTTP unless a test says otherwise.
const urlFor = (url, info) => (info.state === "insecure" ? url.replace(/^https:/, "http:") : url);

function tab(rows) {
  const s = newTabState();
  for (const [type, url, info] of rows) recordResponse(s, { type, url: urlFor(url, info), fromCache: false }, info);
  return s;
}
const pageWith = (pageInfo, ...others) => summarize(tab([
  ["main_frame", "https://a.example/", pageInfo],
  ...others.map((info, i) => ["script", `https://o${i}.example/x.js`, info]),
]));

test("stepOf places every kind of setup", () => {
  assert.equal(stepOf(INSECURE), "insecure");
  assert.equal(stepOf({ state: "secure", protocolVersion: "TLSv1" }), "tls-legacy");
  assert.equal(stepOf({ state: "secure", protocolVersion: "TLSv1.1" }), "tls-legacy");
  assert.equal(stepOf(TLS12), "tls12");
  assert.equal(stepOf(TRAD13), "tls13-classical");
  assert.equal(stepOf(HYBRID), "tls13-hybrid");
  assert.equal(stepOf(KYBER), "unknown");
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

test("ranks: PQ/T hybrid above pure post-quantum, unknown unranked", () => {
  assert.deepEqual(
    ["insecure", "tls-legacy", "tls12", "tls13-classical", "tls13-pq", "tls13-hybrid"].map(rankOf),
    [0, 1, 2, 3, 4, 5],
  );
  assert.equal(rankOf("unknown"), null);
  assert.deepEqual(STEPS.map((s) => s.id),
    ["insecure", "tls-legacy", "tls12", "tls13-classical", "unknown", "tls13-pq", "tls13-hybrid"]);
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
    ["image", "https://p.example/1.png", PURE],
    ["script", "https://b.example/x.js", TLS12],
    ["image", "https://c.example/i.png", TRAD13],
    ["image", "http://d.example/i.png", INSECURE],
    ["image", "https://e.example/i.png", NO_GROUP],
  ]));
  assert.deepEqual(s.setups.map((x) => x.step),
    ["insecure", "tls12", "tls13-classical", "unknown", "tls13-pq", "tls13-hybrid"]);
  assert.equal(s.lowest, "insecure");
});

test("no warning when everything is on the page's step or higher", () => {
  assert.equal(pageWith(HYBRID, HYBRID).warning, false);
  assert.equal(pageWith(TRAD13, HYBRID, PURE).warning, false);
  assert.equal(pageWith(PURE, HYBRID).warning, false);
});

test("lower step: one response is enough", () => {
  const rows = [["main_frame", "https://a.example/", HYBRID]];
  for (let i = 0; i < 100; i++) rows.push(["image", `https://a.example/${i}.png`, HYBRID]);
  rows.push(["script", "https://tracker.example/t.js", TLS12]);
  const s = summarize(tab(rows));
  assert.equal(s.lowerStep, true);
  assert.equal(s.notChecked, false);
  assert.equal(s.warning, true);
  assert.equal(s.lowest, "tls12");
});

test("pure post-quantum on a PQ/T hybrid page is a lower step", () => {
  const s = pageWith(HYBRID, PURE);
  assert.equal(s.lowerStep, true);
  assert.equal(s.warning, true);
});

test("not checked: an unknown response warns unless the page is unknown or HTTP", () => {
  for (const info of [TLS12, TRAD13, PURE, HYBRID]) {
    const s = pageWith(info, NO_GROUP);
    assert.equal(s.notChecked, true, JSON.stringify(info));
    assert.equal(s.lowerStep, false);
    assert.equal(s.warning, true);
  }
  assert.equal(pageWith(NO_GROUP, NO_GROUP).warning, false);
  assert.equal(pageWith(INSECURE, NO_GROUP).warning, false);
});

test("no lower-step warning when the page's own step is unknown", () => {
  const s = pageWith(NO_GROUP, TLS12);
  assert.equal(s.main.step, "unknown");
  assert.equal(s.hasUnknown, true);
  assert.equal(s.warning, false);
});

test("an HTTP page never warns", () => {
  assert.equal(pageWith(INSECURE, { state: "secure", protocolVersion: "TLSv1" }, NO_GROUP).warning, false);
});

test("setup titles", () => {
  const title = (info) => setupTitle(summarize(tab([["main_frame", "https://a.example/", info]])).setups[0]);
  assert.equal(title(HYBRID), "TLS 1.3 · X25519MLKEM768 · PQ/T hybrid");
  assert.equal(title(KYBER), "Not determined · TLSv1.3 · X25519Kyber768Draft00 (obsolete)");
  assert.equal(title({ ...TLS12, keaGroupName: null, cipherSuite: "TLS_RSA_WITH_AES_256_CBC_SHA" }),
    "TLS 1.2 · RSA key transport");
  assert.equal(title(PURE), "TLS 1.3 · MLKEM1024 · pure post-quantum");
  assert.equal(title(TRAD13), "TLS 1.3 · x25519 · traditional");
  assert.equal(title(TLS12), "TLS 1.2 · secp256r1");
  assert.equal(title({ state: "secure", protocolVersion: "TLSv1.1" }), "TLS 1.1");
  assert.equal(title(INSECURE), "No HTTPS");
  assert.equal(title(NO_GROUP), "Not determined · TLSv1.3 · key exchange not reported");
  assert.equal(title({ ...TLS13, keaGroupName: "unknown group" }), "Not determined · TLSv1.3 · unknown group");
});

test("an https response reported without TLS is not determined, not plain HTTP", () => {
  const s = newTabState();
  recordResponse(s, { type: "main_frame", url: "https://a.example/", fromCache: false }, TRAD13);
  recordResponse(s, { type: "script", url: "https://b.example/x.js", fromCache: false }, INSECURE);
  recordResponse(s, { type: "script", url: "wss://c.example/ws", fromCache: false }, INSECURE);
  recordResponse(s, { type: "image", url: "http://d.example/i.png", fromCache: false }, INSECURE);
  const summary = summarize(s);
  const steps = summary.setups.map((x) => [x.step, x.count, setupTitle(x)]);
  assert.deepEqual(steps, [
    ["insecure", 1, "No HTTPS"],
    ["tls13-classical", 1, "TLS 1.3 · x25519 · traditional"],
    ["unknown", 2, "Not determined · HTTPS without TLS details"],
  ]);
  assert.equal(summary.lowerStep, true);  // the plain HTTP image
  assert.equal(summary.notChecked, true); // the https responses without TLS
});
