import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { newTabState, recordResponse } from "../lib/tabstate.js";
import { summarize } from "../lib/ladder.js";
import { iconFor, PLAIN_ICON, NOT_INSPECTABLE } from "../lib/icon.js";

const TLS13 = { state: "secure", protocolVersion: "TLSv1.3", cipherSuite: "TLS_AES_128_GCM_SHA256" };
const PQT = { ...TLS13, keaGroupName: "mlkem768x25519" };
const PQ = { ...TLS13, keaGroupName: "mlkem1024" };
const KYBER = { ...TLS13, keaGroupName: "xyber768d00" };
const TRAD13 = { ...TLS13, keaGroupName: "x25519" };
const NO_GROUP = { ...TLS13, keaGroupName: null };
const TLS12 = { state: "secure", protocolVersion: "TLSv1.2", keaGroupName: "P256" };
const TLS10 = { state: "secure", protocolVersion: "TLSv1" };
const TLS11 = { state: "secure", protocolVersion: "TLSv1.1" };
const INSECURE = { state: "insecure" };

function icon(rows) {
  const s = newTabState();
  for (const [type, url, info] of rows) recordResponse(s, { type, url, fromCache: false }, info);
  return iconFor(summarize(s));
}
const page = (info) => icon([["main_frame", "https://a.example/", info]]);
const withOther = (pageInfo, otherInfo) => icon([
  ["main_frame", "https://a.example/", pageInfo],
  ["script", "https://b.example/x.js", otherInfo],
]);

test("icon for each step of the page", () => {
  assert.equal(page(INSECURE).path, "icons/step-insecure.svg");
  assert.equal(page(TLS10).path, "icons/step-tls10.svg");
  assert.equal(page(TLS11).path, "icons/step-tls11.svg");
  assert.equal(page(TLS12).path, "icons/step-tls12.svg");
  assert.equal(page(TRAD13).path, "icons/step-tls13.svg");
  assert.equal(page(NO_GROUP).path, "icons/step-unknown.svg");
  assert.equal(page(PQ).path, "icons/step-pq.svg");
  assert.equal(page(PQT).path, "icons/step-pqt.svg");
});

test("every icon the code can choose exists", () => {
  const root = fileURLToPath(new URL("..", import.meta.url));
  const paths = new Set([PLAIN_ICON, NOT_INSPECTABLE.path]);
  for (const info of [INSECURE, TLS10, TLS11, TLS12, TRAD13, NO_GROUP, PQ, PQT]) {
    paths.add(page(info).path);
    paths.add(withOther(info, INSECURE).path);
    paths.add(withOther(info, NO_GROUP).path);
  }
  for (const p of paths) assert.ok(existsSync(root + p), p);
});

test("tooltip first and second lines", () => {
  assert.equal(page(INSECURE).title, "Not encrypted (no HTTPS)");
  assert.equal(page(TLS10).title, "TLS 1.0: deprecated\nNo post-quantum key exchange possible");
  assert.equal(page(TLS11).title, "TLS 1.1: deprecated\nNo post-quantum key exchange possible");
  assert.equal(page(TLS12).title, "TLS 1.2: no post-quantum key exchange possible\nKey exchange: P256");
  assert.equal(page(TRAD13).title, "TLS 1.3: traditional key exchange only\nKey exchange: x25519");
  assert.equal(page(PQ).title,
    "MLKEM1024\nPure post-quantum: ML-KEM-1024, NIST security category 5 (FIPS 203)");
  assert.equal(page(PQT).title,
    "X25519MLKEM768\nPQ/T hybrid: X25519 + ML-KEM-768, NIST security category 3 (FIPS 203)");
  assert.equal(page(KYBER).title,
    "X25519Kyber768Draft00\nPQ/T hybrid with pre-standard Kyber768 (obsolete)");
  assert.equal(page(NO_GROUP).title, "Key exchange not determined\nTLS 1.3, group not reported");
  assert.equal(page({ ...TLS13, keaGroupName: "none" }).title,
    "Key exchange not determined\nTLS 1.3, no key exchange group");
  assert.equal(page({ state: "secure", protocolVersion: "unknown" }).title,
    "Key exchange not determined\nTLS version not reported");
});

test("lower step: warning icon and line", () => {
  const i = withOther(PQT, TLS12);
  assert.equal(i.path, "icons/step-pqt-warn.svg");
  assert.match(i.title, /lower step than the page$/);
});

test("pure post-quantum is lower than PQ/T hybrid", () => {
  assert.equal(withOther(PQT, PQ).path, "icons/step-pqt-warn.svg");
  assert.equal(withOther(PQ, PQT).path, "icons/step-pq.svg");
});

test("better responses do not warn", () => {
  assert.equal(withOther(TRAD13, PQT).path, "icons/step-tls13.svg");
  assert.equal(withOther(TLS12, TRAD13).path, "icons/step-tls12.svg");
});

test("not checked: any unknown response warns, unless the page is unknown or HTTP", () => {
  for (const info of [TLS10, TLS12, TRAD13, PQ, PQT]) {
    const i = withOther(info, NO_GROUP);
    assert.match(i.path, /-warn\.svg$/, JSON.stringify(info));
    assert.match(i.title, /could not be checked$/);
  }
  assert.equal(withOther(NO_GROUP, NO_GROUP).path, "icons/step-unknown.svg");
  assert.equal(withOther(INSECURE, NO_GROUP).path, "icons/step-insecure.svg");
});

test("both warning lines when both rules apply", () => {
  const i = icon([
    ["main_frame", "https://a.example/", PQT],
    ["script", "https://b.example/x.js", TLS12],
    ["image", "https://c.example/i.png", NO_GROUP],
  ]);
  assert.deepEqual(i.title.split("\n").slice(2), [
    "Warning: some responses in this tab use a lower step than the page",
    "Warning: some responses in this tab could not be checked",
  ]);
});

test("an HTTP page never warns", () => {
  const i = withOther(INSECURE, TLS10);
  assert.equal(i.path, "icons/step-insecure.svg");
  assert.equal(i.title, "Not encrypted (no HTTPS)");
});

test("plain icon when the page itself was not seen", () => {
  assert.equal(iconFor(summarize(newTabState())).path, PLAIN_ICON);
  const i = icon([["image", "https://cdn.example/i.png", PQT]]);
  assert.equal(i.path, PLAIN_ICON);
  assert.match(i.title, /not seen/);
});
