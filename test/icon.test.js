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

// Responses without TLS are plain HTTP unless a test says otherwise.
const urlFor = (url, info) => (info.state === "insecure" ? url.replace(/^https:/, "http:") : url);

function icon(rows) {
  const s = newTabState();
  for (const [type, url, info] of rows) recordResponse(s, { type, url: urlFor(url, info), fromCache: false }, info);
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

test("tooltip: headline, key exchange, cipher suite", () => {
  const AES128 = "TLS_AES_128_GCM_SHA256";
  assert.equal(page(INSECURE).title, "No HTTPS: loaded over plain HTTP, without TLS");
  assert.equal(page(PQT).title,
    `TLS 1.3 · PQ/T hybrid key exchange (quantum-resistant)\nKey exchange: X25519MLKEM768\nCipher suite: ${AES128}`);
  assert.equal(page(PQ).title,
    `TLS 1.3 · post-quantum key exchange (quantum-resistant)\nKey exchange: MLKEM1024\nCipher suite: ${AES128}`);
  assert.equal(page(TRAD13).title,
    `TLS 1.3 · traditional key exchange (not quantum-resistant)\nKey exchange: x25519\nCipher suite: ${AES128}`);
  const ECDHE12 = { ...TLS12, cipherSuite: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" };
  assert.equal(page(ECDHE12).title,
    "TLS 1.2 · traditional key exchange (not quantum-resistant)\nKey exchange: secp256r1\nCipher suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
  const RSA12 = { state: "secure", protocolVersion: "TLSv1.2", cipherSuite: "TLS_RSA_WITH_AES_128_GCM_SHA256" };
  assert.equal(page(RSA12).title,
    "TLS 1.2 · traditional key exchange (not quantum-resistant)\nKey exchange: RSA key transport (no forward secrecy)\n" +
    "Cipher suite: TLS_RSA_WITH_AES_128_GCM_SHA256");
  assert.equal(page({ ...RSA12, protocolVersion: "TLSv1", cipherSuite: "TLS_RSA_WITH_AES_128_CBC_SHA" }).title,
    "TLS 1.0 · deprecated protocol\nKey exchange: RSA key transport (no forward secrecy)\nCipher suite: TLS_RSA_WITH_AES_128_CBC_SHA");
  assert.equal(page(TLS11).title, "TLS 1.1 · deprecated protocol\nKey exchange: not reported\nCipher suite: not reported");
  assert.equal(page({ ...TLS12, keaGroupName: "custom", cipherSuite: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA" }).title,
    "TLS 1.2 · traditional key exchange (not quantum-resistant)\nKey exchange: Finite field DH with a custom prime\n" +
    "Cipher suite: TLS_DHE_RSA_WITH_AES_128_CBC_SHA");
  assert.equal(page(KYBER).title,
    "Key exchange not determined\nTLS 1.3, obsolete group: X25519Kyber768Draft00 (not supported by current Firefox)");
  assert.equal(page(NO_GROUP).title, "Key exchange not determined\nTLS 1.3, group not reported");
  assert.equal(page({ ...TLS13, keaGroupName: "none" }).title,
    "Key exchange not determined\nTLS 1.3, no key exchange group");
  assert.equal(page({ state: "secure", protocolVersion: "unknown" }).title,
    "Key exchange not determined\nTLS version not reported");
});

test("lower step: warning icon and line", () => {
  const i = withOther(PQT, TLS12);
  assert.equal(i.path, "icons/step-pqt-warn.svg");
  assert.match(i.title, /lower protection level than the page$/);
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
  assert.deepEqual(i.title.split("\n").slice(3), [
    "Warning: some responses in this tab have a lower protection level than the page",
    "Warning: some responses in this tab could not be checked",
  ]);
});

test("an HTTP page never warns", () => {
  const i = withOther(INSECURE, TLS10);
  assert.equal(i.path, "icons/step-insecure.svg");
  assert.equal(i.title, "No HTTPS: loaded over plain HTTP, without TLS");
});

test("plain icon when the page itself was not seen", () => {
  assert.equal(iconFor(summarize(newTabState())).path, PLAIN_ICON);
  const i = icon([["image", "https://cdn.example/i.png", PQT]]);
  assert.equal(i.path, PLAIN_ICON);
  assert.match(i.title, /not seen/);
});

test("an https page reported without TLS: not determined", () => {
  const s = newTabState();
  recordResponse(s, { type: "main_frame", url: "https://a.example/", fromCache: false }, INSECURE);
  const i = iconFor(summarize(s));
  assert.equal(i.path, "icons/step-unknown.svg");
  assert.equal(i.title, "Key exchange not determined\nHTTPS, but Firefox reported no TLS details");
});
