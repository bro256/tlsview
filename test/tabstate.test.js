import { test } from "node:test";
import assert from "node:assert/strict";
import {
  MAX_ITEMS,
  originOf,
  urlWithoutQuery,
  newTabState,
  setupOf,
  setupKey,
  recordResponse,
} from "../lib/tabstate.js";

const HYBRID = {
  state: "secure",
  protocolVersion: "TLSv1.3",
  keaGroupName: "mlkem768x25519",
  signatureSchemeName: "ecdsa_secp256r1_sha256",
  cipherSuite: "TLS_AES_128_GCM_SHA256",
};
const CLASSICAL = { ...HYBRID, keaGroupName: "x25519" };
const INSECURE = { state: "insecure" };

const r = (type, url, fromCache = false) => ({ type, url, fromCache });
const only = (state) => {
  const setups = Object.values(state.setups);
  assert.equal(setups.length, 1);
  return setups[0];
};

test("originOf keeps scheme, host and port only", () => {
  assert.equal(originOf("https://example.com/a/b?q=secret#x"), "https://example.com");
  assert.equal(originOf("https://example.com:8443/"), "https://example.com:8443");
  assert.equal(originOf("wss://example.com/socket"), "wss://example.com");
  assert.equal(originOf("not a url"), null);
  assert.equal(originOf("data:text/plain,hi"), null);
});

test("urlWithoutQuery drops query string and fragment", () => {
  assert.equal(urlWithoutQuery("https://example.com/a/b?token=abc#x"), "https://example.com/a/b");
  assert.equal(urlWithoutQuery("https://example.com"), "https://example.com/");
  assert.equal(urlWithoutQuery("not a url"), null);
});

test("records the main frame with its signature", () => {
  const s = newTabState();
  recordResponse(s, r("main_frame", "https://example.com/page?x=1"), HYBRID);
  assert.equal(s.pageOrigin, "https://example.com");
  assert.deepEqual(s.mainFrame, { ...setupOf(HYBRID), signatureSchemeName: "ecdsa_secp256r1_sha256" });
});

test("groups responses by TLS version, key exchange group and cipher suite", () => {
  const s = newTabState();
  recordResponse(s, r("script", "https://a.example/1.js"), HYBRID);
  recordResponse(s, r("script", "https://b.example/2.js"), HYBRID);
  recordResponse(s, r("script", "https://a.example/3.js"), CLASSICAL);
  recordResponse(s, r("script", "https://a.example/4.js"), { ...HYBRID, cipherSuite: "TLS_AES_256_GCM_SHA384" });
  assert.equal(Object.keys(s.setups).length, 3);
  const hybrid = s.setups[setupKey(setupOf(HYBRID))];
  assert.equal(hybrid.count, 2);
  assert.deepEqual(hybrid.origins, ["https://a.example", "https://b.example"]);
});

test("the signature scheme does not split a setup", () => {
  const s = newTabState();
  recordResponse(s, r("image", "https://a.example/1.png"), HYBRID);
  recordResponse(s, r("image", "https://b.example/2.png"), { ...HYBRID, signatureSchemeName: "rsa_pss_rsae_sha256" });
  assert.deepEqual(only(s).signatures, { ecdsa_secp256r1_sha256: 1, rsa_pss_rsae_sha256: 1 });
});

test("counts responses and cached responses", () => {
  const s = newTabState();
  for (const cached of [false, true, true]) recordResponse(s, r("image", "https://a.example/x.png", cached), HYBRID);
  assert.equal(only(s).count, 3);
  assert.equal(only(s).fromCache, 2);
  assert.deepEqual(only(s).urls, ["https://a.example/x.png"]);
});

test("records plain HTTP with nulls for missing TLS fields", () => {
  const s = newTabState();
  recordResponse(s, r("main_frame", "http://example.com/"), INSECURE);
  assert.equal(only(s).state, "insecure");
  assert.equal(only(s).protocolVersion, null);
  assert.equal(only(s).keaGroupName, null);
  assert.deepEqual(only(s).signatures, {});
});

test("caps stored URLs and marks the list as truncated", () => {
  const s = newTabState();
  for (let i = 0; i < MAX_ITEMS + 5; i++) recordResponse(s, r("image", `https://a.example/${i}.png`), HYBRID);
  assert.equal(only(s).urls.length, MAX_ITEMS);
  assert.equal(only(s).urlsTruncated, true);
  assert.equal(only(s).count, MAX_ITEMS + 5);
  assert.equal(only(s).originsTruncated, false);
});

test("ignores responses whose URL has no origin", () => {
  const s = newTabState();
  recordResponse(s, r("image", "not a url"), HYBRID);
  assert.deepEqual(s.setups, {});
});

test("state contains no query strings or fragments", () => {
  const s = newTabState();
  recordResponse(s, r("main_frame", "https://example.com/page?user=alice#me"), HYBRID);
  recordResponse(s, r("xmlhttprequest", "https://api.example/v1/me?token=abc"), HYBRID);
  const json = JSON.stringify(s);
  for (const secret of ["alice", "token", "abc", "#me", "?"]) {
    assert.ok(!json.includes(secret), secret);
  }
});

test("state survives a JSON round trip unchanged", () => {
  const s = newTabState();
  recordResponse(s, r("main_frame", "https://example.com/"), HYBRID);
  assert.deepEqual(JSON.parse(JSON.stringify(s)), s);
});
