import { test } from "node:test";
import assert from "node:assert/strict";
import {
  originOf,
  newTabState,
  profileOf,
  profileKey,
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

test("originOf keeps scheme, host and port only", () => {
  assert.equal(originOf("https://example.com/a/b?q=secret#x"), "https://example.com");
  assert.equal(originOf("https://example.com:8443/"), "https://example.com:8443");
  assert.equal(originOf("http://example.com/"), "http://example.com");
  assert.equal(originOf("wss://example.com/socket"), "wss://example.com");
  assert.equal(originOf("not a url"), null);
  assert.equal(originOf("data:text/plain,hi"), null);
});

test("new state stores the page origin, not the URL", () => {
  const s = newTabState("https://example.com/private?token=1");
  assert.equal(s.pageOrigin, "https://example.com");
  assert.deepEqual(s.origins, {});
  assert.equal(s.mainFrame, null);
});

test("records the main frame", () => {
  const s = newTabState(null);
  recordResponse(s, { type: "main_frame", url: "https://example.com/", fromCache: false }, HYBRID);
  assert.equal(s.pageOrigin, "https://example.com");
  assert.equal(s.mainFrame, profileKey(profileOf(HYBRID)));
});

test("counts responses with the same profile together", () => {
  const s = newTabState("https://example.com/");
  for (const fromCache of [false, true, true]) {
    recordResponse(s, { type: "image", url: "https://cdn.example/x.png", fromCache }, HYBRID);
  }
  const profiles = Object.values(s.origins["https://cdn.example"].profiles);
  assert.equal(profiles.length, 1);
  assert.equal(profiles[0].count, 3);
  assert.equal(profiles[0].fromCache, 2);
});

test("keeps different profiles of one origin apart", () => {
  const s = newTabState("https://example.com/");
  recordResponse(s, { type: "script", url: "https://example.com/a.js", fromCache: false }, HYBRID);
  recordResponse(s, { type: "script", url: "https://example.com/b.js", fromCache: false }, CLASSICAL);
  const groups = Object.values(s.origins["https://example.com"].profiles).map((p) => p.keaGroupName);
  assert.deepEqual(groups.sort(), ["mlkem768x25519", "x25519"]);
});

test("records plain HTTP with nulls for missing TLS fields", () => {
  const s = newTabState(null);
  recordResponse(s, { type: "main_frame", url: "http://example.com/", fromCache: false }, INSECURE);
  const [p] = Object.values(s.origins["http://example.com"].profiles);
  assert.equal(p.state, "insecure");
  assert.equal(p.keaGroupName, null);
  assert.equal(p.protocolVersion, null);
});

test("ignores responses whose URL has no origin", () => {
  const s = newTabState(null);
  recordResponse(s, { type: "image", url: "not a url", fromCache: false }, HYBRID);
  assert.deepEqual(s.origins, {});
});

test("state contains no full URLs", () => {
  const s = newTabState("https://example.com/page?user=alice");
  recordResponse(s, { type: "main_frame", url: "https://example.com/page?user=alice", fromCache: false }, HYBRID);
  recordResponse(s, { type: "xmlhttprequest", url: "https://api.example/v1/me?token=abc", fromCache: false }, HYBRID);
  const json = JSON.stringify(s);
  assert.ok(!json.includes("alice"));
  assert.ok(!json.includes("token"));
  assert.ok(!json.includes("/v1/"));
});

test("state survives a JSON round trip unchanged", () => {
  const s = newTabState("https://example.com/");
  recordResponse(s, { type: "main_frame", url: "https://example.com/", fromCache: false }, HYBRID);
  assert.deepEqual(JSON.parse(JSON.stringify(s)), s);
});
