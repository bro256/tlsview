import { test } from "node:test";
import assert from "node:assert/strict";
import {
  MAX_ITEMS,
  originOf,
  newTabState,
  setupOf,
  setupKey,
  recordResponse,
  topDocumentOrigin,
  isFromCurrentPage,
} from "../lib/tabstate.js";

const HYBRID = {
  state: "secure",
  protocolVersion: "TLSv1.3",
  keaGroupName: "mlkem768x25519",
  signatureSchemeName: "ECDSA-P256-SHA256",
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

test("records the main frame with its signature", () => {
  const s = newTabState();
  recordResponse(s, r("main_frame", "https://example.com/page?x=1"), HYBRID);
  assert.equal(s.pageOrigin, "https://example.com");
  assert.deepEqual(s.mainFrame, {
    ...setupOf(HYBRID), signatureSchemeName: "ECDSA-P256-SHA256",
    hsts: null, usedEch: null, hstsHeader: null,
  });
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
  assert.deepEqual(hybrid.origins, { "https://a.example": 1, "https://b.example": 1 });
});

test("the signature scheme does not split a setup", () => {
  const s = newTabState();
  recordResponse(s, r("image", "https://a.example/1.png"), HYBRID);
  recordResponse(s, r("image", "https://b.example/2.png"), { ...HYBRID, signatureSchemeName: "RSA-PSS-SHA256" });
  assert.deepEqual(only(s).signatures, { "ECDSA-P256-SHA256": 1, "RSA-PSS-SHA256": 1 });
});

test("counts responses and cached responses", () => {
  const s = newTabState();
  for (const cached of [false, true, true]) recordResponse(s, r("image", "https://a.example/x.png", cached), HYBRID);
  assert.equal(only(s).count, 3);
  assert.equal(only(s).fromCache, 2);
  assert.deepEqual(only(s).origins, { "https://a.example": 3 });
});

test("records plain HTTP with nulls for missing TLS fields", () => {
  const s = newTabState();
  recordResponse(s, r("main_frame", "http://example.com/"), INSECURE);
  assert.equal(only(s).state, "insecure");
  assert.equal(only(s).protocolVersion, null);
  assert.equal(only(s).keaGroupName, null);
  assert.deepEqual(only(s).signatures, {});
});

test("stores origins only, with a response count, never paths or queries", () => {
  const s = newTabState();
  recordResponse(s, r("script", "https://a.example/secret/path.js?token=x"), HYBRID);
  recordResponse(s, r("image", "https://a.example/other.png"), HYBRID);
  assert.deepEqual(only(s).origins, { "https://a.example": 2 });
  assert.ok(!JSON.stringify(s).includes("secret"));
  assert.ok(!JSON.stringify(s).includes("token"));
});

test("caps listed origins and counts the rest as unlisted", () => {
  const s = newTabState();
  for (let i = 0; i < MAX_ITEMS + 5; i++) recordResponse(s, r("image", `https://h${i}.example/x.png`), HYBRID);
  recordResponse(s, r("image", "https://h0.example/y.png"), HYBRID); // listed origin still counts
  assert.equal(Object.keys(only(s).origins).length, MAX_ITEMS);
  assert.equal(only(s).unlisted, 5);
  assert.equal(only(s).origins["https://h0.example"], 2);
  assert.equal(only(s).count, MAX_ITEMS + 6);
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

test("topDocumentOrigin uses the top-level frame, or the document", () => {
  assert.equal(topDocumentOrigin({ documentUrl: "https://a.example/page", frameAncestors: [] }), "https://a.example");
  assert.equal(topDocumentOrigin({
    documentUrl: "https://ads.example/frame.html",
    frameAncestors: [{ url: "https://mid.example/x", frameId: 5 }, { url: "https://top.example/", frameId: 0 }],
  }), "https://top.example");
  assert.equal(topDocumentOrigin({}), null);
  assert.equal(topDocumentOrigin({ documentUrl: "about:blank" }), null);
});

test("isFromCurrentPage drops late responses of a previous page from another origin", () => {
  const s = newTabState();
  recordResponse(s, r("main_frame", "https://new.example/"), HYBRID);
  const late = { type: "image", url: "https://cdn.old.example/i.png", documentUrl: "https://old.example/", frameAncestors: [] };
  const own = { type: "image", url: "https://cdn.example/i.png", documentUrl: "https://new.example/", frameAncestors: [] };
  const inFrame = {
    type: "script", url: "https://ads.example/a.js", documentUrl: "https://ads.example/f.html",
    frameAncestors: [{ url: "https://new.example/", frameId: 0 }],
  };
  assert.equal(isFromCurrentPage(s, late), false);
  assert.equal(isFromCurrentPage(s, own), true);
  assert.equal(isFromCurrentPage(s, inFrame), true);
  assert.equal(isFromCurrentPage(s, { type: "main_frame", url: "https://other.example/" }), true);
  assert.equal(isFromCurrentPage(s, { type: "image", url: "https://x.example/i.png" }), true);
});

test("isFromCurrentPage accepts everything before the page is known", () => {
  assert.equal(isFromCurrentPage(newTabState(),
    { type: "image", url: "https://x.example/i.png", documentUrl: "https://y.example/" }), true);
});

