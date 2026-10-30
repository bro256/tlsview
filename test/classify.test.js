import { test } from "node:test";
import assert from "node:assert/strict";
import { GROUPS, FIREFOX_SPECIAL } from "../lib/groups.js";
import { classifyGroup, isRsaKeyTransport, forwardSecrecy, recordProtection, signatureKind, signatureIanaName } from "../lib/classify.js";

// Every name getKeaGroupName() in Firefox can return (nsNSSCallbacks.cpp),
// and the expected mode.
const FIREFOX_NAMES = {
  P256: "classical",
  P384: "classical",
  P521: "classical",
  x25519: "classical",
  "FF 2048": "classical",
  "FF 3072": "classical",
  custom: "classical",
  xyber768d00: "hybrid",
  mlkem768x25519: "hybrid",
  secp256r1mlkem768: "hybrid",
  secp384r1mlkem1024: "hybrid",
  mlkem1024: "pq",
  none: "none",
  "unknown group": "unknown",
};

test("classifies every Firefox group name", () => {
  for (const [name, mode] of Object.entries(FIREFOX_NAMES)) {
    assert.equal(classifyGroup(name).mode, mode, name);
  }
});

test("maps Firefox names to IANA names", () => {
  assert.equal(classifyGroup("mlkem768x25519").name, "X25519MLKEM768");
  assert.equal(classifyGroup("mlkem768x25519").codepoint, 0x11ec);
  assert.equal(classifyGroup("mlkem1024").name, "MLKEM1024");
  assert.equal(classifyGroup("P256").name, "secp256r1");
  assert.equal(classifyGroup("xyber768d00").status, "obsolete");
});

test("accepts IANA names, case-insensitively", () => {
  assert.equal(classifyGroup("X25519MLKEM768").mode, "hybrid");
  assert.equal(classifyGroup("x25519mlkem768").mode, "hybrid");
  assert.equal(classifyGroup("  MLKEM1024 ").mode, "pq");
});

test("returns unknown for empty, missing or unrecognised input", () => {
  for (const input of [undefined, null, "", "   ", 42, "brand-new-group"]) {
    assert.equal(classifyGroup(input).mode, "unknown");
  }
});

test("registry entries are consistent", () => {
  const seenNames = new Set();
  const seenCodepoints = new Set();
  for (const g of GROUPS) {
    // A group may repeat its own name (Firefox and IANA both say "x25519"),
    // but no name may point to two different groups.
    const ownNames = new Set([g.name, g.firefox].map((n) => n.toLowerCase()));
    for (const key of ownNames) {
      assert.ok(!seenNames.has(key), "name used by two groups: " + key);
      seenNames.add(key);
    }
    assert.ok(!seenCodepoints.has(g.codepoint), "duplicate codepoint " + g.codepoint);
    seenCodepoints.add(g.codepoint);

    assert.ok(["classical", "hybrid", "pq"].includes(g.mode), g.name);
    assert.ok(["rfc", "draft", "obsolete"].includes(g.status), g.name);
    // "[RFC-ietf-..." (approved draft) does not count as a published RFC.
    if (g.status === "rfc") assert.ok(g.reference.includes("[RFC "), g.name);
    if (g.status === "draft") assert.ok(!g.reference.includes("[RFC "), g.name);
    assert.ok(["Y", "N", "D"].includes(g.recommended), g.name);
    assert.equal(g.classical !== null, g.mode !== "pq", g.name + ": classical component");
    assert.equal(g.pq !== null, g.mode !== "classical", g.name + ": pq component");
    if (g.pq) {
      assert.ok([1, 3, 5].includes(g.pq.nistCategory), g.name);
      // ML-KEM categories come from FIPS 203; anything else is a claim.
      const expectedSource = g.pq.alg.startsWith("ML-KEM-")
        ? "FIPS 203"
        : "claimed in the round-3 submission";
      assert.equal(g.pq.categorySource, expectedSource, g.name);
    }
  }
});

test("covers exactly the names Firefox reports", () => {
  const registryNames = [
    ...GROUPS.map((g) => g.firefox),
    ...Object.keys(FIREFOX_SPECIAL),
    "unknown group",
  ].sort();
  assert.deepEqual(registryNames, Object.keys(FIREFOX_NAMES).sort());
});

test("RSA key transport is recognised from the cipher suite, before TLS 1.3 only", () => {
  const v12 = "TLSv1.2";
  assert.equal(isRsaKeyTransport({ protocolVersion: v12, cipherSuite: "TLS_RSA_WITH_AES_128_GCM_SHA256" }), true);
  assert.equal(isRsaKeyTransport({ protocolVersion: "TLSv1", cipherSuite: "TLS_RSA_WITH_AES_128_CBC_SHA" }), true);
  assert.equal(isRsaKeyTransport({ protocolVersion: v12, cipherSuite: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" }), false);
  assert.equal(isRsaKeyTransport({ protocolVersion: v12, cipherSuite: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA" }), false);
  assert.equal(isRsaKeyTransport({ protocolVersion: "TLSv1.3", cipherSuite: "TLS_AES_128_GCM_SHA256" }), false);
  assert.equal(isRsaKeyTransport({ protocolVersion: v12, cipherSuite: null }), false);
});

test("forward secrecy", () => {
  assert.equal(forwardSecrecy({ protocolVersion: "TLSv1.3", keaGroupName: "mlkem768x25519" }), true);
  assert.equal(forwardSecrecy({ protocolVersion: "TLSv1.3", keaGroupName: null }), null);
  assert.equal(forwardSecrecy({ protocolVersion: "TLSv1.2", cipherSuite: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" }), true);
  assert.equal(forwardSecrecy({ protocolVersion: "TLSv1.2", cipherSuite: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA" }), true);
  assert.equal(forwardSecrecy({ protocolVersion: "TLSv1.2", cipherSuite: "TLS_RSA_WITH_AES_128_GCM_SHA256" }), false);
  assert.equal(forwardSecrecy({ protocolVersion: "TLSv1", cipherSuite: "TLS_RSA_WITH_AES_128_CBC_SHA" }), false);
  assert.equal(forwardSecrecy({ protocolVersion: "TLSv1.2", cipherSuite: null }), null);
});

test("record protection from the cipher suite", () => {
  const cases = {
    TLS_AES_128_GCM_SHA256: ["AES-128-GCM", true],
    TLS_AES_256_GCM_SHA384: ["AES-256-GCM", true],
    TLS_CHACHA20_POLY1305_SHA256: ["ChaCha20-Poly1305", true],
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: ["ChaCha20-Poly1305", true],
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: ["AES-128-GCM", true],
    TLS_RSA_WITH_AES_256_GCM_SHA384: ["AES-256-GCM", true],
    TLS_AES_128_CCM_8_SHA256: ["AES-128-CCM-8", true],
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: ["AES-128-CBC + HMAC-SHA1", false],
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA: ["AES-256-CBC + HMAC-SHA1", false],
    TLS_RSA_WITH_3DES_EDE_CBC_SHA: ["3DES-EDE-CBC + HMAC-SHA1", false],
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256: ["AES-128-CBC + HMAC-SHA256", false],
  };
  for (const [suite, [cipher, aead]] of Object.entries(cases)) {
    assert.deepEqual(recordProtection(suite), { cipher, aead }, suite);
  }
  assert.equal(recordProtection("TLS_RSA_WITH_RC4_128_SHA"), null);
  assert.equal(recordProtection(null), null);
});

test("signature scheme kind, by the names Firefox reports", () => {
  for (const n of ["ECDSA-P256-SHA256", "ECDSA-P384-SHA384", "ECDSA-P521-SHA512", "RSA-PSS-SHA256",
    "RSA-PKCS1-SHA256", "ECDSA-SHA1", "RSA-PKCS1-SHA1", "RSA-PKCS1-SHA1MD5"]) {
    assert.equal(signatureKind(n), "traditional", n);
  }
  for (const n of ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]) assert.equal(signatureKind(n), "post-quantum", n);
  assert.equal(signatureKind("unknown signature"), null);
  assert.equal(signatureKind(null), null);
});

test("signature schemes map to IANA names", () => {
  const cases = {
    "ECDSA-P256-SHA256": "ecdsa_secp256r1_sha256", "ECDSA-P384-SHA384": "ecdsa_secp384r1_sha384",
    "ECDSA-P521-SHA512": "ecdsa_secp521r1_sha512", "RSA-PSS-SHA256": "rsa_pss_rsae_sha256",
    "RSA-PSS-SHA384": "rsa_pss_rsae_sha384", "RSA-PSS-SHA512": "rsa_pss_rsae_sha512",
    "RSA-PKCS1-SHA256": "rsa_pkcs1_sha256", "RSA-PKCS1-SHA384": "rsa_pkcs1_sha384",
    "RSA-PKCS1-SHA512": "rsa_pkcs1_sha512", "ECDSA-SHA1": "ecdsa_sha1", "RSA-PKCS1-SHA1": "rsa_pkcs1_sha1",
    "ML-DSA-44": "mldsa44", "ML-DSA-65": "mldsa65", "ML-DSA-87": "mldsa87",
  };
  for (const [firefox, iana] of Object.entries(cases)) assert.equal(signatureIanaName(firefox), iana, firefox);
  assert.equal(signatureIanaName("RSA-PKCS1-SHA1MD5"), null);
  assert.equal(signatureIanaName("unknown signature"), null);
});
