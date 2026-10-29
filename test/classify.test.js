import { test } from "node:test";
import assert from "node:assert/strict";
import { GROUPS, FIREFOX_SPECIAL } from "../lib/groups.js";
import { classifyGroup } from "../lib/classify.js";

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
