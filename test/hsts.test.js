import { test } from "node:test";
import assert from "node:assert/strict";
import { hstsHeaderOf, parseHsts, describeHsts } from "../lib/hsts.js";

test("finds the header by case-insensitive name", () => {
  assert.equal(hstsHeaderOf([{ name: "Content-Type", value: "text/html" }, { name: "Strict-Transport-Security", value: "max-age=1" }]), "max-age=1");
  assert.equal(hstsHeaderOf([{ name: "content-type", value: "text/html" }]), null);
  assert.equal(hstsHeaderOf(undefined), null);
});

test("parses valid headers", () => {
  assert.deepEqual(parseHsts("max-age=31536000"), { maxAge: 31536000, includeSubDomains: false, preload: false });
  assert.deepEqual(parseHsts("Max-Age=10 ; IncludeSubDomains;preload"), { maxAge: 10, includeSubDomains: true, preload: true });
  assert.deepEqual(parseHsts('max-age="300"'), { maxAge: 300, includeSubDomains: false, preload: false });
  assert.deepEqual(parseHsts("max-age=1;"), { maxAge: 1, includeSubDomains: false, preload: false });
  assert.deepEqual(parseHsts("max-age=1; unknown=x"), { maxAge: 1, includeSubDomains: false, preload: false });
});

test("rejects headers Firefox ignores", () => {
  for (const h of [
    "", "includeSubDomains", "max-age", "max-age=", "max-age=-1", "max-age=1.5", "max-age=1x",
    "max-age=1; max-age=2", "max-age=1; includeSubDomains; includeSubDomains",
    "max-age=1; includeSubDomains=yes", 'max-age="1', "max-age=1, max-age=2",
    "max-age=18446744073709551616",
  ]) {
    assert.equal(parseHsts(h), null, h);
  }
});

test("describes the HSTS state", () => {
  assert.equal(describeHsts(false, "max-age=86400"), "Header sent: max-age=86400 (1 day)");
  assert.equal(describeHsts(true, "max-age=0"), "Header sent: max-age=0 (the site turns HSTS off)");
  assert.equal(describeHsts(false, "max-age=x"), "Header sent, but invalid (Firefox ignores it)");
  assert.equal(describeHsts(true, null), "Known to Firefox; no header in this response");
  assert.equal(describeHsts(false, null), "Not used");
  assert.equal(describeHsts(null, null), "not reported");
});
