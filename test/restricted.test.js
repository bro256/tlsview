import { test } from "node:test";
import assert from "node:assert/strict";
import { isRestrictedUrl } from "../lib/restricted.js";

test("restricted hosts match exactly", () => {
  assert.equal(isRestrictedUrl("https://addons.mozilla.org/en-US/firefox/"), true);
  assert.equal(isRestrictedUrl("https://support.mozilla.org/kb/x"), true);
  assert.equal(isRestrictedUrl("https://www.mozilla.org/"), false);
  assert.equal(isRestrictedUrl("https://addons.mozilla.org.example/"), false);
  assert.equal(isRestrictedUrl("https://sub.addons.mozilla.org/"), false);
  assert.equal(isRestrictedUrl("not a url"), false);
});
