import { test } from "node:test";
import assert from "node:assert/strict";
import { parseDn, commonNameOf, displayName, localRootOf, MAX_NAME } from "../lib/certroot.js";

const leaf = { subject: "CN=www.example.com", isBuiltInRoot: false };
const root = (subject, isBuiltInRoot) => ({ subject, isBuiltInRoot });
const info = (certificates, extra = {}) => ({ state: "secure", certificates, ...extra });

test("parseDn splits on commas and plus signs outside quotes", () => {
  assert.deepEqual(parseDn('CN=Contoso Root CA,O="Contoso, Ltd",C=LT'), [
    ["CN", "Contoso Root CA"], ["O", "Contoso, Ltd"], ["C", "LT"],
  ]);
  assert.deepEqual(parseDn("CN=A+OU=B,O=C"), [["CN", "A"], ["OU", "B"], ["O", "C"]]);
  assert.deepEqual(parseDn("CN=a\\,b,O=c"), [["CN", "a,b"], ["O", "c"]]);
  assert.deepEqual(parseDn('CN="say \\"hi\\""'), [["CN", 'say "hi"']]);
});

test("commonNameOf finds the first CN, or null", () => {
  assert.equal(commonNameOf("CN=Contoso Root CA,O=Contoso"), "Contoso Root CA");
  assert.equal(commonNameOf("O=Contoso,cn=lower case"), "lower case");
  assert.equal(commonNameOf("2.5.4.3=By OID,O=x"), "By OID");
  assert.equal(commonNameOf("OU=No CN,O=Contoso"), null);
  assert.equal(commonNameOf(undefined), null);
});

test("displayName removes control characters and cuts long names", () => {
  assert.equal(displayName("Evil\nWarning: fake line"), "Evil Warning: fake line");
  assert.equal(displayName("   "), null);
  const long = displayName("x".repeat(200));
  assert.equal(long.length, MAX_NAME);
  assert.ok(long.endsWith("..."));
});

test("a root added to this computer is reported with its common name", () => {
  assert.deepEqual(localRootOf(info([leaf, root("CN=Contoso Root CA,O=Contoso", false)])),
    { commonName: "Contoso Root CA" });
  assert.deepEqual(localRootOf(info([leaf, root("O=Contoso", false)])), { commonName: null });
});

test("a built-in root is not reported", () => {
  assert.equal(localRootOf(info([leaf, root("CN=ISRG Root X1", true)])), null);
});

test("no verdict without a verified chain", () => {
  // Firefox's fallback when it has no chain: the server certificate only.
  assert.equal(localRootOf(info([leaf])), null);
  assert.equal(localRootOf(info(undefined)), null);
  assert.equal(localRootOf(info([leaf, root("CN=X", undefined)])), null);
  // An overridden certificate error: the chain was not verified.
  for (const flag of ["isUntrusted", "isDomainMismatch", "isNotValidAtThisTime"]) {
    assert.equal(localRootOf(info([leaf, root("CN=X", false)], { [flag]: true })), null, flag);
  }
});
