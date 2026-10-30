import { GROUPS, FIREFOX_SPECIAL } from "./groups.js";

// Lookup table from lowercase name to registry entry, built once.
// Accepts the IANA name ("X25519MLKEM768") and Firefox names
// ("mlkem768x25519"), case-insensitively.
const BY_NAME = new Map();
for (const group of GROUPS) {
  for (const name of [group.name, group.firefox]) {
    BY_NAME.set(name.toLowerCase(), group);
  }
}

// Classifies a key exchange group name as reported by the browser.
// Returns an object with at least { input, mode }, where mode is one of
// "classical", "hybrid", "pq", "none" or "unknown".
export function classifyGroup(input) {
  if (typeof input !== "string" || input.trim() === "") {
    return { input, mode: "unknown" };
  }
  const key = input.trim().toLowerCase();

  const group = BY_NAME.get(key);
  if (group) {
    return { input, ...group };
  }

  const special = FIREFOX_SPECIAL[key];
  if (special) {
    return { input, ...special };
  }

  return { input, mode: "unknown" };
}

// TLS 1.2 and earlier with RSA key transport: the client encrypts the
// premaster secret to the server's RSA key, so there is no ephemeral key
// exchange and no forward secrecy. Firefox reports no key exchange group for
// it, so it is recognised from the cipher suite name (TLS_RSA_WITH_*).
// setup: { protocolVersion, cipherSuite } as reported by Firefox.
export function isRsaKeyTransport(setup) {
  return setup.protocolVersion !== "TLSv1.3" &&
    typeof setup.cipherSuite === "string" &&
    setup.cipherSuite.startsWith("TLS_RSA_WITH_");
}

// Whether the connection has forward secrecy: true, false, or null if it
// cannot be determined.
//   TLS 1.3: every handshake uses an ephemeral key exchange group. NSS
//     offers only psk_dhe_ke for resumption, never psk_ke.
//   Earlier: from the cipher suite name. ECDHE and DHE are ephemeral;
//     RSA key transport is not.
export function forwardSecrecy(setup) {
  if (setup.protocolVersion === "TLSv1.3") return setup.keaGroupName ? true : null;
  if (isRsaKeyTransport(setup)) return false;
  const suite = setup.cipherSuite ?? "";
  if (suite.startsWith("TLS_ECDHE_") || suite.startsWith("TLS_DHE_")) return true;
  return null;
}

// Record encryption of a cipher suite, from its name, or null if not
// recognised. TLS 1.3 names have no key exchange part ("TLS_AES_128_GCM_SHA256");
// earlier ones do ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256").
//   AEAD:       GCM, CCM, ChaCha20-Poly1305. The trailing hash is the PRF or
//               HKDF hash, not a MAC.
//   CBC + HMAC: the trailing hash is the HMAC hash ("SHA" is SHA-1).
const CIPHER = /^TLS_(?:.*_WITH_)?(AES_128|AES_256|CHACHA20|3DES_EDE)_(GCM|CCM|CCM_8|POLY1305|CBC)_(SHA|SHA256|SHA384)$/;
const BULK = { AES_128: "AES-128", AES_256: "AES-256", CHACHA20: "ChaCha20", "3DES_EDE": "3DES-EDE" };

export function recordEncryption(cipherSuite) {
  const m = typeof cipherSuite === "string" ? cipherSuite.match(CIPHER) : null;
  if (!m) return null;
  const [, bulk, mode, hash] = m;
  if (mode === "POLY1305") return "AEAD: ChaCha20-Poly1305";
  if (mode === "CBC") {
    return `CBC + HMAC: ${BULK[bulk]}-CBC, HMAC-${hash === "SHA" ? "SHA1" : hash}`;
  }
  return `AEAD: ${BULK[bulk]}-${mode.replace("_", "-")}`;
}

