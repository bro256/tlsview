// TLS key exchange groups.
//
// Scope: every IANA TLS Supported Group with a named case in
// getKeaGroupName() (security/manager/ssl/nsNSSCallbacks.cpp in the Firefox
// source). For any value not handled by getKeaGroupName(), the function
// returns "unknown group".
// Special values "none" and "custom" are documented separately below.
// Being named there does not mean Firefox offers or can negotiate a group.
//
// From the IANA "TLS Supported Groups" registry's CSV export (last updated
// 2026-10-21), as written there:
//   name:        Description column, without the " (OBSOLETE)" suffix.
//   codepoint:   Value column.
//   recommended: Recommended column. Values defined in RFC 9847, Section 3:
//     "Y": the IETF has consensus that the item is RECOMMENDED.
//     "N": the item has not been evaluated by the IETF; the IETF has made
//          no statement about its suitability. This does not necessarily
//          mean the mechanism is flawed, only that no consensus exists.
//     "D": the item is discouraged.
//   reference:   Reference column.
// https://www.iana.org/assignments/tls-parameters/
//
// Added by TLSView:
//   mode:      "classical" (no post-quantum component), "hybrid" (classical
//              + post-quantum) or "pq" (post-quantum only).
//   classical: classical component.
//   pq:        post-quantum component:
//     alg:            algorithm.
//     nistCategory:   security category (1 to 5) as defined by NIST for its
//                     post-quantum standardization process.
//     categorySource: who states the category for this algorithm.
//       "FIPS 203": stated by NIST in FIPS 203 (ML-KEM-512 = 1,
//                   ML-KEM-768 = 3, ML-KEM-1024 = 5).
//       "claimed in the round-3 submission": claimed by the submitters of
//                   round-3 Kyber, which is not FIPS 203 ML-KEM and was not
//                   standardized by NIST.
//   status:    "rfc" (reference includes a published RFC that defines the
//              group), "draft" (Internet-Draft only) or "obsolete"
//              (description marked "(OBSOLETE)" by IANA).
//   firefox:   the name getKeaGroupName() returns for this group.

export const GROUPS = [
  // Classical: elliptic curves
  {
    name: "secp256r1", codepoint: 23, recommended: "Y", reference: "[RFC 8422]",
    mode: "classical", classical: "P-256", pq: null, status: "rfc", firefox: "P256",
  },
  {
    name: "secp384r1", codepoint: 24, recommended: "Y", reference: "[RFC 8422]",
    mode: "classical", classical: "P-384", pq: null, status: "rfc", firefox: "P384",
  },
  {
    name: "secp521r1", codepoint: 25, recommended: "N", reference: "[RFC 8422]",
    mode: "classical", classical: "P-521", pq: null, status: "rfc", firefox: "P521",
  },
  {
    name: "x25519", codepoint: 29, recommended: "Y", reference: "[RFC 9846]; [RFC 8422]",
    mode: "classical", classical: "X25519", pq: null, status: "rfc", firefox: "x25519",
  },

  // Classical: finite field Diffie-Hellman
  {
    name: "ffdhe2048", codepoint: 256, recommended: "N", reference: "[RFC 7919]",
    mode: "classical", classical: "FFDHE-2048", pq: null, status: "rfc", firefox: "FF 2048",
  },
  {
    name: "ffdhe3072", codepoint: 257, recommended: "N", reference: "[RFC 7919]",
    mode: "classical", classical: "FFDHE-3072", pq: null, status: "rfc", firefox: "FF 3072",
  },

  // Post-quantum only: ML-KEM (FIPS 203)
  {
    name: "MLKEM1024", codepoint: 514, recommended: "N", reference: "[RFC-ietf-tls-mlkem-10]",
    mode: "pq", classical: null,
    pq: { alg: "ML-KEM-1024", nistCategory: 5, categorySource: "FIPS 203" },
    status: "draft", firefox: "mlkem1024",
  },

  // Hybrid: ECDHE + ML-KEM
  {
    name: "SecP256r1MLKEM768", codepoint: 4587, recommended: "N", reference: "[RFC 10024]",
    mode: "hybrid", classical: "P-256",
    pq: { alg: "ML-KEM-768", nistCategory: 3, categorySource: "FIPS 203" },
    status: "rfc", firefox: "secp256r1mlkem768",
  },
  {
    name: "X25519MLKEM768", codepoint: 4588, recommended: "Y", reference: "[RFC 10024]",
    mode: "hybrid", classical: "X25519",
    pq: { alg: "ML-KEM-768", nistCategory: 3, categorySource: "FIPS 203" },
    status: "rfc", firefox: "mlkem768x25519",
  },
  {
    name: "SecP384r1MLKEM1024", codepoint: 4589, recommended: "N", reference: "[RFC 10024]",
    mode: "hybrid", classical: "P-384",
    pq: { alg: "ML-KEM-1024", nistCategory: 5, categorySource: "FIPS 203" },
    status: "rfc", firefox: "secp384r1mlkem1024",
  },

  // Hybrid: ECDHE + round-3 Kyber (pre-standard)
  {
    // NSS (Firefox's TLS library) has removed round-3 Kyber: the identifier
    // remains only in the SSLNamedGroup enum (security/nss/lib/ssl/sslt.h,
    // "round-3 Kyber removed; value retained for ABI"). getKeaGroupName()
    // still maps it to "xyber768d00".
    name: "X25519Kyber768Draft00", codepoint: 25497, recommended: "D",
    reference: "[draft-tls-westerbaan-xyber768d00-02]; [RFC 10024]",
    mode: "hybrid", classical: "X25519",
    pq: {
      alg: "Kyber768 (round 3)", nistCategory: 3,
      categorySource: "claimed in the round-3 submission",
    },
    status: "obsolete", firefox: "xyber768d00",
  },
];

// Names getKeaGroupName() returns for NSS special values, which are not
// IANA groups (security/nss/lib/ssl: sslinfo.c, ssl3con.c).
//   "none":   NSS has no key exchange group for the connection,
//             e.g. TLS 1.2 static RSA key exchange.
//   "custom": TLS 1.2 DHE where the server's prime and generator match
//             no RFC 7919 group.
// "unknown group", returned for any other value, is classified as unknown.
export const FIREFOX_SPECIAL = {
  none: { mode: "none", description: "No key exchange group" },
  custom: { mode: "classical", description: "Finite field DH with a custom prime" },
};
