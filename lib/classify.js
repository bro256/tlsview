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

// "NIST security category 3, FIPS 203"
function describeCategory(pq) {
  return `NIST security category ${pq.nistCategory}, ${pq.categorySource}`;
}

// Short human-readable description, e.g.
// "PQ/T hybrid: X25519 + ML-KEM-768 (PQ component: NIST security category 3,
// FIPS 203)". The category describes only the post-quantum component.
// Wording follows RFC 9794: "traditional" for non-post-quantum algorithms,
// "PQ/T hybrid" for post-quantum + traditional.
export function describeGroup(result) {
  switch (result.mode) {
    case "classical":
      return "traditional" + (result.classical ? ": " + result.classical : "");
    case "hybrid":
      return `PQ/T hybrid: ${result.classical} + ${result.pq.alg}` +
        ` (PQ component: ${describeCategory(result.pq)})` +
        (result.status === "obsolete" ? ", obsolete" : "");
    case "pq":
      return `pure post-quantum: ${result.pq.alg} (${describeCategory(result.pq)})`;
    case "none":
      return "no key exchange group";
    default:
      return "unknown";
  }
}
