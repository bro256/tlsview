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
