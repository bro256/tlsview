import { classifyGroup, isRsaKeyTransport } from "./classify.js";

// Steps a TLS setup can be on, in display order (lowest first).
// rank orders the known steps. PQ/T hybrid ranks above pure post-quantum:
// it keeps a traditional component if the post-quantum one fails.
// "unknown" has no rank: it cannot be placed on the ladder.
// Labels follow RFC 9794 ("traditional", "PQ/T hybrid").
export const STEPS = [
  { id: "insecure", rank: 0, label: "No HTTPS" },
  { id: "tls-legacy", rank: 1, label: "TLS 1.0/1.1" },
  { id: "tls12", rank: 2, label: "TLS 1.2" },
  { id: "tls13-classical", rank: 3, label: "TLS 1.3 · traditional" },
  { id: "unknown", rank: null, label: "Not determined" },
  { id: "tls13-pq", rank: 4, label: "TLS 1.3 · pure post-quantum" },
  { id: "tls13-hybrid", rank: 5, label: "TLS 1.3 · PQ/T hybrid" },
];

const STEP = Object.fromEntries(STEPS.map((s, order) => [s.id, { ...s, order }]));

// Step of a setup ({ state, protocolVersion, keaGroupName }).
// Post-quantum groups exist only for TLS 1.3, so earlier versions are placed
// by version alone.
export function stepOf(setup) {
  // An https response reported without TLS is not plain HTTP: not rated.
  if (setup.state === "insecure") return setup.missingTls ? "unknown" : "insecure";
  switch (setup.protocolVersion) {
    case "TLSv1":
    case "TLSv1.1":
      return "tls-legacy";
    case "TLSv1.2":
      return "tls12";
    case "TLSv1.3":
      switch (classifyGroup(setup.keaGroupName).mode) {
        case "classical": return "tls13-classical";
        // An obsolete group (pre-standard Kyber) cannot be negotiated by
        // current Firefox, so it is not rated.
        case "hybrid": return classifyGroup(setup.keaGroupName).status === "obsolete"
          ? "unknown"
          : "tls13-hybrid";
        case "pq": return "tls13-pq";
        default: return "unknown"; // "none", "unknown group" or not reported
      }
    default:
      return "unknown"; // version "unknown" or not reported
  }
}

export function rankOf(stepId) {
  return STEP[stepId].rank;
}

function withStep(setup) {
  const step = stepOf(setup);
  return { ...setup, step, group: classifyGroup(setup.keaGroupName) };
}

// Summary of a tab state:
//   main:        the page's setup with its step and group, or null.
//   setups:      every setup with its step and group, sorted by step
//                (display order), then by response count, highest first.
//   lowest:      lowest known step in the tab, or null.
//   hasUnknown:  true if any setup could not be placed on the ladder.
//   lowerStep:   true if any setup has a lower rank than the page.
//   notChecked:  true if any setup is unknown, unless the page itself is
//                unknown or has no HTTPS.
//   warning:     lowerStep or notChecked.
//   responses:   total number of responses.
// Without a page (main null) there is nothing to compare: no warning.
export function summarize(state) {
  const setups = Object.values(state.setups)
    .map(withStep)
    .sort((a, b) => STEP[a.step].order - STEP[b.step].order || b.count - a.count);
  const main = state.mainFrame ? withStep(state.mainFrame) : null;

  const known = setups.filter((s) => rankOf(s.step) !== null);
  const lowest = known.length
    ? known.reduce((low, s) => (rankOf(s.step) < rankOf(low) ? s.step : low), known[0].step)
    : null;
  const hasUnknown = setups.some((s) => s.step === "unknown");

  const mainRank = main ? rankOf(main.step) : null;
  const lowerStep = mainRank !== null && lowest !== null && rankOf(lowest) < mainRank;
  const notChecked = main !== null && hasUnknown &&
    main.step !== "unknown" && main.step !== "insecure";

  return {
    main,
    setups,
    lowest,
    hasUnknown,
    lowerStep,
    notChecked,
    warning: lowerStep || notChecked,
    responses: setups.reduce((n, s) => n + s.count, 0),
  };
}

export const WARNING_NOT_CHECKED = "Warning: some responses in this tab could not be checked";

// Levels below the page's that responses in the tab used, lowest first,
// e.g. ["TLS 1.2", "TLS 1.3 · traditional"]. TLS 1.0 and 1.1 share a level
// but are named by their actual version, TLS 1.0 first.
export function lowerLevels(summary) {
  const mainRank = summary.main ? rankOf(summary.main.step) : null;
  if (mainRank === null) return [];
  const found = new Map(); // label -> sort key
  for (const s of summary.setups) {
    const rank = rankOf(s.step);
    if (rank === null || rank >= mainRank) continue;
    if (s.step === "tls-legacy") {
      const tls10 = s.protocolVersion === "TLSv1";
      found.set(tls10 ? "TLS 1.0" : "TLS 1.1", rank + (tls10 ? 0 : 0.5));
    } else {
      found.set(stepLabel(s.step), rank);
    }
  }
  return [...found].sort((a, b) => a[1] - b[1]).map(([label]) => label);
}

export function warningLines(summary) {
  const lines = [];
  if (summary.lowerStep) {
    lines.push(`Warning: some responses in this tab used a lower level than the page: ${lowerLevels(summary).join(", ")}`);
  }
  if (summary.notChecked) lines.push(WARNING_NOT_CHECKED);
  return lines;
}

export function stepLabel(stepId) {
  return STEP[stepId].label;
}

// Title of a setup, e.g. "TLS 1.3 · X25519MLKEM768 · PQ/T hybrid".
// Groups are shown by IANA name; a name the registry does not know is shown
// as Firefox reported it. For TLS 1.0/1.1 the actual version is shown.
export function setupTitle(s) {
  const group = s.group.name ?? s.keaGroupName;
  switch (s.step) {
    case "insecure":
      return "No HTTPS";
    case "tls-legacy":
      return s.protocolVersion === "TLSv1" ? "TLS 1.0" : "TLS 1.1";
    case "tls12":
      if (isRsaKeyTransport(s)) return "TLS 1.2 · RSA key transport";
      return "TLS 1.2" + (group ? " · " + group : "");
    case "tls13-classical":
      return `TLS 1.3 · ${group} · traditional`;
    case "tls13-hybrid":
      return `TLS 1.3 · ${group} · PQ/T hybrid`;
    case "tls13-pq":
      return `TLS 1.3 · ${group} · pure post-quantum`;
    default:
      if (s.missingTls) return "Not determined · HTTPS without TLS details";
      if (s.group.status === "obsolete") {
        return `Not determined · ${s.protocolVersion} · ${s.group.name} (obsolete)`;
      }
      return "Not determined" +
        (s.protocolVersion ? ` · ${s.protocolVersion}` : "") +
        (s.keaGroupName ? ` · ${s.keaGroupName}` : " · key exchange not reported");
  }
}
