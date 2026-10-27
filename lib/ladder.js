import { classifyGroup, describeGroup } from "./classify.js";

// Steps a TLS setup can be on, in display order (lowest first).
// rank orders the known steps; hybrid and pure post-quantum share a rank:
// they are two post-quantum options, not one better than the other.
// "unknown" has no rank: it cannot be placed on the ladder.
export const STEPS = [
  { id: "insecure", rank: 0, label: "No HTTPS" },
  { id: "tls-legacy", rank: 1, label: "TLS 1.0/1.1" },
  { id: "tls12", rank: 2, label: "TLS 1.2" },
  { id: "tls13-classical", rank: 3, label: "TLS 1.3 · classical" },
  { id: "unknown", rank: null, label: "Not determined" },
  { id: "tls13-hybrid", rank: 4, label: "TLS 1.3 · hybrid" },
  { id: "tls13-pq", rank: 4, label: "TLS 1.3 · pure post-quantum" },
];

const STEP = Object.fromEntries(STEPS.map((s, order) => [s.id, { ...s, order }]));
const PQ_RANK = 4;

// Step of a setup ({ state, protocolVersion, keaGroupName }).
// Post-quantum groups exist only for TLS 1.3, so earlier versions are placed
// by version alone.
export function stepOf(setup) {
  if (setup.state === "insecure") return "insecure";
  switch (setup.protocolVersion) {
    case "TLSv1":
    case "TLSv1.1":
      return "tls-legacy";
    case "TLSv1.2":
      return "tls12";
    case "TLSv1.3":
      switch (classifyGroup(setup.keaGroupName).mode) {
        case "classical": return "tls13-classical";
        case "hybrid": return "tls13-hybrid";
        case "pq": return "tls13-pq";
        default: return "unknown"; // "none", "unknown group" or not reported
      }
    default:
      return "unknown"; // version "unknown" or not reported
  }
}

function withStep(setup) {
  const step = stepOf(setup);
  return { ...setup, step, group: classifyGroup(setup.keaGroupName) };
}

// Summary of a tab state:
//   main:       the page's setup with its step and group, or null.
//   setups:     every setup with its step and group, sorted by step
//               (display order), then by response count, highest first.
//   lowest:     lowest known step in the tab, or null.
//   hasUnknown: true if any setup could not be placed on the ladder.
//   warning:    true if something in the tab is, or may be, on a lower step
//               than the page: a lower known step, or an unknown setup while
//               the page is post-quantum. False if the page's step is unknown.
//   responses:  total number of responses.
export function summarize(state) {
  const setups = Object.values(state.setups)
    .map(withStep)
    .sort((a, b) => STEP[a.step].order - STEP[b.step].order || b.count - a.count);
  const main = state.mainFrame ? withStep(state.mainFrame) : null;

  const known = setups.filter((s) => STEP[s.step].rank !== null);
  const lowest = known.length
    ? known.reduce((low, s) => (STEP[s.step].rank < STEP[low].rank ? s.step : low), known[0].step)
    : null;
  const hasUnknown = setups.some((s) => s.step === "unknown");

  const mainRank = main ? STEP[main.step].rank : null;
  const warning = mainRank !== null && (
    (lowest !== null && STEP[lowest].rank < mainRank) ||
    (hasUnknown && mainRank === PQ_RANK)
  );

  return {
    main,
    setups,
    lowest,
    hasUnknown,
    warning,
    responses: setups.reduce((n, s) => n + s.count, 0),
  };
}

export function stepLabel(stepId) {
  return STEP[stepId].label;
}

// Title of a setup, e.g. "TLS 1.3 · X25519MLKEM768 · hybrid".
// For TLS 1.0/1.1 the actual version is shown.
export function setupTitle(s) {
  switch (s.step) {
    case "insecure":
      return "No HTTPS";
    case "tls-legacy":
      return s.protocolVersion === "TLSv1" ? "TLS 1.0" : "TLS 1.1";
    case "tls12":
      return "TLS 1.2" + (s.keaGroupName ? " · " + s.keaGroupName : "");
    case "tls13-classical":
      return `TLS 1.3 · ${s.keaGroupName} · classical`;
    case "tls13-hybrid":
      return `TLS 1.3 · ${s.keaGroupName} · hybrid` + (s.group.status === "obsolete" ? ", obsolete" : "");
    case "tls13-pq":
      return `TLS 1.3 · ${s.keaGroupName} · pure post-quantum`;
    default:
      return "Not determined" +
        (s.protocolVersion ? ` · ${s.protocolVersion}` : "") +
        (s.keaGroupName ? ` · ${s.keaGroupName}` : " · key exchange not reported");
  }
}

// Multi-line text summary for the console.
export function describeSummary(summary) {
  const lines = [];
  const m = summary.main;
  if (m) {
    lines.push(`This page: ${stepLabel(m.step)}`);
    if (m.step !== "insecure") {
      lines.push(`  Key exchange  ${m.keaGroupName ?? "not reported"} · ${describeGroup(m.group)}`);
      if (m.group.reference) {
        lines.push(`                ${m.group.reference} · Recommended: ${m.group.recommended}`);
      }
      lines.push(`  Cipher suite  ${m.cipherSuite ?? "not reported"}`);
      lines.push(`  Signature     ${m.signatureSchemeName ?? "not reported"}`);
    }
  } else {
    lines.push("This page: not seen");
  }

  lines.push(`TLS setups in this tab (${summary.responses} responses):`);
  for (const s of summary.setups) {
    const origins = s.origins.length + (s.originsTruncated ? "+" : "");
    lines.push(`  ${setupTitle(s)}`);
    if (s.cipherSuite) lines.push(`    ${s.cipherSuite}`);
    lines.push(`    ${s.count} responses (${s.fromCache} from cache), ${origins} origin(s)`);
  }
  if (summary.warning) {
    lines.push("Warning: part of this tab is, or may be, on a lower step than the page.");
  }
  return lines.join("\n");
}
