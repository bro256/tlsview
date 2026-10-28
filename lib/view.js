import { summarize, stepLabel, setupTitle, warningLines } from "./ladder.js";
import { describeGroup } from "./classify.js";
import { originOf } from "./tabstate.js";
import { stepIconPath } from "./icon.js";

// Everything the popup shows for one tab, as plain data. The popup only
// renders it, so all wording and decisions are here and unit-tested.
//
// buildView(state, tabUrl) returns one of:
//   { status: "not-inspectable", message, hint }
//   { status: "not-seen", origin, message, hint }
//   { status: "ok", origin, page, warnings, setups, responses }
//
// Icon paths are relative to the extension root.

const PROTOCOL = {
  "TLSv1": "TLS 1.0",
  "TLSv1.1": "TLS 1.1",
  "TLSv1.2": "TLS 1.2",
  "TLSv1.3": "TLS 1.3",
};

export function protocolLabel(version) {
  if (!version) return "not reported";
  return PROTOCOL[version] ?? version;
}

// "[RFC 9846]; [RFC 8422]" -> "RFC 9846; RFC 8422"
export function referenceLabel(reference) {
  return reference.replace(/[[\]]/g, "");
}

// Key exchange as "IANA name (Firefox name)", or the reported name alone
// when the registry does not know it.
function keyExchangeLabel(main) {
  if (!main.keaGroupName) return "not reported";
  const iana = main.group.name;
  if (!iana) return main.keaGroupName;
  return iana === main.keaGroupName ? iana : `${iana} (${main.keaGroupName})`;
}

function pageView(main) {
  const view = {
    icon: stepIconPath(main.step, main.protocolVersion),
    label: stepLabel(main.step),
    rows: [],
  };
  if (main.step === "insecure") {
    view.rows.push(["Encryption", "Not encrypted (no HTTPS)"]);
    return view;
  }
  view.rows.push(["Protocol", protocolLabel(main.protocolVersion)]);
  view.rows.push(["Key exchange", keyExchangeLabel(main)]);
  if (main.group.mode !== "unknown") {
    view.rows.push(["Type", describeGroup(main.group)]);
  }
  if (main.group.reference) {
    view.rows.push(["IANA", `Recommended: ${main.group.recommended} · ${referenceLabel(main.group.reference)}`]);
  }
  view.rows.push(["Cipher suite", main.cipherSuite ?? "not reported"]);
  view.rows.push(["Signature", main.signatureSchemeName ?? "not reported"]);
  return view;
}

function setupView(s) {
  return {
    icon: stepIconPath(s.step, s.protocolVersion),
    title: setupTitle(s),
    cipherSuite: s.cipherSuite,
    count: s.count,
    fromCache: s.fromCache,
    origins: s.origins.length,
    originsTruncated: s.originsTruncated,
    urls: s.urls,
    urlsTruncated: s.urlsTruncated,
  };
}

export function buildView(state, tabUrl) {
  const tabOrigin = tabUrl ? originOf(tabUrl) : null;
  if (!tabOrigin) {
    return {
      status: "not-inspectable",
      message: "This page cannot be inspected.",
      hint: "TLSView checks http and https pages only.",
    };
  }
  // No record, or a record of an earlier page (see the origin check in
  // background.js): nothing to show for this page.
  if (!state || !state.mainFrame || state.pageOrigin !== tabOrigin) {
    return {
      status: "not-seen",
      origin: tabOrigin,
      message: "The page itself was not seen.",
      hint: "Reload the page to check it.",
    };
  }

  const summary = summarize(state);
  return {
    status: "ok",
    origin: state.pageOrigin,
    page: pageView(summary.main),
    warnings: warningLines(summary).map((line) => line.replace(/^Warning: /, "")),
    setups: summary.setups.map(setupView),
    responses: summary.responses,
  };
}

// "1 response", "3 responses"
export function plural(n, word) {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}
