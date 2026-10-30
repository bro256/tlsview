import { warningLines } from "./ladder.js";
import { isRsaKeyTransport } from "./classify.js";
import { headline } from "./view.js";

// Toolbar icon and tooltip for a tab summary (see lib/ladder.js).
//
// The icon shows the page's own ladder step; its warning variant (a corner
// mark) is used when the summary's warning is set. The tooltip repeats the
// popup's headline, then the key exchange and cipher suite, then any
// warnings. Returns { path, title }.
//
// Icon colours: red = no HTTPS or deprecated TLS; yellow = secure today,
// not post-quantum; green "PQ" = PQ/T hybrid; lavender "PQ" = pure
// post-quantum; grey = unknown. Both post-quantum icons carry atom orbits.

export const PLAIN_ICON = "icons/icon.svg";

const ICON_FILE = {
  "insecure": "insecure",
  "tls-legacy": null, // "tls10" or "tls11", by version
  "tls12": "tls12",
  "tls13-classical": "tls13",
  "unknown": "unknown",
  "tls13-pq": "pq",
  "tls13-hybrid": "pqt",
};

// Steps whose icon has no warning variant: nothing is lower than "No HTTPS",
// and an unknown page has nothing to compare against.
const NO_WARNING_VARIANT = new Set(["insecure", "unknown"]);

export const NOT_INSPECTABLE = {
  path: PLAIN_ICON,
  title: "TLSView: this page cannot be inspected",
};

// Sites on which Firefox hides all requests from extensions (lib/restricted.js).
export const RESTRICTED = {
  path: PLAIN_ICON,
  title: "TLSView: Firefox does not let extensions inspect this site",
};

// Path of the icon for a step, relative to the extension root.
// protocolVersion picks TLS 1.0 or 1.1 for "tls-legacy".
export function stepIconPath(step, protocolVersion, warning = false) {
  const file = ICON_FILE[step] ?? (protocolVersion === "TLSv1" ? "tls10" : "tls11");
  const warn = warning && !NO_WARNING_VARIANT.has(step);
  return `icons/step-${file}${warn ? "-warn" : ""}.svg`;
}

function iconPath(main, warning) {
  return stepIconPath(main.step, main.protocolVersion, warning);
}

function unknownDetail(main) {
  if (main.missingTls) return "HTTPS, but Firefox reported no TLS details";
  if (main.protocolVersion !== "TLSv1.3") return "TLS version not reported";
  if (main.keaGroupName === null) return "TLS 1.3, group not reported";
  if (main.keaGroupName === "none") return "TLS 1.3, no key exchange group";
  if (main.group.status === "obsolete") {
    return `TLS 1.3, obsolete group: ${main.group.name} (not supported by current Firefox)`;
  }
  return `TLS 1.3, group not recognised: ${main.keaGroupName}`;
}

// Key exchange as shown in the tooltip: IANA group name, Firefox's
// description for its special values, or RSA key transport.
function keyExchangeLine(main) {
  if (isRsaKeyTransport(main)) return "RSA key transport (no forward secrecy)";
  return main.group.name ?? main.group.description ?? main.keaGroupName ?? "not reported";
}

// Tooltip: the popup's headline, then the key exchange and the cipher suite,
// or the reason a page could not be rated.
function tooltipLines(main) {
  switch (main.step) {
    case "insecure":
      return [headline(main)];
    case "unknown":
      return [headline(main), unknownDetail(main)];
    default:
      return [
        headline(main),
        `Key exchange: ${keyExchangeLine(main)}`,
        `Cipher suite: ${main.cipherSuite ?? "not reported"}`,
      ];
  }
}

export function iconFor(summary) {
  const main = summary.main;
  if (!main) {
    return {
      path: PLAIN_ICON,
      title: summary.setups.length
        ? "TLSView: the page itself was not seen. Reload the page to check it."
        : "TLSView: nothing recorded in this tab",
    };
  }
  return {
    path: iconPath(main, summary.warning),
    title: [...tooltipLines(main), ...warningLines(summary)].join("\n"),
  };
}
