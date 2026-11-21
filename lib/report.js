import { countsLine } from "./view.js";

// Plain-text report of a tab, for pasting into a ticket, a mail or notes.
// Built from the same view the popup shows (lib/view.js), so it contains
// exactly what is on screen: origins only, never paths or queries.
//
//   view: buildView() result with status "ok".
//   meta: { version, firefox, time } - TLSView version, Firefox version
//         (or null) and the time of the report as a Date.
// Returns the text, lines separated by "\n".
export function reportText(view, meta) {
  const lines = [
    "TLSView report",
    `Page: ${view.origin}`,
    // Seconds are enough; the time is in UTC ("Z").
    `Time: ${meta.time.toISOString().replace(/\.\d+Z$/, "Z")}`,
    `Checked with: ${meta.firefox ? `Firefox ${meta.firefox}, ` : ""}TLSView ${meta.version}`,
    "",
    `This page: ${view.page.headline}`,
  ];
  for (const section of view.page.sections) {
    lines.push(`  ${section.title}`);
    for (const [term, value] of section.rows) lines.push(`    ${term}: ${value}`);
  }
  if (view.warnings.length) {
    lines.push("", "Warnings:");
    for (const warning of view.warnings) lines.push(`  - ${warning}`);
  }
  lines.push(
    "",
    `TLS setups in this tab: ${countsLine(view.origins, view.originsMore, view.responses, view.fromCache)}`,
  );
  for (const setup of view.setups) {
    lines.push(
      "",
      `  ${setup.title}`,
      `    Cipher suite: ${setup.cipherSuite ?? "not reported"}`,
      `    ${countsLine(setup.origins.length, setup.unlisted > 0, setup.count, setup.fromCache)}`,
    );
    if (setup.certErrors > 0) {
      lines.push(`    ${setup.certErrors} with an overridden certificate error`);
    }
    for (const origin of setup.origins) lines.push(`      ${origin.name}  ${origin.count}`);
    if (setup.unlisted) lines.push(`      further origins, not listed  ${setup.unlisted}`);
  }
  lines.push(
    "",
    "Only the key exchange is rated. Certificates are not validated by TLSView.",
    "A response from cache shows the connection that originally fetched it.",
  );
  return lines.join("\n");
}
