import { buildView, plural } from "../lib/view.js";

// The popup shows the active tab's record, read from storage.session, where
// background.js keeps it. It updates live while the page is still loading.
//
// All text from websites (URLs, names) is set with textContent, never as
// HTML, so a page cannot inject markup into the popup.

// Must match background.js and "host_permissions" in manifest.json.
const HOST_PERMISSIONS = { origins: ["*://*/*"] };
const STORAGE_PREFIX = "tab:";

const content = document.getElementById("content");
const originEl = document.getElementById("origin");

// Setups the user has expanded, kept across live updates.
const expanded = new Set();

function el(tag, props = {}, children = []) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (key === "text") node.textContent = value;
    else if (key === "className") node.className = value;
    else node.setAttribute(key, value);
  }
  for (const child of children) if (child) node.append(child);
  return node;
}

// Icon paths in the view are relative to the extension root.
const iconSrc = (path) => "../" + path;

function renderMessage(message, hint, extra) {
  content.replaceChildren(el("div", { className: "message" }, [
    el("p", { text: message }),
    hint && el("p", { className: "hint", text: hint }),
    extra,
  ]));
}

// Text with names kept on one line: hyphenated words (ML-KEM-768) and RFC
// numbers (RFC 10024). The characters are unchanged, so copied text still
// has normal hyphens and spaces.
function keepNamesTogether(text) {
  return (text.match(/RFC \d+[;,)]?|\S+|\s+/g) ?? []).map((part) =>
    part.includes("-") || part.startsWith("RFC ")
      ? el("span", { className: "nowrap", text: part })
      : document.createTextNode(part));
}

function renderPage(page) {
  const rows = [];
  for (const [term, value] of page.rows) {
    const mono = term === "Key exchange" || term === "Cipher suite" || term === "Signature scheme";
    rows.push(el("dt", { text: term }), el("dd", { className: mono ? "mono" : "" }, keepNamesTogether(value)));
  }
  return el("section", {}, [
    el("h2", {}, [el("span", { text: "This page" })]),
    el("div", { className: "page-head" }, [
      el("img", { src: iconSrc(page.icon), alt: "" }),
      el("span", { className: "label", text: page.headline }),
    ]),
    el("dl", {}, rows),
  ]);
}

function renderWarnings(warnings) {
  if (!warnings.length) return null;
  return el("div", { className: "warnings", role: "status" },
    warnings.map((w) => el("p", { text: "Warning: " + w })));
}

function renderSetup(setup) {
  let meta = `${plural(setup.count, "response")} · ` +
    `${plural(setup.origins, "origin")}${setup.originsTruncated ? "+" : ""}`;
  if (setup.fromCache) meta += ` · ${setup.fromCache} from cache`;

  const urls = setup.urls.map((u) => el("li", { text: u }));
  if (setup.urlsTruncated) {
    urls.push(el("li", { className: "note", text: `List limited to the first ${setup.urls.length} URLs.` }));
  }

  const details = el("details", {}, [
    el("summary", {}, [
      el("img", { src: iconSrc(setup.icon), alt: "" }),
      el("span", { className: "text" }, [
        el("div", { className: "title", text: setup.title }),
        setup.cipherSuite && el("div", { className: "cipher", text: setup.cipherSuite }),
        el("div", { className: "meta", text: meta }),
      ]),
      el("span", { className: "chevron", "aria-hidden": "true", text: "›" }),
    ]),
    el("ul", { className: "urls" }, urls),
  ]);
  if (expanded.has(setup.title)) details.open = true;
  details.addEventListener("toggle", () => {
    if (details.open) expanded.add(setup.title);
    else expanded.delete(setup.title);
  });
  return el("li", {}, [details]);
}

function renderView(view) {
  originEl.textContent = view.origin ?? "";
  if (view.status !== "ok") {
    renderMessage(view.message, view.hint);
    return;
  }
  content.replaceChildren(
    renderPage(view.page),
    renderWarnings(view.warnings) ?? "",
    el("section", {}, [
      el("h2", {}, [
        el("span", { text: "TLS setups in this tab" }),
        el("span", { className: "count", text: plural(view.responses, "response") }),
      ]),
      el("ul", { className: "setups" }, view.setups.map(renderSetup)),
    ]),
  );
}

function renderPermissionRequest() {
  const button = el("button", { type: "button", text: "Allow access to all sites" });
  // permissions.request() needs a user action, such as this click.
  button.addEventListener("click", () => {
    browser.permissions.request(HOST_PERMISSIONS).then((granted) => {
      if (granted) renderMessage("Access granted.", "Reload the page to check it.");
    });
  });
  renderMessage(
    "TLSView needs access to all sites to read their TLS details.",
    "Nothing is collected or sent anywhere.",
    button,
  );
}

async function start() {
  if (!(await browser.permissions.contains(HOST_PERMISSIONS))) {
    renderPermissionRequest();
    return;
  }
  const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
  const key = STORAGE_PREFIX + tab.id;

  async function update() {
    const stored = await browser.storage.session.get(key);
    renderView(buildView(stored[key], tab.url));
  }

  // Live updates while the popup is open and the page keeps loading.
  browser.storage.onChanged.addListener((changes, area) => {
    if (area === "session" && key in changes) update();
  });
  await update();
}

start();
