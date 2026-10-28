// Hosts on which Firefox lets no extension see requests or run scripts.
// Default of the Firefox preference extensions.webextensions.restrictedDomains
// (modules/libpref/init/all.js). Firefox matches the host exactly.
// Users can change the preference, and Firefox can also quarantine further
// domains remotely; neither can be read by an extension.
export const RESTRICTED_HOSTS = new Set([
  "accounts-static.cdn.mozilla.net",
  "accounts.firefox.com",
  "addons.cdn.mozilla.net",
  "addons.mozilla.org",
  "api.accounts.firefox.com",
  "content.cdn.mozilla.net",
  "discovery.addons.mozilla.org",
  "oauth.accounts.firefox.com",
  "profile.accounts.firefox.com",
  "support.mozilla.org",
  "sync.services.mozilla.com",
]);

export function isRestrictedUrl(url) {
  try {
    return RESTRICTED_HOSTS.has(new URL(url).hostname);
  } catch {
    return false;
  }
}
