# TLSView

Firefox extension for checking which TLS version and key exchange a site uses: traditional, PQ/T hybrid, or pure post-quantum (ML-KEM).

**Status:** early development. The toolbar icon shows the page's TLS version and key exchange; the popup lists the TLS setups of every response in the tab. For the page itself, the popup also shows HSTS, without rating it.

## Requirements

- Firefox 140 or later (desktop), 142 or later (Android)
- Node.js, only for development tooling

## Run from source

Option A, no tooling:

1. Open `about:debugging#/runtime/this-firefox`.
2. Click **Load Temporary Add-on…** and select `manifest.json`.

Option B, with [web-ext](https://github.com/mozilla/web-ext):

```sh
npm install
npm start        # launches a clean Firefox profile with the extension loaded
npm run lint     # checks the extension with Mozilla's addons-linter
npm run build    # writes a .zip to web-ext-artifacts/
npm test         # runs unit tests (Node.js 22 or later)
```

## Known limitations

- Only responses Firefox reports to extensions are seen. Firefox hides all requests on some Mozilla sites, such as addons.mozilla.org, from extensions.
- A page restored from the back/forward cache sends no requests. If it has the same origin as the page shown before it, the details of that earlier page are shown.
- Responses that arrive late from a previous page of the same origin are counted for the current page.

## Privacy

The extension collects and transmits no data (`data_collection_permissions: none`).
