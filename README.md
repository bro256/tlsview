# TLSView

Firefox extension for checking which TLS key exchange a site uses: classical, hybrid post-quantum, or pure post-quantum (ML-KEM).

**Status:** early development. The extension currently does nothing visible beyond logging to the console.

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
```

## Privacy

The extension collects and transmits no data (`data_collection_permissions: none`).
