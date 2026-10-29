# TLSView

Firefox extension that shows which TLS version and key exchange a site uses: traditional, PQ/T hybrid or pure post-quantum (ML-KEM).

Only the key exchange is rated. Post-quantum key exchange is designed to protect the confidentiality of recorded traffic against a future quantum computer ("harvest now, decrypt later"). It does not protect authentication: signatures and certificates are not rated.

Terms follow RFC 9794: *traditional* (not post-quantum), *post-quantum* (PQ), *PQ/T hybrid* (a PQ and a traditional algorithm combined).

## Protection levels

The toolbar icon shows the level of the connection that delivered the page itself (the main document). Higher is better.

| Icon | Level | Meaning |
|:-:|---|---|
| <img src="icons/step-pqt.svg" width="24" alt="PQT"> | TLS 1.3 · PQ/T hybrid | ML-KEM combined with ECDH. Designed to remain secure if either component remains secure. |
| <img src="icons/step-pq.svg" width="24" alt="PQ"> | TLS 1.3 · pure post-quantum | ML-KEM alone. Ranked below PQ/T hybrid: with no traditional component, its security rests on ML-KEM alone. |
| <img src="icons/step-tls13.svg" width="24" alt="1.3"> | TLS 1.3 · traditional | ECDH or finite field DH only. Not quantum-resistant. |
| <img src="icons/step-tls12.svg" width="24" alt="1.2"> | TLS 1.2 | Not quantum-resistant: Firefox offers ML-KEM groups only in TLS 1.3. |
| <img src="icons/step-tls11.svg" width="24" alt="1.1"> | TLS 1.1 | Deprecated (RFC 8996). |
| <img src="icons/step-tls10.svg" width="24" alt="1.0"> | TLS 1.0 | Deprecated (RFC 8996). |
| <img src="icons/step-insecure.svg" width="24" alt="✕"> | No HTTPS | Loaded over plain HTTP, without TLS. |
| <img src="icons/step-unknown.svg" width="24" alt="?"> | Not determined | TLS version or key exchange group not reported or not recognised. Not ranked. |

A corner mark on the icon (<img src="icons/step-pqt-warn.svg" width="20" alt="PQT with warning">) means other responses in the tab need attention:

- **Lower protection level:** at least one response in the tab is on a lower level than the page.
- **Could not be checked:** at least one response is *Not determined*. Not shown when the page itself is *Not determined* or has no HTTPS.

The tooltip names the group, e.g. `X25519MLKEM768` and `PQ/T hybrid: X25519 + ML-KEM-768, NIST security category 3 (FIPS 203)`.

## Key exchange groups

Groups are identified by their [IANA TLS Supported Groups](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8) name. The table lists every group TLSView recognises; it covers every group name current Firefox reports.

| IANA name | Firefox name | Type | Offered by Firefox |
|---|---|---|---|
| X25519MLKEM768 | `mlkem768x25519` | PQ/T hybrid, ML-KEM-768 (category 3) + X25519 | yes |
| SecP256r1MLKEM768 | `secp256r1mlkem768` | PQ/T hybrid, ML-KEM-768 (category 3) + P-256 | no |
| SecP384r1MLKEM1024 | `secp384r1mlkem1024` | PQ/T hybrid, ML-KEM-1024 (category 5) + P-384 | no |
| MLKEM1024 | `mlkem1024` | pure PQ, ML-KEM-1024 (category 5) | only with `security.tls.enable_mlkem1024` |
| X25519Kyber768Draft00 | `xyber768d00` | PQ/T hybrid with pre-standard Kyber, obsolete | no |
| x25519 | `x25519` | traditional | yes |
| secp256r1, secp384r1, secp521r1 | `P256`, `P384`, `P521` | traditional | yes |
| ffdhe2048, ffdhe3072 | `FF 2048`, `FF 3072` | traditional | only if DHE cipher suites are enabled |

Firefox also reports `none` (no key exchange group, e.g. TLS 1.2 RSA key transport) and `custom` (TLS 1.2 DHE with a prime not from RFC 7919). NIST security categories are from FIPS 203. The hybrid groups are specified in RFC 10024; MLKEM1024 in draft-ietf-tls-mlkem.

## Popup

**This page** shows the page's own connection:

| Row | Content |
|---|---|
| Protocol | TLS version |
| Key exchange | IANA group name, and Firefox's name if different |
| Key exchange type | Traditional, PQ/T hybrid or post-quantum, with the components and the specification |
| Cipher suite | As reported by Firefox, e.g. `TLS_AES_128_GCM_SHA256` |
| Signature scheme | TLS signature scheme of the handshake. Shown, not rated. |
| HSTS | The `Strict-Transport-Security` header as sent and checked with Firefox's parsing rules, or whether Firefox already knew the site as HSTS (preload list or an earlier visit). Shown, not rated. |
| Encrypted Client Hello | Whether the server accepted ECH. Shown, not rated. |

**TLS setups in this tab** groups every response in the tab by TLS version, key exchange group and cipher suite. Each setup shows its responses, distinct origins, responses served from cache, and, when expanded, the URLs.

## Install from source

Requires Firefox 140 or later (desktop) or 142 or later (Android).

1. Open `about:debugging#/runtime/this-firefox`.
2. Click **Load Temporary Add-on…** and select `manifest.json`.

Development tooling ([web-ext](https://github.com/mozilla/web-ext), Node.js 22 or later):

```sh
npm install
npm start        # runs Firefox with the extension in a clean profile
npm test         # unit tests
npm run lint     # Mozilla's addons-linter
npm run build    # packages the extension into web-ext-artifacts/
```

## Known limitations

- Firefox only. The extension uses `webRequest.getSecurityInfo()`, which other browsers do not provide.
- Firefox hides all requests on some Mozilla sites, such as addons.mozilla.org, from extensions. These sites cannot be inspected.
- A page restored from the back/forward cache sends no requests. If an earlier page in the tab had the same origin, that page's details are shown.
- Late responses from an earlier page of the same origin are counted for the current page.

## Privacy

TLSView collects and transmits no data. Each tab's record is kept in `storage.session`, which Firefox holds in memory and never writes to disk. URLs are stored without query string or fragment. A record is deleted when its tab closes, and all records when Firefox closes.
