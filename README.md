# TLSView

Firefox extension that shows which TLS version and key exchange a site uses: traditional, PQ/T hybrid or pure post-quantum (ML-KEM).

Only the key exchange is rated. Post-quantum key exchange is designed to protect the confidentiality of recorded traffic against a future quantum computer ("harvest now, decrypt later"). It does not protect authentication: signatures and certificates are not rated.

Terms follow RFC 9794: *traditional* (not post-quantum), *post-quantum* (PQ), *PQ/T hybrid* (a PQ and a traditional algorithm combined).

## Protection levels

The toolbar icon shows the level of the connection that delivered the page itself (the main document). Higher is better. Both post-quantum levels show `PQ`: green for PQ/T hybrid, lavender for pure post-quantum.

| Icon | Level | Meaning |
|:-:|---|---|
| <img src="icons/step-pqt.svg" width="24" alt="PQ, green"> | TLS 1.3 · PQ/T hybrid | ML-KEM combined with ECDH. Designed to remain secure if either component remains secure. |
| <img src="icons/step-pq.svg" width="24" alt="PQ, lavender"> | TLS 1.3 · pure post-quantum | ML-KEM alone. Ranked below PQ/T hybrid: with no traditional component, its security rests on ML-KEM alone. |
| <img src="icons/step-tls13.svg" width="24" alt="1.3"> | TLS 1.3 · traditional | ECDH or finite field DH only. Not post-quantum. |
| <img src="icons/step-tls12.svg" width="24" alt="1.2"> | TLS 1.2 | Not post-quantum: Firefox offers ML-KEM groups only in TLS 1.3. RSA key transport (`TLS_RSA_WITH_*` cipher suites, enabled in Firefox by default) has no forward secrecy. |
| <img src="icons/step-tls11.svg" width="24" alt="1.1"> | TLS 1.1 | Deprecated (RFC 8996). |
| <img src="icons/step-tls10.svg" width="24" alt="1.0"> | TLS 1.0 | Deprecated (RFC 8996). |
| <img src="icons/step-insecure.svg" width="24" alt="✕"> | No HTTPS | Loaded over plain HTTP, without TLS. |
| <img src="icons/step-unknown.svg" width="24" alt="?"> | Not determined | TLS version or key exchange group not reported, not recognised, or obsolete; or an https response that Firefox reported without TLS details. Not ranked. |

The order is TLSView's. Some guidance prefers pure ML-KEM: CNSA 2.0 requires ML-KEM-1024 for key establishment.

A corner mark on the icon (<img src="icons/step-pqt-warn.svg" width="20" alt="PQ with warning">) means other responses in the tab need attention:

- **Lower level:** at least one response in the tab is on a lower level than the page. The warning names those levels, e.g. `TLS 1.2, TLS 1.3 · traditional`.
- **Could not be checked:** at least one response is *Not determined*. Not shown when the page itself is *Not determined* or has no HTTPS.

The tooltip shows the popup's headline, then the key exchange and the cipher suite, then any warnings:

```
TLS 1.3 · PQ/T hybrid key exchange
Key exchange: X25519MLKEM768
Cipher suite: TLS_AES_128_GCM_SHA256
```

## Key exchange groups

Groups are identified by their [IANA TLS Supported Groups](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8) name. The table lists every group TLSView recognises; it covers every group name current Firefox reports.

| IANA name | Firefox name | Type | Offered by Firefox |
|---|---|---|---|
| X25519MLKEM768 | `mlkem768x25519` | PQ/T hybrid, ML-KEM-768 (category 3) + X25519 | yes |
| SecP256r1MLKEM768 | `secp256r1mlkem768` | PQ/T hybrid, ML-KEM-768 (category 3) + P-256 | no |
| SecP384r1MLKEM1024 | `secp384r1mlkem1024` | PQ/T hybrid, ML-KEM-1024 (category 5) + P-384 | no |
| MLKEM1024 | `mlkem1024` | pure PQ, ML-KEM-1024 (category 5) | only with `security.tls.enable_mlkem1024` |
| X25519Kyber768Draft00 | `xyber768d00` | PQ/T hybrid with pre-standard Kyber; obsolete, not supported by current Firefox; shown as Not determined | no |
| x25519 | `x25519` | traditional | yes |
| secp256r1, secp384r1, secp521r1 | `P256`, `P384`, `P521` | traditional | yes |
| ffdhe2048, ffdhe3072 | `FF 2048`, `FF 3072` | traditional | only if DHE cipher suites are enabled |

Firefox also reports `custom` (TLS 1.2 DHE with a prime not from RFC 7919). For RSA key transport it reports no group; TLSView recognises it from the cipher suite name. NIST security categories are from FIPS 203. The hybrid groups are specified in RFC 10024; MLKEM1024 in draft-ietf-tls-mlkem.

## Optional Firefox settings

Two `about:config` preferences let Firefox negotiate levels it does not use by default. Both are off by default and apply to the whole browser, so use them for testing and reset them afterwards.

| Preference | Default | When `true` |
|---|---|---|
| `security.tls.enable_mlkem1024` | `false` | Firefox also offers pure ML-KEM-1024 (MLKEM1024) in TLS 1.3. It sends no key share for it, so a server that selects it asks for one with a HelloRetryRequest. |
| `security.tls.version.enable-deprecated` | `false` | Firefox allows TLS 1.0 and 1.1. |

A change applies to new connections only. Restart Firefox, then reload the page without the cache (Ctrl+F5).

## Popup

**This page** shows the page's own connection:

| Row | Content |
|---|---|
| Protocol | TLS version |
| Cipher suite | As reported by Firefox, e.g. `TLS_AES_128_GCM_SHA256` |
| Encryption | Record encryption from the cipher suite: `AEAD` (GCM, CCM, ChaCha20-Poly1305) or `CBC + HMAC` with the HMAC hash. Firefox does not support encrypt-then-MAC (RFC 7366), so CBC suites use MAC-then-encrypt. Shown, not rated. |
| Key exchange | IANA group name, and Firefox's name if different; `RSA key transport` for `TLS_RSA_WITH_*` cipher suites |
| Key exchange type | Traditional, PQ/T hybrid or post-quantum, with the components and the specification |
| Forward secrecy | Yes for TLS 1.3 and for ECDHE or DHE cipher suites; No for RSA key transport. Shown, not rated. |
| Handshake signature | Signature scheme the server used in the handshake (CertificateVerify in TLS 1.3, ServerKeyExchange in TLS 1.2), as Firefox names it, with its kind: `traditional` (RSA, ECDSA) or `post-quantum` (ML-DSA, FIPS 204). Not the certificate's key or its CA signature. Shown, not rated. |
| HSTS | The `Strict-Transport-Security` header as sent and checked with Firefox's parsing rules, or whether Firefox already knew the site as HSTS (preload list or an earlier visit). Shown, not rated. |
| ECH | Encrypted Client Hello: `Used` if the server accepted it, otherwise `Not used`. Shown, not rated. |

**TLS setups in this tab** groups every response in the tab by TLS version, key exchange group and cipher suite. Each setup shows its responses, distinct origins, responses served from cache, and, when expanded, the URLs.

## Install from source

Requires Firefox 140 or later (desktop).

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
- A response served from Firefox's cache shows the TLS details of the connection that originally fetched it.
- TLS 1.3 session resumption and 0-RTT early data reuse a secret from an earlier handshake, and 0-RTT data has no forward secrecy. Firefox does not tell extensions whether either was used.

## Privacy

TLSView collects and transmits no data. Each tab's record is kept in `storage.session`, which Firefox holds in memory and never writes to disk. URLs are stored without query string or fragment. A record is deleted when its tab closes, and all records when Firefox closes.

## References

| Topic | Source |
|---|---|
| TLS 1.3 | [RFC 9846](https://www.rfc-editor.org/rfc/rfc9846) |
| TLS 1.0 and 1.1 deprecation | [RFC 8996](https://www.rfc-editor.org/rfc/rfc8996) |
| PQ/T hybrid terminology | [RFC 9794](https://www.rfc-editor.org/rfc/rfc9794) |
| ML-KEM | [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) |
| ML-DSA | [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) |
| PQ/T hybrid groups for TLS 1.3 | [RFC 10024](https://www.rfc-editor.org/rfc/rfc10024) |
| Pure ML-KEM groups for TLS 1.3 | [draft-ietf-tls-mlkem](https://datatracker.ietf.org/doc/draft-ietf-tls-mlkem/) |
| TLS Supported Groups registry | [IANA](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8) |
| X25519 | [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748) |
| FFDHE groups | [RFC 7919](https://www.rfc-editor.org/rfc/rfc7919) |
| HSTS | [RFC 6797](https://www.rfc-editor.org/rfc/rfc6797) |
| ECH | [RFC 9849](https://www.rfc-editor.org/rfc/rfc9849) |
| CNSA 2.0 | [NSA CNSA 2.0 FAQ](https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF) |
| Extension API | [webRequest.getSecurityInfo()](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/webRequest/getSecurityInfo) |
