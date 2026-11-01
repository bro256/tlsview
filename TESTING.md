# Manual tests

Checks in Firefox that unit tests cannot cover. For each row, open the URL, then check the toolbar icon, its tooltip and the popup.

Third-party test servers can change their configuration at any time. A different result there is not necessarily a bug: compare with what the popup reports.

## Firefox settings used below (`about:config`)

| Preference | Default | Set to | Needed for |
|---|---|---|---|
| `security.tls.enable_kyber` | `true` | keep `true` | hybrid post-quantum (X25519MLKEM768); despite the name, this is the ML-KEM hybrid |
| `security.tls.enable_mlkem1024` | `false` | `true` | pure ML-KEM-1024 |
| `security.tls.version.enable-deprecated` | `false` | `true` | TLS 1.0 and 1.1 |

A changed setting applies to new connections only. After changing one, restart Firefox, then load the test page with **Ctrl+F5** so it is not served from the cache. Reset all settings to their defaults after testing.

## Levels

| Expected icon | URL | Requires | Tooltip (first line; Key exchange on the second) |
|---|---|---|---|
| <img src="icons/step-insecure.svg" width="20" alt="No HTTPS"> | http://http.badssl.com/ | – | No HTTPS: loaded over plain HTTP, without TLS |
| <img src="icons/step-tls10.svg" width="20" alt="1.0"> | https://tls-v1-0.badssl.com:1010/ | `enable-deprecated` | TLS 1.0 · deprecated protocol |
| <img src="icons/step-tls11.svg" width="20" alt="1.1"> | https://tls-v1-1.badssl.com:1011/ | `enable-deprecated` | TLS 1.1 · deprecated protocol |
| <img src="icons/step-tls12.svg" width="20" alt="1.2"> | https://tls-v1-2.badssl.com:1012/ | – | TLS 1.2 · traditional key exchange (not post-quantum) |
| <img src="icons/step-tls12.svg" width="20" alt="1.2"> | https://static-rsa.badssl.com/ | – | TLS 1.2 · traditional key exchange (not post-quantum); second line: Key exchange: RSA key transport (no forward secrecy); popup: Forward secrecy: No |
| <img src="icons/step-tls13.svg" width="20" alt="1.3"> | https://github.com/ | – | TLS 1.3 · traditional key exchange (not post-quantum) |
| <img src="icons/step-pqt.svg" width="20" alt="PQ, green"> | https://pq.cloudflareresearch.com/ | – | TLS 1.3 · hybrid post-quantum key exchange; X25519MLKEM768 |
| <img src="icons/step-pqt.svg" width="20" alt="PQ, green"> | https://test.openquantumsafe.org:6006/ | certificate exception | TLS 1.3 · hybrid post-quantum key exchange; X25519MLKEM768 (same server as the pure post-quantum test: if this works and 6024 does not, the cause is ML-KEM-1024) |
| <img src="icons/step-pq.svg" width="20" alt="PQ, lavender"> | https://test.openquantumsafe.org:6024/ | certificate exception, `enable_mlkem1024` | TLS 1.3 · pure post-quantum key exchange; MLKEM1024 |
| <img src="icons/step-tls13.svg" width="20" alt="1.3"> or <img src="icons/step-pqt.svg" width="20" alt="PQ, green"> | https://test.openquantumsafe.org:6002/ | certificate exception | depends on the server's group order |

test.openquantumsafe.org is the Open Quantum Safe project's test server. Each port offers one key exchange group; the current list is at https://test.openquantumsafe.org/assignments.json (open it outside the test profile, see below). Its certificates are signed by the project's own test CA, so Firefox shows a security warning: choose **Advanced → Accept the Risk and Continue** for that port. Do not import the test CA into your everyday Firefox profile.

Do not open any page of the server on port 443 (https://test.openquantumsafe.org/…) in the test profile. It sends `Strict-Transport-Security`, and HSTS applies to every port of a host (RFC 6797), so Firefox then removes the option to accept the test certificate on all test ports. If that happened: Library (**Ctrl+Shift+H**) → right-click the site → **Forget About This Site**.

## Groups Firefox names but does not offer

These connections are expected to **fail** in Firefox, because Firefox does not offer the group:

| URL | Group |
|---|---|
| https://test.openquantumsafe.org:6005/ | SecP384r1MLKEM1024 |
| https://test.openquantumsafe.org:6026/ | MLKEM768 |

## HSTS and ECH

Shown for the page itself, not rated.

| Check | Expected |
|---|---|
| Open https://hsts.badssl.com/ (a test page that sends `Strict-Transport-Security`) | **HSTS** shows the header as sent. Compare with the response headers of the page in the Network panel (F12). |
| Open https://preloaded-hsts.badssl.com/ (on Firefox's built-in HSTS preload list) | **HSTS** shows `Known to Firefox`, or the header as sent if the page also sends one |
| Open an https page whose response headers (F12 → Network) have no `Strict-Transport-Security` | **HSTS:** `Not used`, or `Known to Firefox; no header in this response` if Firefox already knows the site |
| Open https://crypto.cloudflare.com/cdn-cgi/trace | **ECH** agrees with the page: `Used` when it shows `sni=encrypted`, `Not used` when it shows `sni=plaintext` |

Firefox gets a site's ECH key from its DNS HTTPS record. Without DNS over HTTPS, whether that record can be read depends on the operating system and DNS server; on Windows 10, Firefox does not query it from the system DNS. If ECH is never used, turn on DNS over HTTPS (Settings → Privacy & Security), restart Firefox and retry.

## Encryption

| Check | Expected |
|---|---|
| Open https://cbc.badssl.com/ (offers only CBC cipher suites) | **Encryption:** a CBC cipher with HMAC, e.g. `AES-128-CBC + HMAC-SHA1`; **AEAD:** `No` |
| Open any TLS 1.3 site | **Encryption:** `AES-128-GCM`, `AES-256-GCM` or `ChaCha20-Poly1305`; **AEAD:** `Yes` |

## Connections Firefox reuses or reports differently

The Network panel (F12 → Network) shows the protocol of each response in the **Protocol** column (add it by right-clicking a column header).

| Check | How | Expected |
|---|---|---|
| HTTP/3 | Open https://cloudflare.com/, then reload: Firefox may use HTTP/2 first and switch to HTTP/3 once the server advertises it. Check that the page's Protocol is `HTTP/3`. | The page's level and group as over HTTP/2, e.g. green `PQ` with X25519MLKEM768. Not `?`. |
| TLS 1.3 resumption | Open a TLS 1.3 site, close the tab, wait more than 115 seconds (`network.http.keep-alive.timeout`) so the connection closes, then open the site again in a new tab. Firefox resumes the session with a stored ticket. | Same level and group as the first visit. Firefox resumes TLS 1.3 only with a new key exchange (`psk_dhe_ke`), so a group is reported. |
| TLS 1.2 resumption | As above, with https://tls-v1-2.badssl.com:1012/ | `1.2` icon. **Key exchange** may show `not reported` on the resumed connection; **Forward secrecy** stays `Yes` (from the cipher suite). |
| Responses from cache | Open a site, then open it again in a new tab without Ctrl+F5. | Setups show `from cache` counts with the same levels as on the first visit. |
| HTTPS without TLS details | Not reproducible on demand; Firefox reports it for example when a request is aborted before validation. If a setup titled `Not determined · HTTPS without TLS details` appears, note the URL, the response status and whether it came from cache, and report it. | Never shown as `✕` (No HTTPS). |

Report the result of each check, including when a group is `not reported`, so README limitations can say what was observed.

## Pages TLSView cannot inspect

| Page | Expected popup message |
|---|---|
| `about:addons` | This page cannot be inspected. |
| https://addons.mozilla.org/ | Firefox does not let extensions inspect this site. |
| Any page opened before TLSView was loaded | The page itself was not seen. |

## Behaviour

- **Warning:** on a page whose resources come from servers with different setups, the icon shows the corner mark when any setup is on a lower level, and the popup and tooltip name the lower levels.
- **Live update:** open the popup while a large page is loading; setups and counts update.
- **Navigation:** open a large page and immediately click a link to another site; the new page's popup does not list the first site's servers.
- **No query strings:** expand a setup; no URL contains `?`.
- **Tab closed:** the tab's record is deleted (check `storage.session` in `about:debugging` → Inspect → Storage).
