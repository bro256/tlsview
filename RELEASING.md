# Releasing

TLSView runs with access to all sites, so a compromised account or build could ship a harmful update to every user. These steps keep accounts and releases trustworthy.

## Accounts (once)

- **GitHub:** two-factor authentication on. Protect the `main` branch: no force-pushes, no deletion.
- **Mozilla account (AMO):** two-factor authentication on.
- **AMO API keys** (only if releases are signed with `web-ext sign`): store them as GitHub Actions secrets or in a password manager. Never commit them.
- **Signed commits and tags:** set up Git signing (SSH or GPG) and add the key to GitHub, so releases can be verified.
- **Dependabot alerts** on for the repository. The only dependency is the development tool web-ext; nothing from `node_modules` is shipped.

## Each release

1. Set the same version in `manifest.json` and `package.json`.
2. Start from a clean clone of the commit to release:
   ```sh
   git clone https://github.com/bro256/tlsview.git && cd tlsview
   npm ci          # installs exactly the versions in package-lock.json
   npm test
   npm run lint    # must report 0 errors and 0 warnings
   npm run build
   ```
3. Check the package contents: `unzip -l web-ext-artifacts/tlsview-<version>.zip`. Only `manifest.json`, `background.js`, `lib/`, `popup/`, `icons/`, `README.md` and `LICENSE` belong there.
4. Record the package hash: `sha256sum web-ext-artifacts/tlsview-<version>.zip` (macOS: `shasum -a 256`).
5. Upload the zip to AMO. The code is not minified or bundled, so no separate source code submission is needed.
6. Tag the release with a signed tag and push it:
   ```sh
   git tag -s v<version> -m "TLSView <version>"
   git push origin v<version>
   ```
7. Create a GitHub release for the tag, attach the zip and state its SHA-256.

## From time to time

- Run `npm audit` and update web-ext when needed (development only).
- Re-run the checks in TESTING.md after a new Firefox major version.
