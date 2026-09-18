# Security checks and deployment

Run `npm ci` in each JavaScript project, then `node scripts/security/audit-npm.mjs <project>` from the repository root. Run `cargo audit --deny warnings` in `core/rust`. CI runs these on pull requests and weekly, plus .NET restore with vulnerability warnings treated as errors and the defensive HTTP tests against a dedicated PostgreSQL database.

## Temporary image-size mitigation

The official npm releases 1.2.1 and 2.0.2 still match [GHSA-w3rx-r6r6-pgpr](https://github.com/advisories/GHSA-w3rx-r6r6-pgpr) and [GHSA-5p2g-fcmc-qvqq](https://github.com/advisories/GHSA-5p2g-fcmc-qvqq). Mobile and documentation postinstall scripts add strict header and length checks before ICNS and HEIF/JPEG XL box traversal. Both CJS and ESM entry points, including direct type imports, are patched. No third-party replacement package is used.

Raw `npm audit` continues to report those versions and their dependent packages. The audit gate permits only these two exact advisories, only after verifying every installed parser guard. All other advisories and scanner failures fail the job. Review this exception by **2026-10-06**; CI fails after that date. Replace the patch with an upstream fixed release when available. `npm ci --ignore-scripts` must be followed by `node scripts/security/harden-image-size.mjs <project>` before any build. Verify with `node scripts/security/image-size.test.mjs <project>`.

## Upgrade requirements

- Back up the PostgreSQL database before applying the normal server migrations. `AddDurableSessions` preserves existing refresh-token hashes. Previously issued access tokens need one refresh to acquire a session identifier. Clients that cannot refresh need to sign in again.
- Update the mobile application together with the server. Older mobile clients cannot approve login without the new vault-key signature. Rebuild native libraries and Swift/Kotlin bindings together after the UniFFI update; do not reuse libraries built with 0.28.
- Ordinary vault sync can register the first mail key or resend the same key, but cannot replace an established primary key. Existing keys and mail remain intact. A dedicated confirmed key-rotation feature is not introduced by this patch.
- 2FA setup expires after ten minutes and is bound to the requesting session. Setup requires the new authenticator's code; disabling requires the active authenticator's code. API restarts require restarting an unfinished setup. Multi-instance deployments need sticky routing for this temporary setup state (as for the existing in-memory SRP state).
- Explicitly configure `TRUSTED_PROXIES` for proxies upstream of nginx; empty now trusts none. The API/admin trust loopback and `TRUSTED_APP_PROXIES` only. Bundled multi-container compose sets the latter to `reverse-proxy`.

## Production configuration

Build and publish images containing these changes through the normal release process. Pulling existing upstream images does not deploy this patch. Use the installation CLI's explicit version selection rather than `latest`, and record the deployed image digests for rollback.

For stricter deployments, generate a digest-pinned override with `node scripts/security/pin-compose.mjs <compose-file> <output-file>`. The script only reads registry metadata and writes a new file; it never starts containers. It also makes `ADMIN_IP_ALLOWLIST` mandatory for the nginx service. Set that variable to your administrative/VPN source IPs or CIDRs and enable the admin account's existing 2FA. Apply the base and generated override through your normal deployment process after reviewing them. Network allowlists and account settings depend on your deployment and are not guessed by the code change.

For local HTTP regression tests, set `ALIASVAULT_SECURITY_TEST_DB` to a disposable PostgreSQL database on localhost whose name begins with `aliasvault_security_test`. The migration regression downgrades/upgrades its schema; never point it at a working database. Tests use synthetic accounts only.
