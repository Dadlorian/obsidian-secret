# Security Review — Secret Placeholders (obsidian-secret-placeholders)

- **Reviewed version:** 0.6.1 (manifest `id: secret-placeholders`)
- **Review date:** 2026-06-09
- **Scope:** Full source tree under `src/`, build config, and the published
  security/permissions documentation.
- **Method:** Static read of the source, plus targeted searches for the
  patterns that typically make a secrets-handling plugin dangerous
  (outbound network endpoints, dynamic code execution, secret logging,
  at-rest token storage, and any write path into the user's notes).

---

## Verdict

**Safe to install, with one caveat (plaintext 1Password Connect token at
rest).** The plugin does what its documentation claims. The behaviours that
usually make a secrets plugin risky are absent: there is no telemetry, no
author-controlled endpoint, no dynamic code execution, and no secret
logging. The single discrepancy with the stated security model is the
1Password provider, which persists its access token unencrypted (details
below).

---

## What was verified (and how)

### 1. No telemetry / no author-controlled endpoints — CONFIRMED

Every URL literal in `src/**/*.ts` was enumerated. The only hardcoded URLs
are:

- Documentation links inside code comments (Bitwarden whitepaper, 1Password
  API reference).
- **Example** placeholders shown in settings fields
  (`https://vw.example.com`, `https://openbao.example.com`,
  `https://1pconnect.example.com`).

Every *real* network request is built from a base URL the user enters in
settings — their own OpenBao, 1Password Connect, or Bitwarden/Vaultwarden
server. There is no analytics, no crash reporting, and no author-controlled
host anywhere in the code.

### 2. No dangerous execution or transport primitives — CONFIRMED

A search for `fetch(`, `XMLHttpRequest`, `WebSocket`, `eval(`,
`new Function`, dynamic `import()` of remote code, and `child_process`
returned nothing of concern:

- All provider HTTP goes through Obsidian's `requestUrl`
  (`src/providers/openbao/client.ts`, `src/providers/bitwarden/client.ts`,
  `src/providers/onepassword.ts`, `src/providers/openbao/oidcLogin.ts`).
- The only Node `require()` calls — `http`, `net`, `electron` — are in the
  **desktop-only** OpenBao OIDC login (`src/providers/openbao/oidcLogin.ts`).
  They implement a standard OAuth loopback: a one-shot HTTP listener bound to
  `127.0.0.1`, opened to catch the IdP redirect and closed immediately after
  (or on timeout). This is the conventional, safe pattern.
- The `import()` calls that do exist are lazy imports of **local** bundle
  modules (`./argon2`, `../../modals`), not remote code.

### 3. No secret logging — CONFIRMED

There are **no** `console.log/warn/error/debug` statements in `src/`.
Tokens, passphrases, and resolved secret values are never written to the
developer console.

### 4. Crypto matches the documented model — CONFIRMED

`src/crypto/passphraseEncryption.ts`:

- PBKDF2-HMAC-SHA256, **200,000** iterations, 16-byte random salt → 256-bit
  AES-GCM key.
- 12-byte random IV per encryption; output packs `salt || iv || ciphertext`,
  base64-encoded.
- The passphrase is never persisted.

Bitwarden client crypto (PBKDF2 / Argon2id / HKDF / AES-CBC-HMAC / RSA-OAEP)
runs locally via WebCrypto and the bundled `hash-wasm` WASM; only a derived
password hash is sent to the server, never the master password. This matches
`docs/security.md`.

### 5. Display-only render paths — CONFIRMED

The Reading-view post-processor and Live Preview decoration never call a
write API. Note mutation happens only in explicit user commands, and the one
that writes a raw secret (*Replace with resolved value*) is
confirmation-gated. This upholds the hard invariant stated in `CLAUDE.md`.

---

## Findings

### FINDING-1 (Medium) — 1Password Connect token stored in plaintext at rest

**Where:** `src/providers/onepassword.ts`
(`OnePasswordSettings.token`, `persist()` at ~L376, login handler ~L331).

**What:** OpenBao and Bitwarden keep tokens/sessions in memory by default and
only persist them AES-GCM-encrypted under a user passphrase ("remember on
device"). The **1Password provider has no passphrase-encryption path**. Once
the user logs in, the Connect token is written verbatim into the plugin data
file (`<vault>/.obsidian/plugins/secret-placeholders/data.json`).

**Why it matters:** A 1Password Connect token is long-lived and grants read
access to whatever vaults it is scoped to. On disk in cleartext, it is
exposed to anything that can read the vault folder (other apps, backups,
sync targets, file-level malware).

**Discrepancy:** `docs/security.md` states *"Tokens / sessions are kept in
memory by default. The optional 'remember on device' settings encrypt them
at rest with AES-GCM."* This is true for OpenBao and Bitwarden but **not**
for 1Password.

**Recommended remediation (in priority order):**

1. Route the 1Password token through the same
   `encryptStringWithPassphrase` / `decryptStringWithPassphrase` helpers in
   `src/crypto/passphraseEncryption.ts` that OpenBao and Bitwarden already
   use, gated behind an explicit "remember on device" opt-in.
2. Until then, default to **in-memory only** (do not persist the token), so a
   restart simply re-prompts.
3. Scope the Connect token to the minimum vaults required, and treat
   `data.json` as sensitive.

**Affected users:** Only those who configure the 1Password Connect provider.
OpenBao-only and Bitwarden-only users are unaffected.

---

## Lower-severity notes / hardening ideas

- **OIDC redirect host mismatch (informational):** the loopback listener
  binds to `127.0.0.1` while the advertised `redirect_uri` uses `localhost`
  (`src/providers/openbao/oidcLogin.ts:40,131`). These usually resolve to the
  same place; on systems where `localhost` resolves to `::1` (IPv6) first the
  callback could miss the listener. Consider binding consistently or
  advertising `127.0.0.1`. Not a security issue.
- **Plugin data sensitivity:** `data.json` holds encrypted secrets (and, for
  1Password, a plaintext token). Confirm it is excluded from any vault
  publish pipeline and treat it as secret material in backups.
- **Defense-in-depth for publishing:** as the docs note, strip placeholders
  in any publish pipeline — a leaked placeholder reveals a secret *path*, not
  its value, but paths can still be sensitive.

---

## Supply-chain / provenance observations

- **Dependencies are minimal:** runtime dependency is `hash-wasm` only;
  everything else is dev/build tooling (`esbuild`, `typescript`, Obsidian and
  CodeMirror types).
- **WASM is bundled at build time** from the published `hash-wasm` package; no
  WASM is fetched at runtime.
- **Release artifacts** (`main.js`, `manifest.json`, `styles.css`) ship with
  GitHub artifact attestations linking each asset to the workflow run and
  commit that built it.

**Strongest assurance for a self-hosted user:** build from source rather than
installing a release binary —

```bash
npm install
npm run build   # produces main.js from source you can read
npm run typecheck
```

Then install the locally built `main.js`, `manifest.json`, and `styles.css`
into `<vault>/.obsidian/plugins/secret-placeholders/`.

---

## Recommendations summary

| # | Severity | Action |
|---|----------|--------|
| 1 | Medium | Encrypt the 1Password Connect token at rest (or keep it in memory only) to match the documented model. |
| 2 | Low/Info | Make OIDC loopback bind host and advertised `redirect_uri` consistent. |
| 3 | Info | Build from source for self-hosting; keep `data.json` out of publish/backup exposure. |

## Files examined

- `manifest.json`, `package.json`, `docs/security.md`, `CLAUDE.md`
- `src/crypto/passphraseEncryption.ts`
- `src/providers/openbao/oidcLogin.ts`, `src/providers/openbao/client.ts`,
  `src/providers/openbao/auth.ts`, `src/providers/openbao/index.ts`
- `src/providers/bitwarden/client.ts`, `src/providers/bitwarden/crypto.ts`,
  `src/providers/bitwarden/index.ts`
- `src/providers/onepassword.ts`
- Tree-wide searches for network endpoints, dynamic execution, secret
  logging, and at-rest persistence.
