# Cross-surface delivery

Updated **2026-08-22**. Verification status is recorded per repository and exact
commit; this document is a delivery requirement, not proof that every store or
signed release has shipped.

## Surfaces

- Rust API/backend: `cliptown/cliptown-rust-backend.rs`
- Flutter Android/iOS, Flutter Web, and Flutter desktop: `cliptown/cliptown-flutter`
- Rust desktop: `cliptown/cliptown-desktop.rs` — independent native GPUI/no-WebView product
- MemeBank interop: `memebank/mbk-flutter` and `memebank/mbk-desktop.rs` when image-transfer behavior changes
- Shared contracts: `cliptown-interfaces`, official clients, encrypted transfer manifests, Signal/device fixtures, routes, and conformance tests

## Judgment-based propagation

The Flutter and Rust desktop apps are developed perpetually side by side. Neither is a prototype, fallback, rewrite target, or automatic replacement for the other. Evaluate Android, iOS, Flutter Web, Flutter desktop on Windows/macOS/Linux, native Rust desktop on Windows/macOS/Linux, MemeBank interop, and shared contracts for every user-visible or contract-changing backend change. Storage, migrations, observability, and cryptographic hardening may remain backend-only. Tray, shortcuts, clipboard providers, filesystem, drag/drop, background services, and native rendering may be implementation-specific. Clipboard item semantics, text/image/file history, configurable retention, lexical/vector search, local encryption, sync, account/device state, app-vault rules, delegated transfers, permissions, errors, notifications, and navigation normally propagate or require an explicit rationale and parity issue.

Desktop pull requests must run both implementations against the same versioned fixture on Windows, macOS, and Linux. App-specific suites remain independent; the paired suite proves only shared externally observable semantics. Flutter additionally builds and tests Android and iOS. Promotion requires exact-commit artifacts, crash diagnostics, signed/notarized/package verification where applicable, and an explicit waiver for any unavailable real-device or store validation.

## Deep links and transfer boundaries

```text
https://<verified-cliptown-owned-host>/open/<route>?<bounded-query>
cliptown://<route>?<bounded-query>
```

The HTTPS host must be verified. Web/API fallback, Flutter, and GPUI share versioned routes and fixtures and support cold start, already-running delivery, authentication resume, replay/expiry rejection, browser fallback, and explicit confirmation for sensitive import/export/transfer/vault actions.

Deep links are not a substitute for the versioned HTTPS/SDK MemeBank transfer API or native OS drag/drop/clipboard manifests. Never place clipboard contents, image/file bytes, private paths, encryption keys, Signal material, 3FA proofs, transfer capabilities, bearer tokens, credentials, or private metadata in URLs. Use bounded IDs or short-lived, single-use, audience-bound codes and validate subject/device/item/transfer identity, route version, operation, authorization, limits, and user intent.

## Review checklist

- [ ] Flutter Android/iOS impact evaluated.
- [ ] Flutter Web/mobile-web impact evaluated.
- [ ] Flutter desktop impact evaluated.
- [ ] GPUI Rust desktop impact evaluated.
- [ ] MemeBank interoperability impact evaluated.
- [ ] Shared interface/client/route/fixture impact evaluated.
- [ ] Deep-link and transfer compatibility tested where relevant.
- [ ] Omitted surfaces have a rationale and follow-up when needed.

## Routing

- GitHub Project: [`cliptown-project` — Project 1](https://github.com/orgs/cliptown/projects/1)
- Linear project: [`github.com/cliptown`](https://linear.app/denman/project/githubcomcliptown-adf62fab3f42)
- Central policy: [`cross-surface-delivery.md`](https://github.com/ORESoftware/project-registry/blob/main/docs/cross-surface-delivery.md)
- Desktop registry: [`desktop-applications.json`](https://github.com/ORESoftware/project-registry/blob/main/registry/desktop-applications.json)
