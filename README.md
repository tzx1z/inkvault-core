# InkVault Core

Cryptographic core of InkVault, a self-hosted password manager with end-to-end encryption and sync over XMPP.

A vault account is a JID on your own XMPP server (for example, Prosody). Records are encrypted on the device, and the server stores only ciphertext in PEP nodes. The same Rust core is used by every client: the web client through WebAssembly, the Android client through Kotlin bindings, and the terminal client directly.

The core does no networking. It takes the data a client has received from the server and returns the commands the client should send back, so each platform keeps its own XMPP stack.

## Features

- Master password key derivation with Argon2id, key hierarchy of user key and vault keys.
- XChaCha20-Poly1305 record encryption bound to the vault, record and key version.
- Per-field merge of edits from different devices using hybrid logical clocks (HLC).
- Sync engine for PEP nodes with an encrypted local cache.
- Account lifecycle: create, unlock, change master password, quick unlock with a device key.
- Encrypted vault export and import.
- Password generator and TOTP codes (RFC 6238).
- Error and warning messages in English and Russian, stable error codes for clients.

## Layout

| Path | Contents |
|------|----------|
| `core/` | `inkvault-core` crate |
| `bindings/wasm/` | WebAssembly build (wasm-bindgen) for browsers and Node |
| `bindings/uniffi/` | Kotlin bindings (UniFFI) for Android and JVM |
| `bindings/uniffi/android/` | Gradle project that packages the Kotlin bindings and libraries as an AAR |
| `bindings/build.sh` | build script for all targets |
| `testkit/` | local Prosody image and a Node tool that creates a test vault, for client end-to-end tests |
| `tools/licenses.py` | dependency license check |

## Building

Requirements: Rust 1.85 or newer. For WebAssembly, the `wasm32-unknown-unknown` target and `wasm-bindgen-cli` 0.2.129. For Android, `cargo-ndk`, Android NDK 26 in `ANDROID_NDK_HOME` and the `aarch64-linux-android` and `x86_64-linux-android` targets.

```sh
bindings/build.sh              # core tests and all targets
bindings/build.sh wasm         # bindings/wasm/pkg/{web,node}
bindings/build.sh jvm          # bindings/uniffi/kotlin and target/release/libinkvault_uniffi.so
bindings/build.sh android      # bindings/uniffi/kotlin and bindings/uniffi/jniLibs (arm64-v8a, x86_64)
(cd bindings/uniffi/android && ./gradlew assembleRelease)   # AAR, after the android target
```

## Usage

Rust:

```toml
[dependencies]
inkvault-core = { git = "https://github.com/tzx1z/inkvault-core.git", tag = "v0.2.1" }
```

Each [release](https://github.com/tzx1z/inkvault-core/releases) also includes the WebAssembly npm package (`inkvault-core-wasm-<version>.tgz`, browser build by default, Node build as `@inkov-dev/inkvault-core-wasm/node`) and the Android library (`inkvault-core-android-<version>.aar`, requires `net.java.dev.jna:jna:5.19.1@aar`).

Entry points are `Account`, `UnlockedAccount` and `SyncEngine`. WebAssembly and Kotlin expose the same API as `VaultAccount`, `VaultSync` and `VaultClock`; the sync engine returns JSON with commands for the server and events for the UI.

Message language is English by default and is set once per process: `inkvault_core::lang::set(Lang::from_tag("ru-RU"))` in Rust, `setLanguage("ru-RU")` in WebAssembly and Kotlin.

## Test server

```sh
podman build -t inkvault-test-prosody testkit/prosody
podman run -d --name inkvault-test -p 127.0.0.1:15222:5222 -p 127.0.0.1:15280:5280 inkvault-test-prosody
```

Local use only, no TLS: c2s on `127.0.0.1:15222`, WebSocket on `ws://127.0.0.1:15280/xmpp-websocket`, users `alice`, `bob` and `fast` on `vault.test`, password `secret`. `testkit/vault/vault.mjs` creates a vault and records as `alice@vault.test` and needs `bindings/build.sh wasm` and `npm ci` in `testkit/vault`; its commands are listed at the top of the file.

## License

[GNU AGPL v3.0](LICENSE) (`AGPL-3.0-only`). Copyright (C) 2026 Evgeny Inkov.

## Contact

Evgeny Inkov: [me@inkov.dev](mailto:me@inkov.dev), XMPP [tzx1z@inkov.dev](xmpp:tzx1z@inkov.dev), [inkov.dev](https://inkov.dev)
