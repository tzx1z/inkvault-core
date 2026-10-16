#!/bin/sh
# Сборка ядра для платформ. Цели:
#   test    - тесты ядра
#   wasm    - WASM для Node и браузера (bindings/wasm/pkg)
#   jvm     - Kotlin-биндинги и библиотека для JVM (target/release)
#   android - Kotlin-биндинги и библиотеки для Android (bindings/uniffi/jniLibs)
# Без аргументов - все цели по порядку.
set -eu
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

kotlin_done=
kotlin() {
    [ -n "$kotlin_done" ] && return
    # release-сборка идет без символов, а генератор берет метаданные UniFFI из символов,
    # поэтому биндинги генерируются из debug-сборки
    cargo build -q -p inkvault-uniffi
    cargo run -q -p inkvault-uniffi --features cli --bin uniffi-bindgen -- generate --no-format \
        --library target/debug/libinkvault_uniffi.so --language kotlin --out-dir bindings/uniffi/kotlin
    kotlin_done=1
}

for target in ${*:-test wasm jvm android}; do
    case $target in
    test)
        cargo test -q -p inkvault-core --features vectors
        ;;
    wasm)
        # профиль wasm: размер вместо скорости, кроме Argon2 и BLAKE2 (Cargo.toml)
        WASM=target/wasm32-unknown-unknown/wasm/inkvault_wasm.wasm
        cargo build -q -p inkvault-wasm --profile wasm --target wasm32-unknown-unknown
        wasm-bindgen --target nodejs --out-dir bindings/wasm/pkg/node "$WASM"
        # nodejs-цель генерирует CommonJS, а ближайший package.json выше по дереву
        # (например, web-клиента с "type": "module") заставит Node читать его как ESM
        echo '{"type": "commonjs"}' > bindings/wasm/pkg/node/package.json
        wasm-bindgen --target web --out-dir bindings/wasm/pkg/web "$WASM"
        ;;
    jvm)
        kotlin
        cargo build -q -p inkvault-uniffi --release
        ;;
    android)
        kotlin
        : "${ANDROID_NDK_HOME:=$HOME/Android/Sdk/ndk/26.1.10909125}"
        export ANDROID_NDK_HOME
        cargo ndk -t arm64-v8a -t x86_64 -P 26 -o bindings/uniffi/jniLibs build -q -p inkvault-uniffi --release --lib
        ;;
    *)
        echo "неизвестная цель: $target (test, wasm, jvm, android)" >&2
        exit 2
        ;;
    esac
done
