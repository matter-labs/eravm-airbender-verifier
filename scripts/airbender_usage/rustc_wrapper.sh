#!/usr/bin/env bash
# Injects `-Zprint-mono-items=lazy` into every rustc invocation while leaving
# the flags cargo computed from config.toml / RUSTFLAGS untouched.
# cargo invokes RUSTC_WRAPPER as: `$RUSTC_WRAPPER rustc [args...]`
exec "$@" -Zprint-mono-items=y
