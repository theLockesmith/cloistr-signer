#!/bin/sh
# Reproducible build of the frost WASM: the same source + Cargo.lock + toolchain
# gives byte-identical output on any machine. rustc embeds absolute source paths
# (panic locations) in the binary; without remapping, every build carries the
# builder's home directory and CI can never match a module built elsewhere.
set -eu
cd "$(dirname "$0")"
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
# A toolchain with the rust-src component records std paths under its sysroot;
# one without records /rustc/<commit>. Map the former onto the latter.
sysroot="$(rustc --print sysroot)"
commit="$(rustc -vV | sed -n 's/^commit-hash: //p')"
export RUSTFLAGS="--remap-path-prefix=${cargo_home}=/cargo --remap-path-prefix=$(pwd)=/src --remap-path-prefix=${sysroot}/lib/rustlib/src/rust=/rustc/${commit}"
exec wasm-pack build --target web --release -- --locked
