#!/bin/sh
# Installs the frost WASM build tools (wasm-pack, wasm-bindgen, binaryen's
# wasm-opt) from this project's own package registry, each checked against a
# pinned sha256. With all three on PATH, wasm-pack downloads nothing: it uses
# the wasm-bindgen whose version matches Cargo.lock and the wasm-opt it finds.
#
# Why: wasm-pack used to fetch wasm-bindgen and binaryen from github.com on
# every build, and those downloads failed builds (MRs !234, !235). The files in
# the registry are the unchanged upstream release files (binaryen's and
# wasm-bindgen's sha256 match the checksum files their releases publish).
# To bump a tool: upload the new upstream file under a new package version and
# update the URL and sha256 here (and wasm-bindgen must match Cargo.lock).
#
# usage: install-tools.sh [dest-dir]   (default /usr/local/bin)
set -eu
base="https://git.aegis-hq.xyz/api/v4/projects/25/packages/generic/frost-wasm-build-tools/2026.10.16"
dest="${1:-/usr/local/bin}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fetch() { # file sha256
	curl -sSfL --retry 3 -o "$tmp/$1" "$base/$1"
	echo "$2  $tmp/$1" | sha256sum -c - >/dev/null || { echo "sha256 mismatch for $1" >&2; exit 1; }
}

fetch wasm-pack-v0.15.0-x86_64-unknown-linux-musl.tar.gz c09f971ecaed9a2efc80fdcea7a00ef6b53c7fadc8c57d1f61b53a6aa66b668a
fetch wasm-bindgen-0.2.129-x86_64-unknown-linux-musl.tar.gz 82d12bb940e2d4e72e0d5605387fc1b8ca179044e012b620f0ce4e7440e8320e
fetch binaryen-version_117-x86_64-linux.tar.gz 3dc677006555b355ea2da5e82602065a161d5e83eaefd3f759afa00b96e83212

tar xzf "$tmp/wasm-pack-v0.15.0-x86_64-unknown-linux-musl.tar.gz" -C "$dest" --strip-components=1 \
	wasm-pack-v0.15.0-x86_64-unknown-linux-musl/wasm-pack
tar xzf "$tmp/wasm-bindgen-0.2.129-x86_64-unknown-linux-musl.tar.gz" -C "$dest" --strip-components=1 \
	wasm-bindgen-0.2.129-x86_64-unknown-linux-musl/wasm-bindgen \
	wasm-bindgen-0.2.129-x86_64-unknown-linux-musl/wasm-bindgen-test-runner
tar xzf "$tmp/binaryen-version_117-x86_64-linux.tar.gz" -C "$dest" --strip-components=2 \
	binaryen-version_117/bin/wasm-opt

"$dest/wasm-pack" --version
"$dest/wasm-bindgen" --version
"$dest/wasm-opt" --version
