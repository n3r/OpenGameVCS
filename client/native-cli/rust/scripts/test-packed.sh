#!/bin/sh
set -eu

ogvcs011_tmp=$(mktemp -d "${TMPDIR:-/tmp}/ogvcs011-packed.XXXXXX")
cleanup() {
  rm -rf "$ogvcs011_tmp"
}
trap cleanup EXIT HUP INT TERM

cargo package --locked --offline --allow-dirty
ogvcs011_target=${CARGO_TARGET_DIR:-target}
ogvcs011_crate="$ogvcs011_target/package/ogvcs-local-cli-0.1.0-rc.1.crate"
test -f "$ogvcs011_crate"
tar -xzf "$ogvcs011_crate" -C "$ogvcs011_tmp"

cd "$ogvcs011_tmp/ogvcs-local-cli-0.1.0-rc.1"
CARGO_TARGET_DIR="$ogvcs011_tmp/target" cargo test --locked --offline
