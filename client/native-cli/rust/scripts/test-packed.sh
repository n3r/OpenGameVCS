#!/bin/sh
set -eu

ogvcs011_tmp=$(mktemp -d "${TMPDIR:-/tmp}/ogvcs011-packed.XXXXXX")
cleanup() {
  rm -rf "$ogvcs011_tmp"
}
trap cleanup EXIT HUP INT TERM

ogvcs011_repo=$(cd ../../.. && pwd)
ogvcs011_object="$ogvcs011_repo/core/object-model/rust"
ogvcs011_paths="$ogvcs011_repo/core/paths-filesystem/rust"
ogvcs011_target=${CARGO_TARGET_DIR:-"$ogvcs011_tmp/package-target"}
case "$ogvcs011_target" in
  /*) ;;
  *) ogvcs011_target=$(pwd)/$ogvcs011_target ;;
esac

CARGO_TARGET_DIR="$ogvcs011_target" cargo package \
  --manifest-path "$ogvcs011_object/Cargo.toml" --locked --offline --allow-dirty
CARGO_TARGET_DIR="$ogvcs011_target" cargo package \
  --manifest-path "$ogvcs011_paths/Cargo.toml" --locked --offline --allow-dirty
CARGO_TARGET_DIR="$ogvcs011_target" cargo package --locked --offline --allow-dirty \
  --config "patch.crates-io.ogvcs-object-model.path='$ogvcs011_object'" \
  --config "patch.crates-io.ogvcs-path-contract.path='$ogvcs011_paths'"
ogvcs011_crate="$ogvcs011_target/package/ogvcs-local-cli-0.2.0-rc.2.crate"
test -f "$ogvcs011_crate"
tar -xzf "$ogvcs011_crate" -C "$ogvcs011_tmp"
tar -xzf "$ogvcs011_target/package/ogvcs-object-model-0.1.0.crate" -C "$ogvcs011_tmp"
tar -xzf "$ogvcs011_target/package/ogvcs-path-contract-1.0.0.crate" -C "$ogvcs011_tmp"

cd "$ogvcs011_tmp/ogvcs-local-cli-0.2.0-rc.2"
CARGO_TARGET_DIR="$ogvcs011_tmp/target" cargo test --locked --offline \
  --config "patch.crates-io.ogvcs-object-model.path='$ogvcs011_tmp/ogvcs-object-model-0.1.0'" \
  --config "patch.crates-io.ogvcs-path-contract.path='$ogvcs011_tmp/ogvcs-path-contract-1.0.0'"
