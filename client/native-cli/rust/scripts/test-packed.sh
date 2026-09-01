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

# MSYS translates standalone path arguments for native Windows programs, but it
# cannot translate a path embedded inside Cargo's TOML --config expression.
# Normalize only those embedded values to a forward-slash Windows path.
ogvcs011_config_path() {
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -m "$1"
  else
    printf '%s\n' "$1"
  fi
}

ogvcs011_object_config=$(ogvcs011_config_path "$ogvcs011_object")
ogvcs011_paths_config=$(ogvcs011_config_path "$ogvcs011_paths")

cargo package --manifest-path "$ogvcs011_object/Cargo.toml" --locked --offline --allow-dirty
cargo package --manifest-path "$ogvcs011_paths/Cargo.toml" --locked --offline --allow-dirty
cargo package --locked --offline --allow-dirty \
  --config "patch.crates-io.ogvcs-object-model.path='$ogvcs011_object_config'" \
  --config "patch.crates-io.ogvcs-path-contract.path='$ogvcs011_paths_config'"
ogvcs011_target=${CARGO_TARGET_DIR:-target}
ogvcs011_crate="$ogvcs011_target/package/ogvcs-local-cli-0.2.0-rc.2.crate"
test -f "$ogvcs011_crate"
tar -xzf "$ogvcs011_crate" -C "$ogvcs011_tmp"
tar -xzf "$ogvcs011_object/target/package/ogvcs-object-model-0.1.0.crate" -C "$ogvcs011_tmp"
tar -xzf "$ogvcs011_paths/target/package/ogvcs-path-contract-1.0.0.crate" -C "$ogvcs011_tmp"

cd "$ogvcs011_tmp/ogvcs-local-cli-0.2.0-rc.2"
ogvcs011_packed_object_config=$(ogvcs011_config_path "$ogvcs011_tmp/ogvcs-object-model-0.1.0")
ogvcs011_packed_paths_config=$(ogvcs011_config_path "$ogvcs011_tmp/ogvcs-path-contract-1.0.0")
CARGO_TARGET_DIR="$ogvcs011_tmp/target" cargo test --locked --offline \
  --config "patch.crates-io.ogvcs-object-model.path='$ogvcs011_packed_object_config'" \
  --config "patch.crates-io.ogvcs-path-contract.path='$ogvcs011_packed_paths_config'"
