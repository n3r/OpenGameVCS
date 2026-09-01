#!/bin/sh
set -eu

ogvcs013_tmp=$(mktemp -d "${TMPDIR:-/tmp}/ogvcs013-packed.XXXXXX")
cleanup() {
  rm -rf "$ogvcs013_tmp"
}
trap cleanup EXIT HUP INT TERM

ogvcs013_kernel=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ogvcs013_repo=$(cd "$ogvcs013_kernel/../../.." && pwd)
ogvcs013_paths="$ogvcs013_repo/core/paths-filesystem/rust"
ogvcs013_objects="$ogvcs013_repo/core/object-model/rust"
ogvcs013_chunks="$ogvcs013_repo/core/chunking-manifest/rust"
ogvcs013_target=${CARGO_TARGET_DIR:-"$ogvcs013_tmp/package-target"}
case "$ogvcs013_target" in
  /*) ;;
  *) ogvcs013_target=$(pwd)/$ogvcs013_target ;;
esac

ogvcs013_config_path() {
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -m "$1"
  else
    printf '%s\n' "$1"
  fi
}

ogvcs013_paths_config=$(ogvcs013_config_path "$ogvcs013_paths")
ogvcs013_objects_config=$(ogvcs013_config_path "$ogvcs013_objects")
ogvcs013_chunks_config=$(ogvcs013_config_path "$ogvcs013_chunks")
CARGO_TARGET_DIR="$ogvcs013_target" cargo package \
  --manifest-path "$ogvcs013_paths/Cargo.toml" --locked --offline --allow-dirty
CARGO_TARGET_DIR="$ogvcs013_target" cargo package \
  --manifest-path "$ogvcs013_objects/Cargo.toml" --locked --offline --allow-dirty
CARGO_TARGET_DIR="$ogvcs013_target" cargo package \
  --manifest-path "$ogvcs013_chunks/Cargo.toml" --locked --offline --allow-dirty \
  --config "patch.crates-io.ogvcs-object-model.path='$ogvcs013_objects_config'"
CARGO_TARGET_DIR="$ogvcs013_target" cargo package \
  --manifest-path "$ogvcs013_kernel/Cargo.toml" --locked --offline --allow-dirty \
  --config "patch.crates-io.ogvcs-path-contract.path='$ogvcs013_paths_config'" \
  --config "patch.crates-io.ogvcs-object-model.path='$ogvcs013_objects_config'" \
  --config "patch.crates-io.ogvcs-chunking-manifest.path='$ogvcs013_chunks_config'"

tar -xzf "$ogvcs013_target/package/ogvcs-path-contract-1.0.0.crate" -C "$ogvcs013_tmp"
tar -xzf "$ogvcs013_target/package/ogvcs-object-model-0.1.0.crate" -C "$ogvcs013_tmp"
tar -xzf "$ogvcs013_target/package/ogvcs-chunking-manifest-0.1.0.crate" -C "$ogvcs013_tmp"
tar -xzf "$ogvcs013_target/package/ogvcs-selective-sync-kernel-0.1.0-rc.1.crate" -C "$ogvcs013_tmp"
cd "$ogvcs013_tmp/ogvcs-selective-sync-kernel-0.1.0-rc.1"
ogvcs013_packed_paths=$(ogvcs013_config_path "$ogvcs013_tmp/ogvcs-path-contract-1.0.0")
ogvcs013_packed_objects=$(ogvcs013_config_path "$ogvcs013_tmp/ogvcs-object-model-0.1.0")
ogvcs013_packed_chunks=$(ogvcs013_config_path "$ogvcs013_tmp/ogvcs-chunking-manifest-0.1.0")
CARGO_TARGET_DIR="$ogvcs013_tmp/target" cargo generate-lockfile --offline \
  --config "patch.crates-io.ogvcs-path-contract.path='$ogvcs013_packed_paths'" \
  --config "patch.crates-io.ogvcs-object-model.path='$ogvcs013_packed_objects'" \
  --config "patch.crates-io.ogvcs-chunking-manifest.path='$ogvcs013_packed_chunks'"
CARGO_TARGET_DIR="$ogvcs013_tmp/target" cargo test --locked --offline \
  --config "patch.crates-io.ogvcs-path-contract.path='$ogvcs013_packed_paths'" \
  --config "patch.crates-io.ogvcs-object-model.path='$ogvcs013_packed_objects'" \
  --config "patch.crates-io.ogvcs-chunking-manifest.path='$ogvcs013_packed_chunks'"
