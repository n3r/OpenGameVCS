#!/bin/sh
set -eu

ogvcs014_tmp=$(mktemp -d "${TMPDIR:-/tmp}/ogvcs014-packed.XXXXXX")
cleanup() {
  rm -rf "$ogvcs014_tmp"
}
trap cleanup EXIT HUP INT TERM

ogvcs014_checkpoint=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ogvcs014_repo=$(cd "$ogvcs014_checkpoint/../../.." && pwd)
ogvcs014_paths="$ogvcs014_repo/core/paths-filesystem/rust"
ogvcs014_objects="$ogvcs014_repo/core/object-model/rust"
ogvcs014_chunks="$ogvcs014_repo/core/chunking-manifest/rust"
ogvcs014_target=${CARGO_TARGET_DIR:-"$ogvcs014_tmp/package-target"}
case "$ogvcs014_target" in
  /*) ;;
  *) ogvcs014_target=$(pwd)/$ogvcs014_target ;;
esac

ogvcs014_config_path() {
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -m "$1"
  else
    printf '%s\n' "$1"
  fi
}

ogvcs014_paths_config=$(ogvcs014_config_path "$ogvcs014_paths")
ogvcs014_objects_config=$(ogvcs014_config_path "$ogvcs014_objects")
ogvcs014_chunks_config=$(ogvcs014_config_path "$ogvcs014_chunks")
CARGO_TARGET_DIR="$ogvcs014_target" cargo package \
  --manifest-path "$ogvcs014_paths/Cargo.toml" --locked --offline --allow-dirty
CARGO_TARGET_DIR="$ogvcs014_target" cargo package \
  --manifest-path "$ogvcs014_objects/Cargo.toml" --locked --offline --allow-dirty
CARGO_TARGET_DIR="$ogvcs014_target" cargo package \
  --manifest-path "$ogvcs014_chunks/Cargo.toml" --locked --offline --allow-dirty \
  --config "patch.crates-io.ogvcs-object-model.path='$ogvcs014_objects_config'"
CARGO_TARGET_DIR="$ogvcs014_target" cargo package \
  --manifest-path "$ogvcs014_checkpoint/Cargo.toml" --locked --offline --allow-dirty \
  --config "patch.crates-io.ogvcs-path-contract.path='$ogvcs014_paths_config'" \
  --config "patch.crates-io.ogvcs-object-model.path='$ogvcs014_objects_config'" \
  --config "patch.crates-io.ogvcs-chunking-manifest.path='$ogvcs014_chunks_config'"

tar -xzf "$ogvcs014_target/package/ogvcs-path-contract-1.0.0.crate" -C "$ogvcs014_tmp"
tar -xzf "$ogvcs014_target/package/ogvcs-object-model-0.1.0.crate" -C "$ogvcs014_tmp"
tar -xzf "$ogvcs014_target/package/ogvcs-chunking-manifest-0.1.0.crate" -C "$ogvcs014_tmp"
tar -xzf "$ogvcs014_target/package/ogvcs-local-checkpoint-0.1.0-rc.1.crate" -C "$ogvcs014_tmp"
cd "$ogvcs014_tmp/ogvcs-local-checkpoint-0.1.0-rc.1"
ogvcs014_packed_paths=$(ogvcs014_config_path "$ogvcs014_tmp/ogvcs-path-contract-1.0.0")
ogvcs014_packed_objects=$(ogvcs014_config_path "$ogvcs014_tmp/ogvcs-object-model-0.1.0")
ogvcs014_packed_chunks=$(ogvcs014_config_path "$ogvcs014_tmp/ogvcs-chunking-manifest-0.1.0")
CARGO_TARGET_DIR="$ogvcs014_tmp/target" cargo generate-lockfile --offline \
  --config "patch.crates-io.ogvcs-path-contract.path='$ogvcs014_packed_paths'" \
  --config "patch.crates-io.ogvcs-object-model.path='$ogvcs014_packed_objects'" \
  --config "patch.crates-io.ogvcs-chunking-manifest.path='$ogvcs014_packed_chunks'"
CARGO_TARGET_DIR="$ogvcs014_tmp/target" cargo test --locked --offline \
  --config "patch.crates-io.ogvcs-path-contract.path='$ogvcs014_packed_paths'" \
  --config "patch.crates-io.ogvcs-object-model.path='$ogvcs014_packed_objects'" \
  --config "patch.crates-io.ogvcs-chunking-manifest.path='$ogvcs014_packed_chunks'"

