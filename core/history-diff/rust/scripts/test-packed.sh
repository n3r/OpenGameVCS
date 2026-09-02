#!/bin/sh
set -eu

ogvcs015_tmp=$(mktemp -d "${TMPDIR:-/tmp}/ogvcs015-packed.XXXXXX")
cleanup() {
  rm -rf "$ogvcs015_tmp"
}
trap cleanup EXIT HUP INT TERM

ogvcs015_kernel=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ogvcs015_repo=$(cd "$ogvcs015_kernel/../../.." && pwd)
ogvcs015_paths="$ogvcs015_repo/core/paths-filesystem/rust"
ogvcs015_objects="$ogvcs015_repo/core/object-model/rust"
ogvcs015_target=${CARGO_TARGET_DIR:-"$ogvcs015_tmp/package-target"}
case "$ogvcs015_target" in
  /*) ;;
  *) ogvcs015_target=$(pwd)/$ogvcs015_target ;;
esac

ogvcs015_config_path() {
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -m "$1"
  else
    printf '%s\n' "$1"
  fi
}

ogvcs015_paths_config=$(ogvcs015_config_path "$ogvcs015_paths")
ogvcs015_objects_config=$(ogvcs015_config_path "$ogvcs015_objects")
CARGO_TARGET_DIR="$ogvcs015_target" cargo package \
  --manifest-path "$ogvcs015_paths/Cargo.toml" --locked --offline --allow-dirty
CARGO_TARGET_DIR="$ogvcs015_target" cargo package \
  --manifest-path "$ogvcs015_objects/Cargo.toml" --locked --offline --allow-dirty
CARGO_TARGET_DIR="$ogvcs015_target" cargo package \
  --manifest-path "$ogvcs015_kernel/Cargo.toml" --locked --offline --allow-dirty \
  --config "patch.crates-io.ogvcs-path-contract.path='$ogvcs015_paths_config'" \
  --config "patch.crates-io.ogvcs-object-model.path='$ogvcs015_objects_config'"

tar -xzf "$ogvcs015_target/package/ogvcs-path-contract-1.0.0.crate" -C "$ogvcs015_tmp"
tar -xzf "$ogvcs015_target/package/ogvcs-object-model-0.1.0.crate" -C "$ogvcs015_tmp"
tar -xzf "$ogvcs015_target/package/ogvcs-history-diff-kernel-0.1.0-rc.1.crate" -C "$ogvcs015_tmp"
cd "$ogvcs015_tmp/ogvcs-history-diff-kernel-0.1.0-rc.1"
ogvcs015_packed_paths=$(ogvcs015_config_path "$ogvcs015_tmp/ogvcs-path-contract-1.0.0")
ogvcs015_packed_objects=$(ogvcs015_config_path "$ogvcs015_tmp/ogvcs-object-model-0.1.0")
CARGO_TARGET_DIR="$ogvcs015_tmp/target" cargo generate-lockfile --offline \
  --config "patch.crates-io.ogvcs-path-contract.path='$ogvcs015_packed_paths'" \
  --config "patch.crates-io.ogvcs-object-model.path='$ogvcs015_packed_objects'"
CARGO_TARGET_DIR="$ogvcs015_tmp/target" cargo test --locked --offline \
  --config "patch.crates-io.ogvcs-path-contract.path='$ogvcs015_packed_paths'" \
  --config "patch.crates-io.ogvcs-object-model.path='$ogvcs015_packed_objects'"
