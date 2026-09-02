#!/bin/sh
set -eu

ogvcs020_tmp=$(mktemp -d "${TMPDIR:-/tmp}/ogvcs020-packed.XXXXXX")
cleanup() {
  rm -rf "$ogvcs020_tmp"
}
trap cleanup EXIT HUP INT TERM

ogvcs020_crate=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ogvcs020_repo=$(cd "$ogvcs020_crate/../../.." && pwd)
ogvcs020_paths="$ogvcs020_repo/core/paths-filesystem/rust"
ogvcs020_objects="$ogvcs020_repo/core/object-model/rust"
ogvcs020_target=${CARGO_TARGET_DIR:-"$ogvcs020_tmp/package-target"}
case "$ogvcs020_target" in
  /*) ;;
  *) ogvcs020_target=$(pwd)/$ogvcs020_target ;;
esac

ogvcs020_config_path() {
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -m "$1"
  else
    printf '%s\n' "$1"
  fi
}

ogvcs020_paths_config=$(ogvcs020_config_path "$ogvcs020_paths")
ogvcs020_objects_config=$(ogvcs020_config_path "$ogvcs020_objects")
CARGO_TARGET_DIR="$ogvcs020_target" cargo package \
  --manifest-path "$ogvcs020_paths/Cargo.toml" --locked --offline --allow-dirty
CARGO_TARGET_DIR="$ogvcs020_target" cargo package \
  --manifest-path "$ogvcs020_objects/Cargo.toml" --locked --offline --allow-dirty
CARGO_TARGET_DIR="$ogvcs020_target" cargo package \
  --manifest-path "$ogvcs020_crate/Cargo.toml" --locked --offline --allow-dirty \
  --config "patch.crates-io.ogvcs-path-contract.path='$ogvcs020_paths_config'" \
  --config "patch.crates-io.ogvcs-object-model.path='$ogvcs020_objects_config'"

tar -xzf "$ogvcs020_target/package/ogvcs-path-contract-1.0.0.crate" -C "$ogvcs020_tmp"
tar -xzf "$ogvcs020_target/package/ogvcs-object-model-0.1.0.crate" -C "$ogvcs020_tmp"
tar -xzf "$ogvcs020_target/package/ogvcs-git-import-preflight-0.1.0-rc.1.crate" -C "$ogvcs020_tmp"
cd "$ogvcs020_tmp/ogvcs-git-import-preflight-0.1.0-rc.1"
ogvcs020_packed_paths=$(ogvcs020_config_path "$ogvcs020_tmp/ogvcs-path-contract-1.0.0")
ogvcs020_packed_objects=$(ogvcs020_config_path "$ogvcs020_tmp/ogvcs-object-model-0.1.0")
CARGO_TARGET_DIR="$ogvcs020_tmp/target" cargo generate-lockfile --offline \
  --config "patch.crates-io.ogvcs-path-contract.path='$ogvcs020_packed_paths'" \
  --config "patch.crates-io.ogvcs-object-model.path='$ogvcs020_packed_objects'"
CARGO_TARGET_DIR="$ogvcs020_tmp/target" cargo test --locked --offline \
  --config "patch.crates-io.ogvcs-path-contract.path='$ogvcs020_packed_paths'" \
  --config "patch.crates-io.ogvcs-object-model.path='$ogvcs020_packed_objects'"
