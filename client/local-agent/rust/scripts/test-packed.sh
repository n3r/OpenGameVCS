#!/bin/sh
set -eu

ogvcs042_tmp=$(mktemp -d "${TMPDIR:-/tmp}/ogvcs042-packed.XXXXXX")
cleanup() {
  rm -rf "$ogvcs042_tmp"
}
trap cleanup EXIT HUP INT TERM

ogvcs042_candidate=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ogvcs042_repo=$(cd "$ogvcs042_candidate/../../.." && pwd)
ogvcs042_paths="$ogvcs042_repo/core/paths-filesystem/rust"
ogvcs042_objects="$ogvcs042_repo/core/object-model/rust"
ogvcs042_protocol="$ogvcs042_repo/foundation/protocol-baseline/bindings/rust"
ogvcs042_target=${CARGO_TARGET_DIR:-"$ogvcs042_tmp/package-target"}
case "$ogvcs042_target" in
  /*) ;;
  *) ogvcs042_target=$(pwd)/$ogvcs042_target ;;
esac

ogvcs042_config_path() {
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -m "$1"
  else
    printf '%s\n' "$1"
  fi
}

ogvcs042_paths_config=$(ogvcs042_config_path "$ogvcs042_paths")
ogvcs042_objects_config=$(ogvcs042_config_path "$ogvcs042_objects")
ogvcs042_protocol_config=$(ogvcs042_config_path "$ogvcs042_protocol")

CARGO_TARGET_DIR="$ogvcs042_target" cargo package \
  --manifest-path "$ogvcs042_paths/Cargo.toml" --locked --offline --allow-dirty
CARGO_TARGET_DIR="$ogvcs042_target" cargo package \
  --manifest-path "$ogvcs042_objects/Cargo.toml" --locked --offline --allow-dirty
CARGO_TARGET_DIR="$ogvcs042_target" cargo package \
  --manifest-path "$ogvcs042_protocol/Cargo.toml" --offline --allow-dirty
CARGO_TARGET_DIR="$ogvcs042_target" cargo package \
  --manifest-path "$ogvcs042_candidate/Cargo.toml" --locked --offline --allow-dirty \
  --config "patch.crates-io.ogvcs-path-contract.path='$ogvcs042_paths_config'" \
  --config "patch.crates-io.ogvcs-object-model.path='$ogvcs042_objects_config'" \
  --config "patch.crates-io.opengamevcs-protocol-v1.path='$ogvcs042_protocol_config'"

tar -xzf "$ogvcs042_target/package/ogvcs-path-contract-1.0.0.crate" -C "$ogvcs042_tmp"
tar -xzf "$ogvcs042_target/package/ogvcs-object-model-0.1.0.crate" -C "$ogvcs042_tmp"
tar -xzf "$ogvcs042_target/package/opengamevcs-protocol-v1-1.0.0-rc.1.crate" -C "$ogvcs042_tmp"
tar -xzf "$ogvcs042_target/package/ogvcs-local-agent-ipc-0.1.0-rc.1.crate" -C "$ogvcs042_tmp"

cd "$ogvcs042_tmp/ogvcs-local-agent-ipc-0.1.0-rc.1"
ogvcs042_packed_paths=$(ogvcs042_config_path "$ogvcs042_tmp/ogvcs-path-contract-1.0.0")
ogvcs042_packed_objects=$(ogvcs042_config_path "$ogvcs042_tmp/ogvcs-object-model-0.1.0")
ogvcs042_packed_protocol=$(ogvcs042_config_path "$ogvcs042_tmp/opengamevcs-protocol-v1-1.0.0-rc.1")
CARGO_TARGET_DIR="$ogvcs042_tmp/target" cargo generate-lockfile --offline \
  --config "patch.crates-io.ogvcs-path-contract.path='$ogvcs042_packed_paths'" \
  --config "patch.crates-io.ogvcs-object-model.path='$ogvcs042_packed_objects'" \
  --config "patch.crates-io.opengamevcs-protocol-v1.path='$ogvcs042_packed_protocol'"
CARGO_TARGET_DIR="$ogvcs042_tmp/target" cargo test --locked --offline \
  --config "patch.crates-io.ogvcs-path-contract.path='$ogvcs042_packed_paths'" \
  --config "patch.crates-io.ogvcs-object-model.path='$ogvcs042_packed_objects'" \
  --config "patch.crates-io.opengamevcs-protocol-v1.path='$ogvcs042_packed_protocol'"
