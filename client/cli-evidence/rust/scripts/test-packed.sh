#!/bin/sh
set -eu

ogvcs043_tmp=$(mktemp -d "${TMPDIR:-/tmp}/ogvcs043-packed.XXXXXX")
cleanup() {
  rm -rf "$ogvcs043_tmp"
}
trap cleanup EXIT HUP INT TERM

ogvcs043_validator=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ogvcs043_repo=$(cd "$ogvcs043_validator/../../.." && pwd)
ogvcs043_deployment="$ogvcs043_repo/core/deployment-preflight/rust"
ogvcs043_objects="$ogvcs043_repo/core/object-model/rust"
ogvcs043_target=${CARGO_TARGET_DIR:-"$ogvcs043_tmp/package-target"}
case "$ogvcs043_target" in
  /*) ;;
  *) ogvcs043_target=$(pwd)/$ogvcs043_target ;;
esac

ogvcs043_config_path() {
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -m "$1"
  else
    printf '%s\n' "$1"
  fi
}

ogvcs043_deployment_config=$(ogvcs043_config_path "$ogvcs043_deployment")
ogvcs043_objects_config=$(ogvcs043_config_path "$ogvcs043_objects")
CARGO_TARGET_DIR="$ogvcs043_target" cargo package \
  --manifest-path "$ogvcs043_deployment/Cargo.toml" --locked --offline --allow-dirty
CARGO_TARGET_DIR="$ogvcs043_target" cargo package \
  --manifest-path "$ogvcs043_objects/Cargo.toml" --locked --offline --allow-dirty
CARGO_TARGET_DIR="$ogvcs043_target" cargo package \
  --manifest-path "$ogvcs043_validator/Cargo.toml" --locked --offline --allow-dirty \
  --config "patch.crates-io.ogvcs-deployment-preflight.path='$ogvcs043_deployment_config'" \
  --config "patch.crates-io.ogvcs-object-model.path='$ogvcs043_objects_config'"

tar -xzf "$ogvcs043_target/package/ogvcs-deployment-preflight-0.1.0-rc.3.crate" \
  -C "$ogvcs043_tmp"
tar -xzf "$ogvcs043_target/package/ogvcs-object-model-0.1.0.crate" -C "$ogvcs043_tmp"
tar -xzf "$ogvcs043_target/package/ogvcs-cli-evidence-validator-0.1.0-rc.2.crate" \
  -C "$ogvcs043_tmp"
cd "$ogvcs043_tmp/ogvcs-cli-evidence-validator-0.1.0-rc.2"
ogvcs043_packed_deployment=$(ogvcs043_config_path \
  "$ogvcs043_tmp/ogvcs-deployment-preflight-0.1.0-rc.3")
ogvcs043_packed_objects=$(ogvcs043_config_path "$ogvcs043_tmp/ogvcs-object-model-0.1.0")
CARGO_TARGET_DIR="$ogvcs043_tmp/target" cargo generate-lockfile --offline \
  --config "patch.crates-io.ogvcs-deployment-preflight.path='$ogvcs043_packed_deployment'" \
  --config "patch.crates-io.ogvcs-object-model.path='$ogvcs043_packed_objects'"
CARGO_TARGET_DIR="$ogvcs043_tmp/target" cargo test --locked --offline \
  --config "patch.crates-io.ogvcs-deployment-preflight.path='$ogvcs043_packed_deployment'" \
  --config "patch.crates-io.ogvcs-object-model.path='$ogvcs043_packed_objects'"
