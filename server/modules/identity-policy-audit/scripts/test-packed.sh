#!/bin/sh
set -eu

ogvcs009_tmp=$(mktemp -d "${TMPDIR:-/tmp}/ogvcs009-packed.XXXXXX")
cleanup() {
  rm -rf "$ogvcs009_tmp"
}
trap cleanup EXIT HUP INT TERM

ogvcs009_candidate=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ogvcs009_repo=$(cd "$ogvcs009_candidate/../../.." && pwd)
ogvcs009_paths="$ogvcs009_repo/core/paths-filesystem/rust"
ogvcs009_target=${CARGO_TARGET_DIR:-"$ogvcs009_tmp/package-target"}
case "$ogvcs009_target" in
  /*) ;;
  *) ogvcs009_target=$(pwd)/$ogvcs009_target ;;
esac

ogvcs009_config_path() {
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -m "$1"
  else
    printf '%s\n' "$1"
  fi
}

ogvcs009_paths_config=$(ogvcs009_config_path "$ogvcs009_paths")
CARGO_TARGET_DIR="$ogvcs009_target" cargo package \
  --manifest-path "$ogvcs009_paths/Cargo.toml" --locked --offline --allow-dirty
CARGO_TARGET_DIR="$ogvcs009_target" cargo package \
  --manifest-path "$ogvcs009_candidate/Cargo.toml" --locked --offline --allow-dirty \
  --no-verify \
  --config "patch.crates-io.ogvcs-path-contract.path='$ogvcs009_paths_config'"

mkdir -p "$ogvcs009_tmp/server/modules" "$ogvcs009_tmp/server/migrations" \
  "$ogvcs009_tmp/spec/identity-policy-audit/v1/vectors"
tar -xzf "$ogvcs009_target/package/ogvcs-path-contract-1.0.0.crate" -C "$ogvcs009_tmp"
tar -xzf "$ogvcs009_target/package/ogvcs-identity-policy-audit-postgres-0.2.0.crate" \
  -C "$ogvcs009_tmp/server/modules"
cp -R "$ogvcs009_repo/server/migrations/identity-policy-audit" \
  "$ogvcs009_tmp/server/migrations/"
cp "$ogvcs009_repo/spec/identity-policy-audit/v1/vectors/authorized-resource-batch-golden.json" \
  "$ogvcs009_tmp/spec/identity-policy-audit/v1/vectors/"

ogvcs009_packed="$ogvcs009_tmp/server/modules/ogvcs-identity-policy-audit-postgres-0.2.0"
ogvcs009_packed_paths=$(ogvcs009_config_path "$ogvcs009_tmp/ogvcs-path-contract-1.0.0")
cd "$ogvcs009_packed"
CARGO_TARGET_DIR="$ogvcs009_tmp/target" cargo generate-lockfile --offline \
  --config "patch.crates-io.ogvcs-path-contract.path='$ogvcs009_packed_paths'"
CARGO_TARGET_DIR="$ogvcs009_tmp/target" cargo test --locked --offline --all-targets \
  --config "patch.crates-io.ogvcs-path-contract.path='$ogvcs009_packed_paths'"
CARGO_TARGET_DIR="$ogvcs009_tmp/target" cargo test --locked --offline --doc \
  --config "patch.crates-io.ogvcs-path-contract.path='$ogvcs009_packed_paths'"
