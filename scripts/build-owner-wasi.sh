#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 MODULE OUTPUT.wasm" >&2
  exit 2
fi

repository=$(cd "$(dirname "$0")/.." && pwd)
source_dir=$(cd "$repository/$1" && pwd)
case "$2" in
  /*) output=$2 ;;
  *) output=$(pwd)/$2 ;;
esac

# Local replacement directories otherwise influence Go compilation actions.
# Generate a transient vendor tree and compile the owned source from that
# closed module graph so identical commits build identically in any checkout.
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

cp -R "$source_dir"/. "$stage"/
rm -rf "$stage/vendor"
(cd "$source_dir" && go mod vendor -o "$stage/vendor")
(cd "$stage" && env GOOS=wasip1 GOARCH=wasm go build \
  -mod=vendor \
  -buildvcs=false \
  -trimpath \
  -buildmode=c-shared \
  -ldflags=-buildid= \
  -o "$output" \
  .)
