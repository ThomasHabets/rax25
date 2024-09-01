#!/usr/bin/env bash
set -euo pipefail
if [[ -n "$(git status --porcelain)" ]]; then
        echo "Local repo not clean"
        git status
        exit 1
fi
PATCH="$(sed -rn '/^version/{s/.*= *"[0-9]+[.][0-9]+[.]([0-9]+)"/\1/;p}' Cargo.toml)"
PATCH=$(( PATCH + 1 ))
sed -ri 's/^(version = "[0-9]+[.][0-9])[.].*/\1'.$PATCH'"/' Cargo.toml
VER="$(sed -rn '/^version/{s/.*= *"([0-9]+[.][0-9]+[.][0-9]+)"/\1/;p}' Cargo.toml)"
git add Cargo.toml
git commit -a -m"Bump version to ${VER}"
cargo publish
exec git push
