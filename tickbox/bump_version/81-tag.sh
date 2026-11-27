#!/usr/bin/env bash
CURRENT="$(awk '/^version/ {print $3}' Cargo.toml | head -1 | sed 's/"//g')"
if [[ ${1:-} == --print ]]; then
    printf 'v%s\n' "$CURRENT"
    exit 0
fi
exec git tag "v${CURRENT}"
