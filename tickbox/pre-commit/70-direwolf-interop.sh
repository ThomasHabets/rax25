#!/usr/bin/env bash
set -ueo pipefail
export CARGO_TARGET_DIR="$TICKBOX_CWD/target/${TICKBOX_BRANCH}.test.direwolf"
cd "$TICKBOX_TEMPDIR/work"
bash tests/run_direwolf_interop.sh
