#!/usr/bin/env bash
set -ueo pipefail
cd "$TICKBOX_TEMPDIR/work"
if [[ "${NO_NET:-}" = "true" ]]; then
        exec cargo deny --locked --all-features --workspace --offline check
fi
exec cargo deny --locked --all-features --workspace check
