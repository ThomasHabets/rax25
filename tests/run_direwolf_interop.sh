#!/usr/bin/env bash
# Private audio session: never change the desktop's default sinks or sources.
set -euo pipefail

if [[ ${RAX25_PRIVATE_AUDIO:-} != 1 ]]; then
    exec dbus-run-session -- env RAX25_PRIVATE_AUDIO=1 bash "$0" "$@"
fi

cd "$(dirname "$0")/.."
repo_dir=$PWD
target_dir=${CARGO_TARGET_DIR:-"$repo_dir/target"}
if [[ $target_dir != /* ]]; then target_dir="$repo_dir/$target_dir"; fi
if [[ -z ${BELL202_BIN:-} ]]; then
    modem_root="$target_dir/direwolf_interop/rustradio-0.20.2"
    cargo install rustradio --version '=0.20.2' --registry crates-io --locked \
        --example bell202 --features audio --root "$modem_root" \
        --target-dir "$modem_root/build"
    export BELL202_BIN="$modem_root/bin/bell202"
fi

audio_runtime=$(mktemp -d /tmp/rax25-audio.XXXXXX)
audio_logs="$target_dir/direwolf_interop/audio-$(date +%s)-$$"
mkdir -p "$audio_logs"
audio_pids=()
cleanup() {
    for pid in "${audio_pids[@]}"; do kill "$pid" 2>/dev/null || true; done
    for pid in "${audio_pids[@]}"; do wait "$pid" 2>/dev/null || true; done
    rm -rf -- "$audio_runtime"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

export XDG_RUNTIME_DIR="$audio_runtime"
export PIPEWIRE_RUNTIME_DIR="$audio_runtime"
export PULSE_RUNTIME_PATH="$audio_runtime/pulse"
export PULSE_SERVER="unix:$audio_runtime/pulse/native"
export GIO_USE_VFS=local
mkdir -p "$PULSE_RUNTIME_PATH"

pipewire >"$audio_logs/pipewire.log" 2>&1 &
audio_pids+=("$!")
pipewire-pulse >"$audio_logs/pulse.log" 2>&1 &
audio_pids+=("$!")
wireplumber >"$audio_logs/wireplumber.log" 2>&1 &
audio_pids+=("$!")

ready=false
for attempt in {1..100}; do
    if pactl info >"$audio_logs/info.log" 2>&1; then ready=true; break; fi
    sleep 0.1
done
if [[ $ready != true ]]; then
    printf 'Private audio server did not start; see %s\n' "$audio_logs" >&2
    exit 1
fi
printf 'Private audio logs: %s\n' "$audio_logs"
cargo test --features async --test direwolf_interop -- --ignored --nocapture "$@"
