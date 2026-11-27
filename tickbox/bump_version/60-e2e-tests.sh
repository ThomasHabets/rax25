#!/usr/bin/env bash
# Step 61 handles Dire Wolf with its modem and audio dependencies.
exec cargo test --workspace --release -- --ignored --skip direwolf_
