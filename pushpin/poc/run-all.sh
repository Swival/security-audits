#!/usr/bin/env bash
# Build and run every PoC. Prints per-PoC verdict and a final summary.
set -u

cd "$(dirname "$0")"

declare -a names=(
    "001-unix-socket"
    "007-sockjs-frames"
    "012-content-length"
    "015-jsonp-callback"
    "022-instruct-headers"
    "023-instruct-reason"
    "024-grip-status-reason"
    "030-cors-reflect"
)

pass=0
fail=0
results=()

for n in "${names[@]}"; do
    echo
    echo "===================================================================="
    echo " $n"
    echo "===================================================================="
    if [[ -f "$n/Cargo.toml" ]]; then
        ( cd "$n" && cargo run --release --quiet )
    else
        ( cd "$n" && make --quiet run )
    fi
    rc=$?
    if [[ $rc -eq 0 ]]; then
        results+=("PASS  $n")
        pass=$((pass+1))
    else
        results+=("FAIL  $n (exit $rc)")
        fail=$((fail+1))
    fi
done

echo
echo "===================================================================="
echo " Summary"
echo "===================================================================="
for r in "${results[@]}"; do echo " $r"; done
echo
echo " $pass reproduced, $fail not reproduced"

[[ $fail -eq 0 ]]
