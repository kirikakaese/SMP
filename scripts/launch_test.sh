#!/bin/bash
# Starts SMP.app and checks that it is still running after a while. Catches anything that stops SMP
# from starting at all, such as a framework macOS refuses to load.
#
# Usage: scripts/launch_test.sh path/to/SMP.app [seconds]
set -euo pipefail

app="${1:?usage: launch_test.sh path/to/SMP.app [seconds]}"
seconds="${2:-15}"
log="$(mktemp)"

"$app/Contents/MacOS/SMP" > "$log" 2>&1 &
pid=$!
sleep "$seconds"
if ! kill -0 "$pid" 2> /dev/null; then
    echo "::error::SMP quit within $seconds seconds of starting."
    cat "$log"
    exit 1
fi
kill "$pid"
echo "SMP started and kept running for $seconds seconds."
