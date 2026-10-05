#!/bin/bash
# Re-signs SMP.app ad-hoc, innermost code first, and checks the result.
#
# With the Hardened Runtime, macOS only loads frameworks signed with the app's own Team ID (library
# validation). An ad-hoc signature has no Team ID, so an ad-hoc signed SMP with the Hardened Runtime
# can't load Sparkle.framework and quits at launch. Every piece of code in the bundle therefore gets
# the same ad-hoc signature without the Hardened Runtime, whatever the build left behind.
#
# Usage: scripts/adhoc_sign.sh path/to/SMP.app
set -euo pipefail

app="${1:?usage: adhoc_sign.sh path/to/SMP.app}"
root="$(cd "$(dirname "$0")/.." && pwd)"
sparkle="$app/Contents/Frameworks/Sparkle.framework"

for item in "$sparkle"/Versions/B/XPCServices/*.xpc \
            "$sparkle/Versions/B/Autoupdate" \
            "$sparkle/Versions/B/Updater.app" \
            "$sparkle"; do
    if [ -e "$item" ]; then
        codesign --force --sign - --preserve-metadata=entitlements "$item"
    fi
done
codesign --force --sign - --entitlements "$root/App/AgentHelper/SMPAgent.entitlements" \
    "$app/Contents/Library/LoginItems/SMPAgentHelper.app"
codesign --force --sign - --entitlements "$root/App/SMP.entitlements" "$app"

codesign --verify --deep --strict --verbose=2 "$app"
# Every piece of code must be ad-hoc signed (no Team ID) and without the Hardened Runtime.
while IFS= read -r -d '' item; do
    info="$(codesign --display --verbose=2 "$item" 2>&1)"
    if ! grep -q '^TeamIdentifier=not set' <<< "$info" || grep -q 'flags=.*runtime' <<< "$info"; then
        echo "::error::$item is not ad-hoc signed without the Hardened Runtime:"
        echo "$info"
        exit 1
    fi
done < <(find "$app" \( -name '*.app' -o -name '*.framework' -o -name '*.xpc' -o -name Autoupdate \) -print0)
echo "All code in $app is ad-hoc signed without the Hardened Runtime."
