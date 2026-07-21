#!/bin/sh
# Init step 3 of 3 (runs in the cactus image, after sunlight-init).
#
# Converts Sunlight's mirror cosigner vkey into the PEM public key form
# cactus's ca_cosigner_quorum config consumes. cactus-keygen recomputes
# the key ID from the name and key while doing so, so a truncated or
# mistyped vkey fails here rather than silently producing a cosigner
# whose signatures never match anything.
set -eu

SHARED=/shared
KEYS=/var/lib/cactus/keys

if [ ! -s "$SHARED/sunlight-mirror.vkey" ]; then
    echo "init-wire: $SHARED/sunlight-mirror.vkey missing or empty" >&2
    exit 1
fi

mkdir -p "$KEYS"
cactus-keygen -from-vkey "$(cat "$SHARED/sunlight-mirror.vkey")" \
    > "$KEYS/sunlight-mirror.pem"

echo "init-wire: wrote $KEYS/sunlight-mirror.pem"
head -1 "$KEYS/sunlight-mirror.pem"
