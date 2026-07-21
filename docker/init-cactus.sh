#!/bin/sh
# Init step 1 of 2 (runs in the cactus image).
#
# Generates the CA cosigner seed if absent and exports the issuance
# log's c2sp vkey, which Sunlight needs in its log list before it will
# accept any mirror push from us.
#
# Everything is idempotent: re-running leaves existing key material
# alone, so `docker compose up` twice does not rotate keys out from
# under a log that has already been mirrored.
set -eu

SHARED=/shared
KEYS=/var/lib/cactus/keys
SEED="$KEYS/ca-cosigner.seed"

# CA ID (§5.1). The log ID is derived as <CA-ID>.0.<log number> (§5.2),
# and that derived ID is what appears in the checkpoint origin line.
CA_ID="${CACTUS_CA_ID:-44363.47.1.99}"
LOG_NUMBER="${CACTUS_LOG_NUMBER:-1}"

mkdir -p "$KEYS" "$SHARED"

if [ ! -f "$SEED" ]; then
    echo "init-cactus: generating CA cosigner seed"
    cactus-keygen -o "$SEED"
else
    echo "init-cactus: reusing existing CA cosigner seed"
fi

# The log's signing identity as Sunlight's log list wants it:
#   vkey <name>+<hex key ID>+<base64(0x06 || 1312-byte ML-DSA-44 key)>
#
# The vkey name is the COSIGNER name (the CA ID, §5.4), because that is
# what labels the checkpoint's signature line. The checkpoint's *origin*
# line is the log ID, which differs — so we export it separately and the
# log list carries it on its own `origin` line. Naming the vkey after the
# log ID instead makes the key unmatchable and add-checkpoint 403s.
cactus-keygen -o "$SEED" -vkey -cosigner-id "$CA_ID" \
    > "$SHARED/cactus-log.vkey"
printf 'oid/1.3.6.1.4.1.%s.0.%s\n' "$CA_ID" "$LOG_NUMBER" \
    > "$SHARED/cactus-log.origin"

echo "init-cactus: log vkey  -> $SHARED/cactus-log.vkey"
echo "init-cactus: log origin -> $(cat "$SHARED/cactus-log.origin")"
