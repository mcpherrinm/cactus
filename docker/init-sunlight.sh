#!/bin/sh
# Init step 2 of 3 (runs in the sunlight image).
#
# Derives Sunlight's witness/mirror keys from a single seed, builds the
# log list naming cactus's issuance log, and pre-creates the checkpoint
# lock database. Sunlight deliberately refuses to create that database
# itself, as a guard against pointing a log at the wrong backend, so it
# has to exist before first start.
#
# Idempotent, for the same reason as init-cactus.sh.
set -eu

SHARED=/shared
DB=/var/lib/sunlight/checkpoints.db
SEED=/var/lib/sunlight/witness-seed.bin
LOGS=/var/lib/sunlight/logs.txt
CFG=/var/lib/sunlight/sunlight.yaml

# The witness cosigner name is a hostname; the mirror cosigner name is
# an OID name, so that Sunlight publishes a cosigner_id for it and the
# cosignature slots into an MTC proof unchanged. They MUST differ.
WITNESS_NAME="${SUNLIGHT_WITNESS_NAME:-sunlight.mirror.test}"
MIRROR_NAME="${SUNLIGHT_MIRROR_NAME:-oid/1.3.6.1.4.1.44363.47.2.1}"

# skylight opens the public directory at startup and exits if it is
# missing; sunlight only creates it lazily on first upload.
mkdir -p /var/lib/sunlight /var/lib/sunlight/public "$SHARED"

# Wait for cactus's init to publish the log vkey; without it the log
# list would be empty and every push would 404 on an unknown origin.
i=0
while [ ! -s "$SHARED/cactus-log.vkey" ]; do
    i=$((i + 1))
    if [ "$i" -gt 60 ]; then
        echo "init-sunlight: timed out waiting for $SHARED/cactus-log.vkey" >&2
        exit 1
    fi
    sleep 1
done

if [ ! -f "$SEED" ]; then
    echo "init-sunlight: generating witness/mirror seed"
    sunlight-keygen -f "$SEED" -witness "$WITNESS_NAME" -mirror "$MIRROR_NAME"
else
    echo "init-sunlight: reusing existing seed"
fi

# Re-print the keys so we can capture the mirror vkey. sunlight-keygen
# is idempotent on an existing seed: it derives and prints, and only
# writes when the file is absent.
sunlight-keygen -f "$SEED" -witness "$WITNESS_NAME" -mirror "$MIRROR_NAME" -json \
    > "$SHARED/sunlight-keys.json"

# The mirror's public key, for cactus's cosigner quorum config.
grep -o '"mirror_vkey_mldsa44"[[:space:]]*:[[:space:]]*"[^"]*"' "$SHARED/sunlight-keys.json" \
    | sed 's/.*: *"//; s/"$//' > "$SHARED/sunlight-mirror.vkey"

if [ ! -s "$SHARED/sunlight-mirror.vkey" ]; then
    echo "init-sunlight: could not extract mirror_vkey_mldsa44" >&2
    exit 1
fi

# Log list (`logs/v0`) naming cactus's issuance log. The `origin` line is
# REQUIRED here: it defaults to the vkey name, but for cactus the vkey is
# named after the cosigner (the CA ID) while the checkpoint origin is the
# log ID. Without it sunlight would look for a log whose origin is the
# cosigner name and never match the pushed checkpoint.
{
    echo "logs/v0"
    echo
    echo "vkey $(cat "$SHARED/cactus-log.vkey")"
    echo "origin $(cat "$SHARED/cactus-log.origin")"
} > "$LOGS"

if [ ! -f "$DB" ]; then
    echo "init-sunlight: creating checkpoint lock database"
    sqlite3 "$DB" \
        "CREATE TABLE checkpoints (logID BLOB PRIMARY KEY, body BLOB NOT NULL) STRICT"
fi

# Keep-alive CT log. Sunlight exits immediately with no logs configured
# (see the comment in sunlight.yaml.tmpl), so we run one throwaway log we
# never submit to. Its seed is separate from the witness seed, and its
# roots file is empty so startup does not reach out to CCADB.
[ -f /var/lib/sunlight/keepalive-seed.bin ] || \
    sunlight-keygen -f /var/lib/sunlight/keepalive-seed.bin >/dev/null
: > /var/lib/sunlight/keepalive-roots.pem

# Render the config. The inception date must be today the first time the
# log is created; afterwards the stored log is found and the date is not
# consulted, so pinning the rendered file keeps restarts working.
if [ ! -f "$CFG" ]; then
    sed -e "s|__INCEPTION__|$(date -u +%Y-%m-%d)|" \
        -e "s|__NOTAFTER_START__|$(date -u +%Y)-01-01T00:00:00Z|" \
        -e "s|__NOTAFTER_LIMIT__|$(($(date -u +%Y) + 1))-01-01T00:00:00Z|" \
        /docker/sunlight.yaml.tmpl > "$CFG"
    echo "init-sunlight: rendered $CFG (inception $(date -u +%Y-%m-%d))"
fi

echo "init-sunlight: log list:"
cat "$LOGS"
echo "init-sunlight: mirror vkey -> $SHARED/sunlight-mirror.vkey"
cat "$SHARED/sunlight-mirror.vkey"
