#!/bin/sh
# Differential test for Monocypher PR #299.
#
# Usage, from a Monocypher checkout with the PR branch checked out
# (or any branch: NEW defaults to the working tree, OLD to master):
#
#   sh path/to/run.sh
#
# Builds master's src/monocypher.c with every public crypto_* symbol
# renamed old_crypto_*, links it with the working tree's monocypher.c,
# and runs diff_check.c, which calls both and compares verdicts.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
OLD=${OLD:-master}
CC=${CC:-cc}
CFLAGS=${CFLAGS:--O2 -Wall -Wextra}

test -f src/monocypher.c || { echo "run from a Monocypher checkout" >&2; exit 1; }
test -f "$HERE/pr299_vectors.h" || python3 "$HERE/verify_pr299.py"

BUILD=$(mktemp -d)
trap 'rm -rf "$BUILD"' EXIT
mkdir "$BUILD/old"
git show "$OLD:src/monocypher.c" > "$BUILD/old/monocypher.c"
git show "$OLD:src/monocypher.h" > "$BUILD/old/monocypher.h"

# rename every public identifier declared in the header
RENAMES=$(grep -o 'crypto_[a-z0-9_]*' "$BUILD/old/monocypher.h" | sort -u \
          | sed 's/.*/-D&=old_&/' | tr '\n' ' ')
# shellcheck disable=SC2086
$CC $CFLAGS -I "$BUILD/old" $RENAMES -c "$BUILD/old/monocypher.c" -o "$BUILD/old.o"
$CC $CFLAGS -I src -c src/monocypher.c -o "$BUILD/new.o"
$CC $CFLAGS -I src -I "$HERE" "$HERE/diff_check.c" "$BUILD/old.o" "$BUILD/new.o" \
    -o "$BUILD/diff_check"
echo "old = $(git rev-parse --short "$OLD")  new = working tree ($(git rev-parse --short HEAD))"
"$BUILD/diff_check"
