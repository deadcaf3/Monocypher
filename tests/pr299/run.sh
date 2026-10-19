#!/bin/sh
# Differential test for Monocypher PR #299.
#
# Usage, from the root of a Monocypher checkout with the PR branch
# checked out (or any branch: NEW defaults to the working tree, OLD to
# master):
#
#   sh tests/pr299/run.sh
#
# Builds master's src/monocypher.c with every public crypto_* symbol
# renamed old_crypto_*, links it with the working tree's monocypher.c,
# and runs diff_check.c, which calls both and compares verdicts.
#
# Every step prints a line before it runs and ok/FAILED with the elapsed
# time after, so a stuck run shows where it stopped.  NO_COLOR honoured.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
OLD=${OLD:-master}
CC=${CC:-cc}
CFLAGS=${CFLAGS:--O2 -Wall -Wextra}

T0=$(date +%s)
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
	BOLD=$(printf '\033[1m'); DIM=$(printf '\033[2m')
	GREEN=$(printf '\033[32m'); RED=$(printf '\033[31m'); OFF=$(printf '\033[0m')
else
	BOLD=; DIM=; GREEN=; RED=; OFF=
fi
STEP=setup
BUILD=
elapsed() { printf '%ds' "$(( $(date +%s) - T0 ))"; }
step() { STEP=$1; printf '%s[%4s]%s %s ... ' "$DIM" "$(elapsed)" "$OFF" "$1"; }
ok()   { printf '%sok%s\n' "$GREEN" "$OFF"; }
finish() {
	rc=$?
	[ -n "$BUILD" ] && rm -rf "$BUILD"
	if [ $rc -eq 0 ]; then
		printf '\n%s%sall OK%s %s(total %s)%s\n' "$BOLD" "$GREEN" "$OFF" "$DIM" "$(elapsed)" "$OFF"
	else
		printf '\n%s%sFAILED%s during: %s (exit %d, after %s)\n' "$BOLD" "$RED" "$OFF" "$STEP" "$rc" "$(elapsed)"
	fi
}
trap finish EXIT

printf '%s== Monocypher PR #299: differential check, old vs new ==%s\n' "$BOLD" "$OFF"

step "checking for src/monocypher.c (run from the checkout root)"
test -f src/monocypher.c || { echo "run from a Monocypher checkout" >&2; exit 1; }
ok

if [ -f "$HERE/pr299_vectors.h" ]; then
	step "reusing $HERE/pr299_vectors.h"
	ok
else
	step "generating pr299_vectors.h with verify_pr299.py (about 1.5 min)"
	echo
	python3 "$HERE/verify_pr299.py"
	echo
fi

BUILD=$(mktemp -d)
mkdir "$BUILD/old"
OLDREV=$(git rev-parse --short "$OLD")
step "extracting $OLD ($OLDREV): src/monocypher.c and src/monocypher.h"
git show "$OLD:src/monocypher.c" > "$BUILD/old/monocypher.c"
git show "$OLD:src/monocypher.h" > "$BUILD/old/monocypher.h"
ok

# rename every public identifier declared in the header
RENAMES=$(grep -o 'crypto_[a-z0-9_]*' "$BUILD/old/monocypher.h" | sort -u \
          | sed 's/.*/-D&=old_&/' | tr '\n' ' ')
NREN=$(printf '%s' "$RENAMES" | wc -w | tr -d ' ')
step "compiling old monocypher.c with $NREN symbols renamed old_crypto_*"
# shellcheck disable=SC2086
$CC $CFLAGS -I "$BUILD/old" $RENAMES -c "$BUILD/old/monocypher.c" -o "$BUILD/old.o"
ok

step "compiling working-tree src/monocypher.c ($(git rev-parse --short HEAD)$(git diff --quiet -- src/monocypher.c || printf ' + uncommitted changes'))"
$CC $CFLAGS -I src -c src/monocypher.c -o "$BUILD/new.o"
ok

step "compiling diff_check.c and linking old.o + new.o"
$CC $CFLAGS -I src -I "$HERE" "$HERE/diff_check.c" "$BUILD/old.o" "$BUILD/new.o" \
    -o "$BUILD/diff_check"
ok

step "running diff_check: old = $OLDREV, new = working tree"
echo
"$BUILD/diff_check"
