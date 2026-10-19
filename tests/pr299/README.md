# Verification aids for Monocypher PR #299

The PR replaces `ge_tobytes + crypto_verify32` with `fe_isequal(Y, Z)` at
the end of `crypto_eddsa_check_equation()`.  Both are tests on the final
point `P = [8]([s]B - [h]A - R)`, and they agree exactly when

1. on the curve, `y == 1` forces `x == 0` (so the old `sign(x) == 0`
   requirement was redundant), and
2. `Z` is never `0`.  This is the load-bearing claim: `fe_invert(0) == 0`,
   so with `Z == 0` the old check computes `y == 0` and rejects, while
   `Y == Z == 0` would make the new check accept.  It holds because the
   Edwards addition law is complete (BL 2007 Thm 3.3; BBJLP 2008 §6) and
   `ge_add`, `ge_madd`, `ge_double` are the complete HWCD formulas.

Two independent things to run, from the root of this checkout (the branch
contains the PR change plus this directory):

## `verify_pr299.py`  (pure Python, no deps, ~45 s)

An affine Edwards implementation written from the curve equation.  It

1. checks the field facts the completeness theorem needs: `p` and `L`
   prime (Miller-Rabin), `p = 5 mod 8`, `a = -1` a square with an
   explicit root, `d` a non-square two independent ways, `d != +-1`,
   `d y^2 + 1 != 0` on 110k values, and that `B` is the RFC 8032 base
   point with the RFC encoding; builds `E[8]` and checks its orders and
   that `[L]P` lands in it for random `P`;
2. checks claim 1 algebraically, by sweeping 110k values of `x`, on
   every 8-torsion point, on `[k]B + T` for `k < 1000`, and on the
   non-canonical encodings of `y = 1`;
3. transcribes `ge_add`, `ge_sub`, `ge_madd`, `ge_msub`, `ge_double`
   line by line from `monocypher.c` and checks, against the affine
   reference: correct result, `Z3 != 0`, `T == XY/Z`, on the curve, and
   the factorisations `Z3 = 4 Z1² Z2² (1 ± d x1x2y1y2)` and
   `Z3 = Z⁴ (1 ± d x²y²)` quoted in the PR comment.  Inputs: all 64
   ordered pairs of 8-torsion points with 32 random and 64 edge-value
   projective representatives, all 576 pairs of 24 special-coordinate
   points (`x` or `y` in `{0, ±1, ±2, ±3, ±4, ±8, ±19, ±i, ±1/2}`), 400
   rounds of random `P+P`, `P-P`, `P+Q`, `P ± P + torsion`, 256-long
   doubling chains, and full NAF scalar-multiplication ladders through
   both the `ge_cached` and the `Z = 1` precomp paths with every
   intermediate point compared to the affine value;
4. checks `old_check(P) == new_check(P)` on 4000 representatives of the
   8-torsion points, edge `Z` values, special points, `[k]B + T` for
   `k < 256`, 2000 random points, and shows exactly when they would
   differ: `Z == 0`, where the old test always rejects and the new one
   accepts iff `Y == 0`;
5. writes `pr299_vectors.h` (next to the script, not committed): 16534
   `(sig, pk, h, verdict)` cases, verdict computed in Python.  7927 are
   accepts: every combination of 8-torsion components in `A` and `R`
   for `k, r, h` in `{0, 1, L-1, random}`, including small-order keys,
   small-order `R`, non-canonical encodings (`y + p`, and `x == 0` with
   sign bit set), all-zero inputs, and a wrong `h` or a flipped sign bit
   whenever the cofactor still absorbs it — the "bogus" signatures
   ed25519-zebra and Monocypher both accept.  The rejects are `s ± 1`,
   `s + L`, `s >= L`, flipped sign bits, wrong `h`, random off-curve and
   random on-curve inputs.  It then runs a projective mirror of
   `crypto_eddsa_check_equation` (same decode, `s < L` check, ladder,
   `- R`, three doublings) over every vector and checks that the old
   final test and the new final test both equal the affine verdict.

    python3 tests/pr299/verify_pr299.py

## `run.sh` + `diff_check.c`  (~30 s)

Builds `master`'s `monocypher.c` with every public symbol renamed
`old_crypto_*`, links it with the working tree's `monocypher.c`, and
compares `crypto_eddsa_check_equation` / `crypto_eddsa_check` verdicts on:

- the 16534 Python vectors (old == new == Python);
- 16 fresh signatures, every single-byte and single-bit corruption of
  each signature and public key (14k cases), tampered messages;
- 5k random inputs, half with on-curve `A` and `R`.

    sh tests/pr299/run.sh                   # OLD=<ref>: other base revision
    SIGS=200 RANDOM=20000 sh tests/pr299/run.sh   # long run, ~1 min

Expected last line: `all OK`.

Both print every step before running it, with a progress counter for the
long loops and the elapsed time when it finishes, so a run that looks
stuck shows exactly where it is.  An assertion failure or Ctrl-C names
the step it happened in.  Output is coloured on a terminal and plain
when piped; set `NO_COLOR` to disable colour.

The harness was mutation-tested: dropping the `- 1`, comparing `Y` to `X`
instead of `Z`, and removing one of the three doublings are each caught
by the Python vectors.
