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

## `verify_pr299.py`  (pure Python, no deps, ~1.5 min)

An affine Edwards implementation written from the curve equation.  It

- checks the field facts the completeness theorem needs (`p = 1 mod 4`,
  `d` a non-square, `1 + d != 0`);
- checks claim 1 algebraically and on every 8-torsion point;
- transcribes `ge_add`, `ge_madd`, `ge_double` line by line from
  `monocypher.c` and checks, on all 64 ordered pairs of 8-torsion points,
  on `P+P`, `P-P`, `P + torsion` and random pairs, with random projective
  representatives: correct result, `Z3 != 0`, `T == XY/Z` preserved, and
  the factorisations `Z3 = 4 Z1² Z2² (1 ± d x1x2y1y2)` and
  `Z3 = Z⁴ (1 ± d x²y²)` quoted in the PR comment;
- checks `old_check(P) == new_check(P)` for random representatives of
  small-order and random points, and shows they differ only at `Z == 0`;
- writes `pr299_vectors.h` (next to the script, not committed): 5494 `(sig, pk, h, verdict)` cases with the
  verdict computed in Python.  3344 are cofactored accepts with every
  combination of 8-torsion components in `A` and `R`, including
  small-order keys, small-order `R`, and non-canonical encodings
  (`y + p`, and `x == 0` with sign bit set) — the "bogus" signatures
  ed25519-zebra and Monocypher both accept.

    python3 tests/pr299/verify_pr299.py

## `run.sh` + `diff_check.c`  (~40 s)

Builds `master`'s `monocypher.c` with every public symbol renamed
`old_crypto_*`, links it with the working tree's `monocypher.c`, and
compares `crypto_eddsa_check_equation` / `crypto_eddsa_check` verdicts on:

- the 5494 Python vectors (old == new == Python);
- 200 fresh signatures, every single-byte and single-bit corruption of
  each signature and public key (173k cases), tampered messages;
- 20k random inputs, half with on-curve `A` and `R`.

    sh tests/pr299/run.sh      # OLD=<ref> to compare against another revision

Expected last line: `... 0 mismatches`.

The harness was mutation-tested: dropping the `- 1`, comparing `Y` to `X`
instead of `Z`, and removing one of the three doublings are each caught
by the Python vectors.
