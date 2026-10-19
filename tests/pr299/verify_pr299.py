#!/usr/bin/env python3
"""Independent check of the two claims behind Monocypher PR #299.

Pure Python, no dependencies.  Everything is done on plain integers
with an affine Edwards implementation written from the curve equation,
so nothing here depends on Monocypher's own arithmetic.

PR #299 replaces, at the end of crypto_eddsa_check_equation():

    ge_tobytes(check, sum);                   // old: encode, compare
    return crypto_verify32(check, zero_point);
with
    return fe_isequal(sum->Y, sum->Z) - 1;    // new: y == 1 ?

Both tests are functions of the final point P = [8]([s]B - [h]A - R).
They agree iff:

  claim 1:  on the curve, y == 1 forces x == 0, so the old encoding of
            P equals {1, 0, ..., 0} exactly when y == 1.  (Note the old
            check ALSO required sign(x) == 0; claim 1 makes that free.)
  claim 2:  Z is never 0, so "Y == Z" really means "y == 1".  If Z could
            be 0 the two checks would NOT agree: ge_tobytes uses
            fe_invert(0) == 0, giving y == 0 and a reject, while
            Y == Z == 0 would make the new check accept.

Claim 2 is the Edwards completeness theorem (Bernstein-Lange 2007,
Thm 3.3; Bernstein-Birkner-Joye-Lange-Peters 2008, Sec. 6), applied
to the exact formulas in monocypher.c.  This script

  1. checks the field facts the theorem needs (a = -1 square, d not),
  2. checks claim 1 algebraically and on every small-order point,
  3. transcribes ge_add / ge_madd / ge_double from monocypher.c line by
     line and checks, against the affine reference, that they are the
     complete Hisil-Wong-Carter-Dawson formulas: correct result, Z != 0,
     and the Z3 factorisation quoted in the PR comment, on every pair of
     8-torsion points (the exceptional inputs of incomplete formulas),
     on P +/- P, P + torsion, and on random pairs,
  4. checks old_check(P) == new_check(P) on random projective
     representatives of every small-order point and of random points,
  5. writes pr299_vectors.h: cofactored ("Zebra-style") accept/reject
     cases for the differential C harness, with the verdict computed
     here, independently of either C implementation.
"""
import os
import random
import sys

random.seed(299)

p = 2**255 - 19
d = (-121665 * pow(121666, -1, p)) % p
L = 2**252 + 27742317777372353535851937790883648493
D2 = 2 * d % p                     # monocypher.c: D2 = 2*d, used by ge_cache
sqrtm1 = pow(2, (p - 1) // 4, p)
assert sqrtm1 * sqrtm1 % p == p - 1


def legendre(a):
    return pow(a % p, (p - 1) // 2, p)


def sqrt_mod_p(a):
    """Square root mod p (p = 5 mod 8), or None."""
    a %= p
    x = pow(a, (p + 3) // 8, p)
    if x * x % p == a:
        return x
    x = x * sqrtm1 % p
    if x * x % p == a:
        return x
    return None


# --------------------------------------------------------------------
# 1. Field facts required by the completeness theorem
# --------------------------------------------------------------------
# Twisted Edwards  a x^2 + y^2 = 1 + d x^2 y^2  with a = -1.
# BBJLP 2008 Sec. 6: the formulas are complete if a is a square and d
# is not.  BL 2007 Thm 3.3 (the actual proof): d non-square implies
# d x1 x2 y1 y2 != +-1 for any two points on the curve.
assert p % 4 == 1, "p = 1 mod 4 so -1 is a square"
assert legendre(p - 1) == 1, "a = -1 is a square in F_p"
assert legendre(d) == p - 1, "d is not a square in F_p"
assert (1 + d) % p != 0, "needed by claim 1 (d != -1)"
# Decoding never divides by zero: d y^2 + 1 == 0 would need y^2 = -1/d,
# and -1/d is a non-square (square / non-square).
assert legendre((-pow(d, -1, p)) % p) == p - 1
print("1. field facts: p = 1 mod 4, a = -1 square, d non-square, 1+d != 0  OK")


# --------------------------------------------------------------------
# Affine reference implementation (written from the curve equation)
# --------------------------------------------------------------------
IDENTITY = (0, 1)


def on_curve(P):
    x, y = P
    return (-x * x + y * y - 1 - d * x * x * y * y) % p == 0


def aff_add(P, Q):
    x1, y1 = P
    x2, y2 = Q
    k = d * x1 * x2 * y1 * y2 % p
    x3 = (x1 * y2 + y1 * x2) * pow(1 + k, -1, p) % p
    y3 = (y1 * y2 + x1 * x2) * pow(1 - k, -1, p) % p   # a = -1: y1y2 - a x1x2
    return (x3, y3)


def aff_neg(P):
    return ((-P[0]) % p, P[1])


def aff_mul(k, P):
    R = IDENTITY
    while k:
        if k & 1:
            R = aff_add(R, P)
        P = aff_add(P, P)
        k >>= 1
    return R


def aff_encode(P):
    """RFC 8032 encoding: y, with sign(x) in the top bit."""
    x, y = P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def mc_decode(s):
    """Monocypher's ge_frombytes_neg_vartime, un-negated, as a Python
    function: returns the point or None.  Mirrors the C exactly:
    non-canonical y (y >= p) is reduced; x = 0 with sign bit 1 is
    accepted (the C never negates 0, so it just yields x = 0)."""
    v = int.from_bytes(s, "little")
    sign = v >> 255
    y = (v & (2**255 - 1)) % p
    num = (y * y - 1) % p
    den = (d * y * y + 1) % p
    x = sqrt_mod_p(num * pow(den, -1, p))
    if x is None:
        return None
    if x & 1 != sign:
        x = (-x) % p
    return (x, y)


# Base point B: y = 4/5, x even.
By = 4 * pow(5, -1, p) % p
Bx = sqrt_mod_p((By * By - 1) * pow(d * By * By + 1, -1, p))
if Bx & 1:
    Bx = p - Bx
B = (Bx, By)
assert on_curve(B)
assert aff_mul(L, B) == IDENTITY

# The 8-torsion subgroup E[8].  A random point times L has order
# dividing 8; pick one of order exactly 8 and take its multiples.
while True:
    # [k]B is in the prime-order subgroup, so push it out with a random
    # x-coordinate instead: pick random y, solve for x, multiply by L.
    y = random.randrange(p)
    x = sqrt_mod_p((y * y - 1) * pow(d * y * y + 1, -1, p))
    if x is None:
        continue
    T8 = aff_mul(L, (x, y))
    if aff_mul(4, T8) != IDENTITY:        # order exactly 8
        break
TORSION = [aff_mul(i, T8) for i in range(8)]
assert len(set(TORSION)) == 8
assert all(on_curve(T) and aff_mul(8, T) == IDENTITY for T in TORSION)
assert TORSION[0] == IDENTITY


# --------------------------------------------------------------------
# 2. Claim 1: y == 1 only at the identity
# --------------------------------------------------------------------
# Put y = 1 in -x^2 + y^2 = 1 + d x^2 y^2  ->  (1 + d) x^2 = 0  ->  x = 0.
# On any point with y == 1, x^2 = (y^2 - 1) / (d y^2 + 1) = 0 / (d+1) = 0.
assert sqrt_mod_p(0) == 0
assert (0 * pow(d + 1, -1, p)) % p == 0
# and the only such point is the identity, which the old check compared
# against:  encode((0, 1)) == 01 00 00 ... 00
assert aff_encode(IDENTITY) == bytes([1] + [0] * 31)
# Sanity on the small-order points: exactly one has y == 1.
assert [T for T in TORSION if T[1] == 1] == [IDENTITY]
print("2. claim 1: y == 1  =>  x == 0; only the identity, encoded 01 00..00  OK")


# --------------------------------------------------------------------
# 3. Monocypher's projective formulas, transcribed line by line
# --------------------------------------------------------------------
# ge        : x = X/Z, y = Y/Z, T = XY/Z
# ge_cached : Yp = Y+X, Ym = Y-X, Z, T2 = T*D2
# ge_precomp: same with Z = 1 (b_window / b_comb entries)

def ge_cache(P):
    X, Y, Z, T = P
    return ((Y + X) % p, (Y - X) % p, Z, T * D2 % p)


def ge_add(P, Q):                         # Q is a ge_cached
    X, Y, Z, T = P
    Yp, Ym, Zq, T2 = Q
    a = (Y + X) * Yp % p
    b = (Y - X) * Ym % p
    sY = (a + b) % p
    sX = (a - b) % p
    sZ = 2 * Z * Zq % p
    sT = T * T2 % p
    a = (sZ + sT) % p
    b = (sZ - sT) % p
    return (sX * b % p, sY * a % p, a * b % p, sX * sY % p)


def ge_madd(P, Q):                        # Q is a ge_precomp (Z = 1)
    X, Y, Z, T = P
    Yp, Ym, T2 = Q
    a = (Y + X) * Yp % p
    b = (Y - X) * Ym % p
    sY = (a + b) % p
    sX = (a - b) % p
    sZ = 2 * Z % p
    sT = T * T2 % p
    a = (sZ + sT) % p
    b = (sZ - sT) % p
    return (sX * b % p, sY * a % p, a * b % p, sX * sY % p)


def ge_double(P):
    X, Y, Z, T = P
    qX = X * X % p
    qY = Y * Y % p
    qZ = 2 * Z * Z % p
    qT = (X + Y) % p
    sT = qT * qT % p
    qT = (qY + qX) % p
    qY = (qY - qX) % p
    qX = (sT - qT) % p
    qZ = (qZ - qY) % p
    return (qX * qZ % p, qT * qY % p, qY * qZ % p, qX * qT % p)


def to_proj(P, scale=None):
    """Affine -> extended coordinates, on a random projective
    representative (any Z != 0), so Z = 1 is not silently assumed."""
    x, y = P
    Z = scale if scale is not None else random.randrange(1, p)
    return (x * Z % p, y * Z % p, Z, x * y * Z % p)


def to_aff(P):
    X, Y, Z, T = P
    assert Z % p != 0
    inv = pow(Z, -1, p)
    return (X * inv % p, Y * inv % p)


def check_op(name, R, expected, Pa, Qa, z_formula):
    X, Y, Z, T = R
    assert Z % p != 0, f"{name}: Z == 0 for {Pa} + {Qa}"
    assert to_aff(R) == expected, f"{name}: wrong result"
    assert X * Y % p == T * Z % p, f"{name}: T != XY/Z"
    assert on_curve(to_aff(R)), f"{name}: off curve"
    assert Z % p == z_formula % p, f"{name}: Z3 factorisation"


def test_pair(Pa, Qa):
    """Check ge_add, ge_madd and (if P == Q) ge_double on affine P, Q."""
    x1, y1 = Pa
    x2, y2 = Qa
    k = d * x1 * x2 * y1 * y2 % p
    # BL 2007 Thm 3.3, the fact completeness rests on:
    assert k not in (1, p - 1), "d x1 x2 y1 y2 == +-1 ?!"
    expected = aff_add(Pa, Qa)

    P = to_proj(Pa)
    Q = to_proj(Qa)
    # ge_add: Z3 = (2 Z1 Z2 + 2d T1 T2)(2 Z1 Z2 - 2d T1 T2)
    #            = 4 Z1^2 Z2^2 (1 + k)(1 - k)
    z3 = 4 * P[2] ** 2 * Q[2] ** 2 * (1 + k) * (1 - k)
    check_op("ge_add", ge_add(P, ge_cache(Q)), expected, Pa, Qa, z3)
    # ge_madd: same with Z2 = 1
    Q1 = to_proj(Qa, scale=1)
    z3 = 4 * P[2] ** 2 * (1 + k) * (1 - k)
    Yp, Ym, _, T2 = ge_cache(Q1)
    check_op("ge_madd", ge_madd(P, (Yp, Ym, T2)), expected, Pa, Qa, z3)
    if Pa == Qa:
        # ge_double: Z3 = (Y^2 - X^2)(2 Z^2 - Y^2 + X^2)
        #               = Z^4 (1 + d x^2 y^2)(1 - d x^2 y^2)
        z3 = P[2] ** 4 * (1 + k) * (1 - k)
        check_op("ge_double", ge_double(P), expected, Pa, Qa, z3)


# Every ordered pair of small-order points: 64 cases, including P + P,
# P + (-P), order-2 and order-4 points.  These are exactly the inputs on
# which incomplete formulas (e.g. Weierstrass, or Edwards with square d)
# blow up, so they are the ones worth testing explicitly.
for Pa in TORSION:
    for Qa in TORSION:
        test_pair(Pa, Qa)
# Random points, with and without a torsion component, against
# themselves, their negation, their torsion translates, and each other.
for _ in range(50):
    Pa = aff_add(aff_mul(random.randrange(L), B), random.choice(TORSION))
    Qa = aff_add(aff_mul(random.randrange(L), B), random.choice(TORSION))
    test_pair(Pa, Pa)
    test_pair(Pa, aff_neg(Pa))
    test_pair(Pa, Qa)
    for T in TORSION:
        test_pair(Pa, aff_add(Pa, T))
        test_pair(Pa, aff_add(aff_neg(Pa), T))
print("3. ge_add/ge_madd/ge_double match the affine law, keep T = XY/Z,"
      " and Z3 factors as\n   4 Z1^2 Z2^2 (1 +- d x1x2y1y2) resp."
      " Z^4 (1 +- d x^2y^2), with every factor nonzero,\n"
      "   on all 64 pairs of 8-torsion points, P+P, P-P, P+torsion,"
      " random pairs  OK")


# --------------------------------------------------------------------
# 4. old check == new check on the final point
# --------------------------------------------------------------------
def old_check(P):
    """ge_tobytes + crypto_verify32 against {1, 0, ..., 0}.
    fe_invert(0) == 0 in Monocypher, mirrored here."""
    X, Y, Z, T = P
    inv = pow(Z, p - 2, p)                   # == 0 when Z == 0
    x = X * inv % p
    y = Y * inv % p
    enc = (y | ((x & 1) << 255)).to_bytes(32, "little")
    return 0 if enc == bytes([1] + [0] * 31) else -1


def new_check(P):
    """fe_isequal(Y, Z) - 1: fe_tobytes reduces both to canonical form
    first, so this is equality mod p."""
    X, Y, Z, T = P
    return 0 if Y % p == Z % p else -1


for Pa in TORSION:
    for _ in range(20):
        P = to_proj(Pa)
        assert old_check(P) == new_check(P) == (0 if Pa == IDENTITY else -1)
for _ in range(200):
    Pa = aff_add(aff_mul(random.randrange(L), B), random.choice(TORSION))
    P = to_proj(Pa)
    assert old_check(P) == new_check(P) == (0 if Pa == IDENTITY else -1)
# The one representation where they would disagree, which claim 2 rules
# out: Z == 0.
assert old_check((0, 0, 0, 0)) == -1 and new_check((0, 0, 0, 0)) == 0
print("4. old_check == new_check on every small-order point and random"
      " points (random Z);\n   they differ only at Z == 0, which 3. rules"
      " out  OK")


# --------------------------------------------------------------------
# 5. Vectors for the differential C harness
# --------------------------------------------------------------------
def ref_check_equation(sig, pk, h):
    """Python version of crypto_eddsa_check_equation's verdict:
    0 = accept, -1 = reject.  Cofactored: [8]([s]B - [h]A - R) == 0."""
    R = mc_decode(sig[:32])
    A = mc_decode(pk)
    s = int.from_bytes(sig[32:], "little")
    if R is None or A is None or s >= L:
        return -1
    hh = int.from_bytes(h, "little")
    P = aff_add(aff_mul(s, B), aff_neg(aff_add(aff_mul(hh, A), R)))
    return 0 if aff_mul(8, P) == IDENTITY else -1


def encodings(P):
    """All byte strings Monocypher decodes to P: canonical, plus the
    non-canonical y + p when it fits in 255 bits (y < 19), each with
    both sign bits when x == 0."""
    x, y = P
    out = []
    ys = [y] + ([y + p] if y + p < 2**255 else [])
    for yy in ys:
        signs = [x & 1] if x else [0, 1]
        for sgn in signs:
            out.append((yy | (sgn << 255)).to_bytes(32, "little"))
    for e in out:
        assert mc_decode(e) == P
    return out


vectors = []   # (sig, pk, h, expected)


def add_vec(sig, pk, h, expected=None):
    v = ref_check_equation(sig, pk, h)
    if expected is not None:
        assert v == expected, (sig.hex(), pk.hex(), h.hex(), v, expected)
    vectors.append((sig, pk, h, v))


def le32(n):
    return (n % 2**256).to_bytes(32, "little")


# Cofactored accepts:  A = [k]B + TA,  R = [r]B + TR,  s = r + h k.
# Then [s]B - [h]A - R = -[h]TA - TR is small-order, so [8](..) = 0.
# These are the "bogus" signatures Zebra and Monocypher both accept
# (small-order keys, small-order R, non-canonical encodings), and the
# inputs where every intermediate point carries a torsion component.
for k in (0, 1, random.randrange(L), random.randrange(L)):
    kB = aff_mul(k, B)
    for r in (0, random.randrange(L)):
        rB = aff_mul(r, B)
        for h in (0, 1, L - 1, random.randrange(L)):
            s = (r + h * k) % L
            for TA in TORSION:
                A = aff_add(kB, TA)
                for TR in TORSION:
                    R = aff_add(rB, TR)
                    for Ae in encodings(A):
                        for Re in encodings(R):
                            add_vec(Re + le32(s), Ae, le32(h), 0)
                    # same with s off by one: must reject
                    add_vec(aff_encode(R) + le32((s + 1) % L),
                            aff_encode(A), le32(h), -1)
# s >= L: rejected before any point arithmetic
add_vec(aff_encode(IDENTITY) + le32(L), aff_encode(IDENTITY), le32(0), -1)
add_vec(aff_encode(IDENTITY) + le32(2**256 - 1), aff_encode(IDENTITY), le32(0), -1)
# off-curve encodings: rejected by ge_frombytes
for _ in range(50):
    pk = random.randbytes(32)
    sig = random.randbytes(32) + le32(random.randrange(L))
    add_vec(sig, pk, le32(random.randrange(L)))
# random on-curve A, R with random s, h: rejects
for _ in range(50):
    A = aff_add(aff_mul(random.randrange(L), B), random.choice(TORSION))
    R = aff_add(aff_mul(random.randrange(L), B), random.choice(TORSION))
    add_vec(aff_encode(R) + le32(random.randrange(L)), aff_encode(A),
            le32(random.randrange(L)), -1)

n_acc = sum(1 for v in vectors if v[3] == 0)
with open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "pr299_vectors.h"), "w") as f:
    f.write("// Generated by verify_pr299.py.  Verdicts computed with an\n"
            "// independent affine implementation, not with Monocypher.\n"
            "// sig[64] (R || s), pk[32] (A), h[32], expected (0 ok, -1 ko)\n"
            "typedef struct { unsigned char sig[64], pk[32], h[32]; int expected; }"
            " pr299_vec;\n"
            f"static const pr299_vec pr299_vectors[{len(vectors)}] = {{\n")
    for sig, pk, h, e in vectors:
        def cl(b):
            return "{" + ",".join(str(x) for x in b) + "}"
        f.write(f"{{{cl(sig)},{cl(pk)},{cl(h)},{e}}},\n")
    f.write("};\n")
print(f"5. wrote pr299_vectors.h: {len(vectors)} cases"
      f" ({n_acc} cofactored accepts incl. small-order and non-canonical"
      f" A/R, {len(vectors) - n_acc} rejects)")
print("all OK")
