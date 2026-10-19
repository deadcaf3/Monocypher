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

  1. checks the field facts the theorem needs: p and L prime, a = -1 a
     square, d a non-square (two independent ways), d != -1, no
     division by zero in decoding, the RFC 8032 base point,
  2. checks claim 1 algebraically, by sweeping x, and on every
     small-order point, including non-canonical encodings of y = 1,
  3. transcribes ge_add / ge_sub / ge_madd / ge_msub / ge_double from
     monocypher.c line by line and checks, against the affine
     reference, that they are the complete Hisil-Wong-Carter-Dawson
     formulas: correct result, Z != 0, T == XY/Z, and the Z3
     factorisation quoted in the PR comment, on every pair of 8-torsion
     and special-coordinate points with many projective representatives,
     on P +/- P, P + torsion, random pairs, and along full NAF scalar
     multiplication ladders through both the ge_cached and the
     ge_precomp (Z = 1) code paths, checking every intermediate point,
  4. checks old_check(P) == new_check(P) on random projective
     representatives of every small-order point, small multiples of B,
     and random points, and shows exactly when they would differ: Z == 0,
  5. writes pr299_vectors.h: cofactored ("Zebra-style") accept/reject
     vectors with verdicts computed here, with every combination of
     8-torsion components in A and R, non-canonical encodings, flipped
     sign bits, wrong h, s +- 1, s + L, s >= L, all-zero inputs, random
     off-curve and on-curve inputs; then runs a projective mirror of
     crypto_eddsa_check_equation over every vector and checks that the
     old and the new final test agree with the affine verdict.
"""
import functools
import os
import random
import sys
import time
import traceback

# --------------------------------------------------------------------
# Progress output: every step announces itself before it runs, so if
# the script looks stuck the last line says what it is doing.  On a
# terminal the running line is overwritten with the result; when piped
# each step prints a start line and a result line.  NO_COLOR is honoured.
# --------------------------------------------------------------------
_T0 = time.monotonic()
_TTY = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
_UTF = (sys.stdout.encoding or "").lower().replace("-", "") == "utf8"
OK, KO, RUN, BAR = ("\u2713", "\u2717", "\u2026", "\u2501") if _UTF \
                   else ("ok", "FAIL", "..", "=")
_CURRENT = "startup"


def _c(code, text):
    return f"\033[{code}m{text}\033[0m" if _TTY else text


def _fmt(dt):
    if dt < 1:
        return f"{dt * 1000:.0f} ms"
    if dt < 60:
        return f"{dt:.1f} s"
    return f"{int(dt // 60)} min {dt % 60:.0f} s"


def _out(text, end="\n"):
    sys.stdout.write(text + end)
    sys.stdout.flush()


def _clear():
    if _TTY:
        _out("\r\033[K", end="")


def section(title):
    head = f"{BAR * 2} {title} "
    _out("\n" + _c("1", head + BAR * max(0, 72 - len(head))))


class step:
    """with step("what"): ...   prints the step, then ok/FAIL and time."""
    def __init__(self, label):
        self.label = label

    def __enter__(self):
        global _CURRENT
        _CURRENT = self.label
        self.t = time.monotonic()
        _out(f"  {_c('2', RUN)} {self.label}", end="" if _TTY else "\n")
        return self

    def __exit__(self, et, ev, tb):
        dt = _fmt(time.monotonic() - self.t)
        _clear()
        mark = _c("32", OK) if et is None else _c("31", KO)
        _out(f"  {mark} {self.label}  {_c('2', dt)}")
        return False


class progress:
    """for x in progress("what", items): ...   or   pr = progress("what", n);
    pr.tick() per item; pr.done() at the end."""
    def __init__(self, label, items):
        global _CURRENT
        _CURRENT = label
        self.label = label
        self.items = range(items) if isinstance(items, int) else list(items)
        self.n = len(self.items)
        self.i = 0
        self.t = time.monotonic()
        self.last = 0.0
        self._show(force=True)

    def _show(self, force=False):
        now = time.monotonic()
        if _TTY:
            if not force and now - self.last < 0.1:
                return
            self.last = now
            w = 24
            f = w * self.i // self.n if self.n else w
            bar = "#" * f + "-" * (w - f)
            _out(f"\r\033[K  {_c('2', RUN)} {self.label}  [{bar}] "
                 f"{self.i}/{self.n}  {_c('2', _fmt(now - self.t))}", end="")
        elif force or self.i % max(1, self.n // 10) == 0:
            _out(f"  {RUN} {self.label}  {self.i}/{self.n}  {_fmt(now - self.t)}")

    def tick(self, k=1):
        self.i += k
        self._show()

    def done(self):
        _clear()
        _out(f"  {_c('32', OK)} {self.label}  {self.n}/{self.n}  "
             f"{_c('2', _fmt(time.monotonic() - self.t))}")

    def __iter__(self):
        for x in self.items:
            yield x
            self.tick()
        self.done()


def _excepthook(et, ev, tb):
    _clear()
    if et is KeyboardInterrupt:
        _out(f"\n{_c('31', 'interrupted')} during: {_CURRENT}")
        os._exit(130)
    if et is AssertionError:
        fr = traceback.extract_tb(tb)[-1]
        _out(f"\n{_c('1;31', 'FAILED')} during: {_CURRENT}\n"
             f"  line {fr.lineno}: {fr.line}\n"
             f"  {ev if str(ev) else '(no message)'}")
        os._exit(1)
    sys.__excepthook__(et, ev, tb)


sys.excepthook = _excepthook

section("Monocypher PR #299: independent verification")
_out(f"  python {sys.version.split()[0]}, seed 299, "
     f"{'terminal' if _TTY else 'piped'} output")

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


def is_probable_prime(n, rounds=64):
    """Miller-Rabin with random bases."""
    if n < 2:
        return False
    for q in (2, 3, 5, 7, 11, 13, 17, 19, 23):
        if n % q == 0:
            return n == q
    r, s = n - 1, 0
    while r % 2 == 0:
        r //= 2
        s += 1
    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, r, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


# --------------------------------------------------------------------
# 1. Field facts required by the completeness theorem
# --------------------------------------------------------------------
# Twisted Edwards  a x^2 + y^2 = 1 + d x^2 y^2  with a = -1.
# BBJLP 2008 Sec. 6: the formulas are complete if a is a square and d
# is not.  BL 2007 Thm 3.3 (the actual proof): d non-square implies
# d x1 x2 y1 y2 != +-1 for any two points on the curve.
section("1/5  Field facts needed by the completeness theorem")
with step("p = 2^255 - 19 is prime (Miller-Rabin, 64 random bases)"):
    assert is_probable_prime(p)
with step("L = 2^252 + 27742... is prime (Miller-Rabin, 64 random bases)"):
    assert is_probable_prime(L)
with step("p = 1 mod 4 (so -1 is a square) and p = 5 mod 8 (sqrt via (p+3)/8)"):
    assert p % 4 == 1 and p % 8 == 5
with step("a = -1 is a square: Euler criterion, and 2^((p-1)/4) is an explicit root"):
    assert legendre(p - 1) == 1
    assert sqrtm1 * sqrtm1 % p == p - 1
    assert sqrt_mod_p(p - 1) in (sqrtm1, p - sqrtm1)
with step("d = -121665/121666 as defined, and D2 == 2d as ge_cache uses it"):
    assert d * 121666 % p == (-121665) % p
    assert D2 == 2 * d % p
with step("d is not a square: Euler criterion says -1"):
    assert legendre(d) == p - 1
with step("d is not a square: sqrt_mod_p finds no root (independent check)"):
    assert sqrt_mod_p(d) is None
with step("1 + d != 0 and 1 - d != 0 (claim 1 needs d != -1; both are Z3 factors)"):
    assert (1 + d) % p != 0 and (1 - d) % p != 0
# Decoding never divides by zero: d y^2 + 1 == 0 would need y^2 = -1/d,
# and -1/d is a non-square (square / non-square).
with step("-1/d is a non-square: decoding never divides by zero"):
    assert legendre((-pow(d, -1, p)) % p) == p - 1
with step("d y^2 + 1 != 0 for y in 0..9999 and 100000 random y"):
    for y in list(range(10000)) + [random.randrange(p) for _ in range(100000)]:
        assert (d * y * y + 1) % p != 0


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
    # One inversion serves both denominators: 1/(1+k) = (1-k)/((1+k)(1-k)).
    # (1+k)(1-k) != 0 by completeness; pow() raises ValueError otherwise.
    inv = pow((1 + k) * (1 - k), -1, p)
    x3 = (x1 * y2 + y1 * x2) * (1 - k) * inv % p
    y3 = (y1 * y2 + x1 * x2) * (1 + k) * inv % p   # a = -1: y1y2 - a x1x2
    return (x3, y3)


def aff_neg(P):
    return ((-P[0]) % p, P[1])


def aff_mul_ladder(k, P):
    R = IDENTITY
    while k:
        if k & 1:
            R = aff_add(R, P)
        P = aff_add(P, P)
        k >>= 1
    return R


B_WINDOWS = []   # B_WINDOWS[i][j] = [j * 16^i]B, filled in once B is known


@functools.lru_cache(maxsize=None)
def aff_mul(k, P):
    """[k]P.  Fixed-base 4-bit windows for B (64 adds instead of ~380),
    double-and-add otherwise.  Memoised: section 5 reuses the same [s]B
    and [h]A across thousands of vectors."""
    if B_WINDOWS and P == B_WINDOWS[0][1]:
        R = IDENTITY
        for i, row in enumerate(B_WINDOWS):
            R = aff_add(R, row[(k >> (4 * i)) & 15])
        return R
    return aff_mul_ladder(k, P)


def aff_encode(P):
    """RFC 8032 encoding: y, with sign(x) in the top bit."""
    x, y = P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


@functools.lru_cache(maxsize=None)
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


def points_with_x(x):
    """All curve points with this x: y^2 = (1 + x^2) / (1 - d x^2)."""
    den = (1 - d * x * x) % p
    if den == 0:
        return []
    y = sqrt_mod_p((1 + x * x) * pow(den, -1, p))
    return [] if y is None else sorted({(x % p, y), (x % p, (-y) % p)})


def points_with_y(y):
    """All curve points with this y: x^2 = (y^2 - 1) / (d y^2 + 1)."""
    x = sqrt_mod_p((y * y - 1) * pow(d * y * y + 1, -1, p))
    return [] if x is None else sorted({(x, y % p), ((-x) % p, y % p)})


def random_point():
    """Random curve point with a random torsion component."""
    return aff_add(aff_mul(random.randrange(L), B), random.choice(TORSION))


section("Affine reference implementation: setup")
# Base point B: y = 4/5, x even.
By = 4 * pow(5, -1, p) % p
Bx = sqrt_mod_p((By * By - 1) * pow(d * By * By + 1, -1, p))
if Bx & 1:
    Bx = p - Bx
B = (Bx, By)
with step("B = (x, 4/5) with x even matches the RFC 8032 constants"):
    assert Bx == 15112221349535400772501151409588531511454012693041857206046113283949847762202
    assert By == 46316835694926478169428394003475163141307993866256225615783033603165251855960
with step("B is on the curve, and the RFC 8032 encoding of B is 5866..6658"):
    assert on_curve(B)
    assert aff_encode(B) == bytes.fromhex(
        "5866666666666666666666666666666666666666666666666666666666666666")
with step("[L]B == identity, [L-1]B == -B (affine double-and-add ladder)"):
    assert aff_mul_ladder(L, B) == IDENTITY
    assert aff_mul_ladder(L - 1, B) == aff_neg(B)
with step("fixed-base table [j 16^i]B for 64 windows, checked against the ladder"):
    base = B
    for i in range(64):
        row = [IDENTITY]
        for j in range(1, 16):
            row.append(aff_add(row[-1], base))
        B_WINDOWS.append(row)
        for _ in range(4):
            base = aff_add(base, base)
    assert aff_mul(L, B) == IDENTITY
    for k in [0, 1, 2, 15, 16, 17, 255, 256, L - 1, 2**255, 2**256 - 1] \
             + [random.randrange(L) for _ in range(20)]:
        assert aff_mul(k, B) == aff_mul_ladder(k, B)

# The 8-torsion subgroup E[8].  A random point times L has order
# dividing 8; pick one of order exactly 8 and take its multiples.
with step("find a point of order 8: random on-curve (x, y) times L"):
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
with step("E[8] = its 8 multiples: distinct, on the curve, orders 1,8,4,8,2,8,4,8"):
    TORSION = [aff_mul(i, T8) for i in range(8)]
    assert len(set(TORSION)) == 8
    assert all(on_curve(T) for T in TORSION)
    assert TORSION[0] == IDENTITY
    for i, T in enumerate(TORSION):
        order = 8 // (i & -i if i else 8)        # 8 / gcd(i, 8)
        assert aff_mul(order, T) == IDENTITY
        assert order == 1 or aff_mul(order // 2, T) != IDENTITY
    assert TORSION[4] == (0, p - 1)                 # the order-2 point
    assert sorted(T for T in TORSION if T[1] == 0) == [(sqrtm1, 0), (p - sqrtm1, 0)]
with step("E[8] is the full 8-torsion: every (0, +-1), (+-i, 0) is in it, and it is a group"):
    assert set(points_with_x(0)) | set(points_with_y(0)) <= set(TORSION)
    assert all(aff_add(S, T) in TORSION for S in TORSION for T in TORSION)
with step("64 random curve points: [L]P lands in E[8] (curve order is 8L)"):
    for _ in range(64):
        while True:
            y = random.randrange(p)
            x = sqrt_mod_p((y * y - 1) * pow(d * y * y + 1, -1, p))
            if x is not None:
                break
        assert aff_mul_ladder(L, (x, y)) in TORSION


# --------------------------------------------------------------------
# 2. Claim 1: y == 1 only at the identity
# --------------------------------------------------------------------
# Put y = 1 in -x^2 + y^2 = 1 + d x^2 y^2  ->  (1 + d) x^2 = 0  ->  x = 0.
# On any point with y == 1, x^2 = (y^2 - 1) / (d y^2 + 1) = 0 / (d+1) = 0.
section("2/5  Claim 1: y == 1 only at the identity")
with step("y = 1 gives x^2 = 0 / (d + 1) = 0, so x = 0"):
    assert sqrt_mod_p(0) == 0
    assert (0 * pow(d + 1, -1, p)) % p == 0
    assert points_with_y(1) == [IDENTITY]
with step("(x, 1) is off the curve for x in 1..9999 and 100000 random x != 0"):
    for x in list(range(1, 10000)) + [random.randrange(1, p) for _ in range(100000)]:
        assert not on_curve((x, 1))
with step("likewise y = -1: only (0, -1), the order-2 point"):
    assert points_with_y(p - 1) == [(0, p - 1)]
# and the only such point is the identity, which the old check compared
# against:  encode((0, 1)) == 01 00 00 ... 00
with step("identity encodes as 01 00..00, the old check's reference"):
    assert aff_encode(IDENTITY) == bytes([1] + [0] * 31)
# Sanity on the small-order points: exactly one has y == 1.
with step("exactly one 8-torsion point has y == 1: the identity"):
    assert [T for T in TORSION if T[1] == 1] == [IDENTITY]
with step("no [k]B + T for k in 0..999 and all T has y == 1 except the identity"):
    for k in range(1000):
        kB = aff_mul(k, B)
        for T in TORSION:
            P = aff_add(kB, T)
            assert (P[1] == 1) == (P == IDENTITY)
with step("non-canonical encodings of y = 1 (1 + p fits 255 bits, either sign bit) decode to the identity"):
    encs = {bytes([1] + [0] * 31), bytes([1] + [0] * 30 + [0x80]),
            (1 + p).to_bytes(32, "little"), (1 + p + 2**255).to_bytes(32, "little")}
    assert all(mc_decode(e) == IDENTITY for e in encs)


# --------------------------------------------------------------------
# 3. Monocypher's projective formulas, transcribed line by line
# --------------------------------------------------------------------
# ge        : x = X/Z, y = Y/Z, T = XY/Z
# ge_cached : Yp = Y+X, Ym = Y-X, Z, T2 = T*D2
# ge_precomp: same with Z = 1 (b_window / b_comb entries)

def ge_zero():
    return (0, 1, 1, 0)


def ge_neg(P):
    X, Y, Z, T = P
    return ((-X) % p, Y, Z, (-T) % p)


def ge_cache(P):
    X, Y, Z, T = P
    return ((Y + X) % p, (Y - X) % p, Z, T * D2 % p)


def ge_precomp(Pa):
    """A b_window / b_comb entry: ge_cached with Z = 1 (dropped)."""
    Yp, Ym, _, T2 = ge_cache(to_proj(Pa, scale=1))
    return (Yp, Ym, T2)


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


def ge_sub(P, Q):                         # swap Yp/Ym, negate T2
    Yp, Ym, Zq, T2 = Q
    return ge_add(P, (Ym, Yp, Zq, (-T2) % p))


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


def ge_msub(P, Q):
    Yp, Ym, T2 = Q
    return ge_madd(P, (Ym, Yp, (-T2) % p))


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


def rescale(P):
    """Another representative of the same point."""
    lam = random.randrange(1, p)
    return tuple(c * lam % p for c in P)


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


def test_pair(Pa, Qa, zp=None, zq=None):
    """Check ge_add, ge_sub, ge_madd, ge_msub and (if P == Q) ge_double
    on affine P, Q, with the given or random projective scales."""
    x1, y1 = Pa
    x2, y2 = Qa
    k = d * x1 * x2 * y1 * y2 % p
    # BL 2007 Thm 3.3, the fact completeness rests on:
    assert k not in (1, p - 1), "d x1 x2 y1 y2 == +-1 ?!"
    expected = aff_add(Pa, Qa)
    expected_sub = aff_add(Pa, aff_neg(Qa))

    P = to_proj(Pa, zp)
    Q = to_proj(Qa, zq)
    # ge_add: Z3 = (2 Z1 Z2 + 2d T1 T2)(2 Z1 Z2 - 2d T1 T2)
    #            = 4 Z1^2 Z2^2 (1 + k)(1 - k)
    z3 = 4 * P[2] ** 2 * Q[2] ** 2 * (1 + k) * (1 - k)
    check_op("ge_add", ge_add(P, ge_cache(Q)), expected, Pa, Qa, z3)
    # ge_sub: same with -Q, i.e. k -> -k, same Z3
    check_op("ge_sub", ge_sub(P, ge_cache(Q)), expected_sub, Pa, Qa, z3)
    # ge_madd / ge_msub: same with Z2 = 1
    z3 = 4 * P[2] ** 2 * (1 + k) * (1 - k)
    pre = ge_precomp(Qa)
    check_op("ge_madd", ge_madd(P, pre), expected, Pa, Qa, z3)
    check_op("ge_msub", ge_msub(P, pre), expected_sub, Pa, Qa, z3)
    if Pa == Qa:
        # ge_double: Z3 = (Y^2 - X^2)(2 Z^2 - Y^2 + X^2)
        #               = Z^4 (1 + d x^2 y^2)(1 - d x^2 y^2)
        z3 = P[2] ** 4 * (1 + k) * (1 - k)
        check_op("ge_double", ge_double(P), expected, Pa, Qa, z3)


def naf(k):
    """Non-adjacent form, least significant digit first, digits in -1..1."""
    out = []
    while k:
        if k & 1:
            z = 2 - (k % 4)
            k -= z
        else:
            z = 0
        out.append(z)
        k >>= 1
    return out


def ge_mul(k, P, mixed=False, trace=False):
    """[k]P by a NAF double-and-add/sub ladder on the transcribed
    formulas, starting from ge_zero() like the C ladder.  mixed=False
    uses ge_add/ge_sub with a ge_cached (the lutA path), mixed=True uses
    ge_madd/ge_msub with a Z = 1 precomp (the b_window path).  Z != 0
    and T == XY/Z are asserted after every operation; with trace, every
    intermediate point is also compared to the affine reference."""
    Pa = to_aff(P)
    cached = ge_cache(P)
    pre = ge_precomp(Pa)
    R = ge_zero()
    Ra = IDENTITY

    def check(R, Ra):
        assert R[2] % p != 0, "Z == 0 inside the ladder"
        assert R[0] * R[1] % p == R[3] * R[2] % p, "T != XY/Z inside the ladder"
        if trace:
            assert to_aff(R) == Ra, "ladder intermediate differs from affine"

    for z in reversed(naf(k)):
        R = ge_double(R)
        if trace:
            Ra = aff_add(Ra, Ra)
        check(R, Ra)
        if z == 1:
            R = ge_madd(R, pre) if mixed else ge_add(R, cached)
            if trace:
                Ra = aff_add(Ra, Pa)
            check(R, Ra)
        elif z == -1:
            R = ge_msub(R, pre) if mixed else ge_sub(R, cached)
            if trace:
                Ra = aff_add(Ra, aff_neg(Pa))
            check(R, Ra)
    return R


section("3/5  ge_add / ge_sub / ge_madd / ge_msub / ge_double are the complete HWCD formulas")
_out("  each pair: result == affine law, Z3 != 0, T == XY/Z, on curve, and\n"
     "  Z3 == 4 Z1^2 Z2^2 (1 +- d x1x2y1y2)  resp.  Z^4 (1 +- d x^2y^2)")
# Every ordered pair of small-order points: 64 cases, including P + P,
# P + (-P), order-2 and order-4 points.  These are exactly the inputs on
# which incomplete formulas (e.g. Weierstrass, or Edwards with square d)
# blow up, so they are the ones worth testing explicitly.
PAIRS = [(P, Q) for P in TORSION for Q in TORSION]
for Pa, Qa in progress("all 64 ordered pairs of 8-torsion points, 32 random representatives each",
                       PAIRS * 32):
    test_pair(Pa, Qa)
Z_EDGE = [1, 2, p - 1, p - 2, (p + 1) // 2, 2**255 - 20, 19, 2**254]
for Pa, Qa in progress("the 64 torsion pairs with every pair of edge Z values (1, 2, p-1, p-2, 1/2, ...)",
                       PAIRS):
    for zp in Z_EDGE:
        for zq in Z_EDGE:
            test_pair(Pa, Qa, zp, zq)
# Points with special coordinates: x or y in {0, +-1, +-2, +-i, 1/2, ...}.
SPECIAL = set(TORSION)
for c in (0, 1, p - 1, 2, p - 2, sqrtm1, p - sqrtm1, (p + 1) // 2, (p - 1) // 2,
          3, p - 3, 4, p - 4, 8, p - 8, 19, p - 19):
    SPECIAL.update(points_with_x(c))
    SPECIAL.update(points_with_y(c))
SPECIAL = sorted(SPECIAL)
with step(f"{len(SPECIAL)} points with x or y in {{0, +-1, +-2, +-3, +-4, +-8, +-19, +-i, +-1/2}} or in E[8] are on the curve"):
    assert all(on_curve(P) for P in SPECIAL)
for Pa, Qa in progress(f"all {len(SPECIAL) ** 2} ordered pairs of those special points, 4 representatives each",
                       [(P, Q) for P in SPECIAL for Q in SPECIAL] * 4):
    test_pair(Pa, Qa)
for Pa in progress("special points plus a random point, and plus all its torsion translates", SPECIAL):
    Qa = random_point()
    for T in TORSION:
        test_pair(Pa, aff_add(Qa, T))
        test_pair(aff_add(Qa, T), Pa)
# Random points, with and without a torsion component, against
# themselves, their negation, their torsion translates, and each other.
for _ in progress("random P, Q: P+P, P-P, P+Q, Q+P, P+-P+torsion (400 rounds x 20)", 400):
    Pa = random_point()
    Qa = random_point()
    test_pair(Pa, Pa)
    test_pair(Pa, aff_neg(Pa))
    test_pair(Pa, Qa)
    test_pair(Qa, Pa)
    for T in TORSION:
        test_pair(Pa, aff_add(Pa, T))
        test_pair(Pa, aff_add(aff_neg(Pa), T))
for _ in progress("doubling chains: 256 doublings of a random point, Z != 0, == affine each time", 16):
    Pa = random_point()
    P = to_proj(Pa)
    for _ in range(256):
        Pa = aff_add(Pa, Pa)
        P = ge_double(P)
        assert P[2] % p != 0 and to_aff(P) == Pa
with step("edge scalars 0, 1, 2, 3, 7, 8, L-1, L, L+1, 8L, 2^256-1 on E[8] and 4 random points, both ladders"):
    for Pa in TORSION + [random_point() for _ in range(4)]:
        for k in (0, 1, 2, 3, 7, 8, L - 1, L, L + 1, 8 * L, 2**256 - 1):
            expected = aff_mul_ladder(k, Pa)
            assert to_aff(ge_mul(k, to_proj(Pa), mixed=False, trace=True)) == expected
            assert to_aff(ge_mul(k, to_proj(Pa), mixed=True, trace=True)) == expected
for _ in progress("NAF ladders [k]P, ge_cached and Z = 1 paths: every intermediate == affine, Z != 0", 48):
    k = random.randrange(L)
    Pa = random_point()
    expected = aff_mul_ladder(k, Pa)
    assert to_aff(ge_mul(k, to_proj(Pa), mixed=False, trace=True)) == expected
    assert to_aff(ge_mul(k, to_proj(Pa), mixed=True, trace=True)) == expected
for _ in progress("NAF ladders [k]B via the fixed-base table: result == affine, Z != 0 at every step", 400):
    k = random.randrange(L)
    expected = aff_mul(k, B)
    assert to_aff(ge_mul(k, to_proj(B), mixed=False)) == expected
    assert to_aff(ge_mul(k, to_proj(B), mixed=True)) == expected


# --------------------------------------------------------------------
# 4. old check == new check on the final point
# --------------------------------------------------------------------
def old_check(P):
    """ge_tobytes + crypto_verify32 against {1, 0, ..., 0}.
    fe_invert(0) == 0 in Monocypher (it is x^(p-2)), mirrored here."""
    X, Y, Z, T = P
    inv = pow(Z, -1, p) if Z % p else 0
    x = X * inv % p
    y = Y * inv % p
    enc = (y | ((x & 1) << 255)).to_bytes(32, "little")
    return 0 if enc == bytes([1] + [0] * 31) else -1


def new_check(P):
    """fe_isequal(Y, Z) - 1: fe_tobytes reduces both to canonical form
    first, so this is equality mod p."""
    X, Y, Z, T = P
    return 0 if Y % p == Z % p else -1


def both_agree(Pa, zscale=None):
    P = to_proj(Pa, zscale)
    assert old_check(P) == new_check(P) == (0 if Pa == IDENTITY else -1), Pa


section("4/5  old check (encode + compare) == new check (Y == Z)")
with step("pow(Z, -1) with the Z == 0 special case equals Z^(p-2) (fe_invert) on 200 random Z and 0"):
    for Z in [0] + [random.randrange(p) for _ in range(200)]:
        assert (pow(Z, -1, p) if Z else 0) == pow(Z, p - 2, p)
for Pa in progress("every 8-torsion point, 500 random projective representatives each", TORSION * 500):
    both_agree(Pa)
for Pa in progress("every 8-torsion point with every edge Z value", TORSION):
    for z in Z_EDGE:
        both_agree(Pa, z)
for Pa in progress("every special-coordinate point, 50 representatives each", SPECIAL * 50):
    both_agree(Pa)
for k in progress("[k]B + T for k in 0..255 and all T, 4 representatives each", 256):
    for T in TORSION:
        for _ in range(4):
            both_agree(aff_add(aff_mul(k, B), T))
for _ in progress("random points with torsion component, random Z", 2000):
    both_agree(random_point())
# The one representation where they would disagree, which claim 2 rules
# out: Z == 0.
with step("Z == 0 (never produced): old always rejects, new accepts iff Y == 0; 2000 random X, Y, T"):
    assert old_check((0, 0, 0, 0)) == -1 and new_check((0, 0, 0, 0)) == 0
    for _ in range(2000):
        X, Y, T = (random.randrange(p) for _ in range(3))
        if random.random() < 0.5:
            Y = 0
        assert old_check((X, Y, 0, T)) == -1
        assert new_check((X, Y, 0, T)) == (0 if Y == 0 else -1)
with step("with Z != 0, Y == Z and Y == -Z are the identity resp. (0, -1): new accepts the first only"):
    for _ in range(1000):
        Z = random.randrange(1, p)
        assert new_check((0, Z, Z, 0)) == 0 == old_check((0, Z, Z, 0))
        assert new_check((0, (-Z) % p, Z, 0)) == -1 == old_check((0, (-Z) % p, Z, 0))


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


@functools.lru_cache(maxsize=None)
def proj_mul(k, Pa):
    """[k]P in projective coordinates through the transcribed ladder."""
    return ge_mul(k, to_proj(Pa, scale=1))


def mc_check_equation(sig, pk, h):
    """crypto_eddsa_check_equation on the transcribed formulas: decode A
    and R (negated, Z = 1), reject s >= L, sum = [s]B + [h](-A) by the
    ladder, add -R, double three times.  Returns (old verdict, new
    verdict) computed on the final projective point."""
    A = mc_decode(pk)
    R = mc_decode(sig[:32])
    s = int.from_bytes(sig[32:], "little")
    if A is None or R is None or s >= L:
        return (-1, -1)
    hh = int.from_bytes(h, "little")
    total = ge_add(rescale(proj_mul(s, B)), ge_cache(rescale(proj_mul(hh, aff_neg(A)))))
    total = ge_add(total, ge_cache(ge_neg(to_proj(R, scale=1))))
    for _ in range(3):
        total = ge_double(total)
    assert total[2] % p != 0
    return (old_check(total), new_check(total))


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


def flip_sign(enc):
    return enc[:31] + bytes([enc[31] ^ 0x80])


vectors = []   # (sig, pk, h, expected)


def add_vec(sig, pk, h, expected=None):
    v = ref_check_equation(sig, pk, h)
    if expected is not None:
        assert v == expected, (sig.hex(), pk.hex(), h.hex(), v, expected)
    vectors.append((sig, pk, h, v))


def le32(n):
    return (n % 2**256).to_bytes(32, "little")


section("5/5  Vectors for the differential C harness")
# Cofactored accepts:  A = [k]B + TA,  R = [r]B + TR,  s = r + h k.
# Then [s]B - [h]A - R = -[h]TA - TR is small-order, so [8](..) = 0.
# These are the "bogus" signatures Zebra and Monocypher both accept
# (small-order keys, small-order R, non-canonical encodings), and the
# inputs where every intermediate point carries a torsion component.
K_SET = (0, 1, L - 1, random.randrange(L))
R_SET = (0, 1, L - 1, random.randrange(L))
H_SET = (0, 1, L - 1, random.randrange(L), random.randrange(L))
COMBOS = [(k, r, h) for k in K_SET for r in R_SET for h in H_SET]
pr = progress("cofactored accepts and their s+1 rejects: (k, r, h) x TA x TR x encodings", len(COMBOS) * 8)
for k, r, h in COMBOS:
    kB = aff_mul(k, B)
    rB = aff_mul(r, B)
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
        pr.tick()
pr.done()
pr = progress("per (k, r, h, TA): s-1, s+L, wrong h, flipped sign bit of R and of A", len(COMBOS) * 8)
for k, r, h in COMBOS:
    kB = aff_mul(k, B)
    R = aff_mul(r, B)
    s = (r + h * k) % L
    for TA in TORSION:
        A = aff_add(kB, TA)
        sig = aff_encode(R) + le32(s)
        add_vec(aff_encode(R) + le32((s - 1) % L), aff_encode(A), le32(h), -1)
        add_vec(aff_encode(R) + le32(s + L), aff_encode(A), le32(h), -1)   # s >= L
        # wrong h: [s]B - [h+1]A - R = -A + small order: accepted iff A is small order
        add_vec(sig, aff_encode(A), le32((h + 1) % L), 0 if k == 0 else -1)
        # -R instead of R: [s]B - [h]A + R = 2R + small order: accepted iff R is small order
        add_vec(flip_sign(aff_encode(R)) + le32(s), aff_encode(A), le32(h), 0 if r == 0 else -1)
        # -A instead of A: 2[h]A + small order: accepted iff [h]A is small order
        add_vec(sig, flip_sign(aff_encode(A)), le32(h), 0 if k == 0 or h == 0 else -1)
        pr.tick()
pr.done()
for _ in progress("genuine equation solutions: random k, r, h, no torsion, plus their s+1 rejects", 100):
    k, r, h = (random.randrange(L) for _ in range(3))
    s = (r + h * k) % L
    sig = aff_encode(aff_mul(r, B)) + le32(s)
    add_vec(sig, aff_encode(aff_mul(k, B)), le32(h), 0)
    add_vec(sig[:32] + le32((s + 1) % L), aff_encode(aff_mul(k, B)), le32(h), -1)
with step("s >= L: L, L+1, 2L, 2^252, 2^253, 2^255, 2^256-1 rejected before any point arithmetic"):
    for s in (L, L + 1, 2 * L, 2**252, 2**253, 2**255, 2**256 - 1):
        add_vec(aff_encode(IDENTITY) + le32(s), aff_encode(IDENTITY), le32(0), -1)
        add_vec(aff_encode(B) + le32(s), aff_encode(B), le32(1), -1)
with step("all-zero signature and all-zero public key are accepted (y = 0 is the order-4 point)"):
    add_vec(bytes(64), bytes(32), bytes(32), 0)
    add_vec(bytes(64), bytes(32), le32(random.randrange(L)), 0)
    assert mc_decode(bytes(32)) in TORSION
# With s = h = 0 and R = identity the equation reads [8](-[0]A) == 0, so A
# only has to decode; with A = identity it reads [8](-R) == 0, so R has to
# decode to a small-order point.
with step("all 19 non-canonical y >= p, both sign bits, as A (accept iff decodable) and as R (iff small order)"):
    for y in range(p, 2**255):
        for sgn in (0, 1):
            e = (y | (sgn << 255)).to_bytes(32, "little")
            P = mc_decode(e)
            add_vec(aff_encode(IDENTITY) + le32(0), e, le32(0), 0 if P is not None else -1)
            add_vec(e + le32(0), aff_encode(IDENTITY), le32(0), 0 if P in TORSION else -1)
with step("0xff.. as A and as R (y = 2^255 - 1 reduces to 18, sign bit set) handled like any encoding"):
    e = bytes([0xff] * 32)
    P = mc_decode(e)
    add_vec(aff_encode(IDENTITY) + le32(0), e, le32(0), 0 if P is not None else -1)
    add_vec(e + le32(0), aff_encode(IDENTITY), le32(0), 0 if P in TORSION else -1)
# off-curve encodings: rejected by ge_frombytes
for _ in progress("random off-curve or on-curve random encodings as A and R, random s < L and h", 500):
    pk = random.randbytes(32)
    sig = random.randbytes(32) + le32(random.randrange(L))
    add_vec(sig, pk, le32(random.randrange(L)))
# random on-curve A, R with random s, h: rejects
for _ in progress("random on-curve A, R with random s, h: rejects", 200):
    A = random_point()
    R = random_point()
    add_vec(aff_encode(R) + le32(random.randrange(L)), aff_encode(A),
            le32(random.randrange(L)), -1)

n_acc = sum(1 for v in vectors if v[3] == 0)
_out(f"  {len(vectors)} vectors: {n_acc} accepts, {len(vectors) - n_acc} rejects")

# Finally the point of it all, in Python: run the projective mirror of
# crypto_eddsa_check_equation on every vector and check that the old
# test and the new test on the final point both equal the affine verdict.
for sig, pk, h, expected in progress("projective mirror of check_equation on every vector: old == new == affine verdict",
                                     vectors):
    assert mc_check_equation(sig, pk, h) == (expected, expected), (sig.hex(), pk.hex(), h.hex())

out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "pr299_vectors.h")
with step(f"write {os.path.relpath(out_path)}"), open(out_path, "w") as f:
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

_out(f"\n{_c('1;32', 'all OK')}  {_c('2', 'total ' + _fmt(time.monotonic() - _T0))}")
