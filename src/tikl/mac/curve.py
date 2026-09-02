# EC-SRP5 elliptic curve math for MikroTik authentication (RouterOS 6.43+).
# Adapted from MarginResearch/mikrotik_authentication (MIT license).
# Implements WCurve25519 in Weierstrass form used by the EC-SRP5 protocol.
#
# The math is kept faithful to upstream; only type annotations were added.
# Methods that return ecdsa point objects are annotated ``Any`` because the
# ecdsa dependency is untyped.
import hashlib
from typing import Any

import ecdsa


def _egcd(a: int, b: int) -> tuple[int, int, int]:
    if a == 0:
        return (b, 0, 1)
    g, y, x = _egcd(b % a, a)
    return (g, x - (b // a) * y, y)


def _modinv(a: int, p: int) -> int:
    if a < 0:
        a = a % p
    g, x, _ = _egcd(a, p)
    if g != 1:
        raise Exception("modular inverse does not exist")
    return x % p


def _legendre_symbol(a: int, p: int) -> int:
    l = pow(a, (p - 1) // 2, p)
    return -1 if l == p - 1 else l


def _prime_mod_sqrt(a: int, p: int) -> list[int]:
    a %= p
    if a == 0:
        return [0]
    if p == 2:
        return [a]
    if _legendre_symbol(a, p) != 1:
        return []
    if p % 4 == 3:
        x = pow(a, (p + 1) // 4, p)
        return [x, p - x]

    q, s = p - 1, 0
    while q % 2 == 0:
        s += 1
        q //= 2

    z = 1
    while _legendre_symbol(z, p) != -1:
        z += 1
    c = pow(z, q, p)
    x = pow(a, (q + 1) // 2, p)
    t = pow(a, q, p)
    m = s
    while t != 1:
        i, e = 0, 2
        for i in range(1, m):
            if pow(t, e, p) == 1:
                break
            e *= 2
        b = pow(c, 2 ** (m - i - 1), p)
        x = (x * b) % p
        t = (t * b * b) % p
        c = (b * b) % p
        m = i
    return [x, p - x]


class WCurve:
    """Curve25519 in Weierstrass form, used by MikroTik EC-SRP5."""

    def __init__(self) -> None:
        self.__p = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED
        self.__r = 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED
        ma = 486662
        self.__conversion_from_m = ma * _modinv(3, self.__p) % self.__p
        self.__conversion = (self.__p - ma * _modinv(3, self.__p)) % self.__p
        self.__a = 0x2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA984914A144
        self.__b = 0x7B425ED097B425ED097B425ED097B425ED097B425ED097B4260B5E9C7710C864
        self.__curve = ecdsa.ellipticcurve.CurveFp(self.__p, self.__a, self.__b, 8)
        self.__g = self.lift_x(9, 0)

    def gen_public_key(self, priv: bytes) -> tuple[bytes, int]:
        assert len(priv) == 32
        pt = int.from_bytes(priv, "big") * self.__g
        return self.to_montgomery(pt)

    def to_montgomery(self, pt: Any) -> tuple[bytes, int]:
        x = (pt.x() + self.__conversion) % self.__p
        return int(x).to_bytes(32, "big"), int(pt.y() & 1)

    def lift_x(self, x: int, parity: int) -> Any:
        x = x % self.__p
        y_sq = (x**3 + 486662 * x**2 + x) % self.__p
        x = (x + self.__conversion_from_m) % self.__p
        ys = _prime_mod_sqrt(y_sq, self.__p)
        if not ys:
            return -1
        pts = [ecdsa.ellipticcurve.PointJacobi(self.__curve, x, y, 1, self.__r) for y in ys]
        for pt in pts:
            if (pt.y() & 1) == int(parity):
                return pt
        return pts[0]

    def redp1(self, x: bytes, parity: int) -> Any:
        x = hashlib.sha256(x).digest()
        while True:
            x2 = hashlib.sha256(x).digest()
            pt = self.lift_x(int.from_bytes(x2, "big"), parity)
            if pt == -1:
                x = (int.from_bytes(x, "big") + 1).to_bytes(32, "big")
            else:
                return pt

    def gen_password_validator_priv(self, username: str, password: str, salt: bytes) -> bytes:
        assert len(salt) == 16
        return hashlib.sha256(
            salt + hashlib.sha256((username + ":" + password).encode()).digest()
        ).digest()

    def finite_field_value(self, a: int) -> int:
        return a % self.__r
