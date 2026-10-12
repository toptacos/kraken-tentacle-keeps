"""Self-contained AES-256-GCM. Used when the `cryptography` wheel is absent.

keeps must seal secrets on a vanilla Alpine image with no pip step, so the arm
ships its own AES-256-GCM rather than refusing to run. Both backends are
byte-compatible: the on-disk format never depends on which one produced it.

Verified against the FIPS-197 AES-256 block vector and the NIST
gcmEncryptExtIV256 GCM vectors in tests/test_keeps.py.
"""

from __future__ import annotations

BLOCK = 16
TAG = 16


def _tables() -> tuple[list[int], list[int]]:
    exp = [0] * 512
    log = [0] * 256
    x = 1
    for i in range(255):
        exp[i] = x
        log[x] = i
        x ^= ((x << 1) ^ (0x11B if x & 0x80 else 0)) & 0xFF
    for i in range(255, 512):
        exp[i] = exp[i - 255]
    sbox = [0] * 256
    for a in range(256):
        inv = 0 if a == 0 else exp[255 - log[a]]
        rot = inv
        for _ in range(4):
            rot = ((rot << 1) | (rot >> 7)) & 0xFF
            inv ^= rot
        sbox[a] = inv ^ 0x63
    return sbox, exp


SBOX, _EXP = _tables()
_R = 0xE1 << 120


def _xtime(a: int) -> int:
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1


def _mul(a: int, b: int) -> int:
    out = 0
    while b:
        if b & 1:
            out ^= a
        a = _xtime(a)
        b >>= 1
    return out


def _expand(key: bytes) -> tuple[list[list[int]], int]:
    nk = len(key) // 4
    nr = nk + 6
    w = [list(key[4 * i : 4 * i + 4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (nr + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = [SBOX[b] for b in t[1:] + t[:1]]
            t[0] ^= rcon
            rcon = _xtime(rcon)
        elif nk > 6 and i % nk == 4:
            t = [SBOX[b] for b in t]
        w.append([w[i - nk][j] ^ t[j] for j in range(4)])
    return w, nr


def _add_key(s: list[list[int]], w: list[list[int]], rnd: int) -> None:
    for c in range(4):
        for r in range(4):
            s[r][c] ^= w[rnd * 4 + c][r]


def _encrypt_block(block: bytes, w: list[list[int]], nr: int) -> bytes:
    s = [[block[r + 4 * c] for c in range(4)] for r in range(4)]
    _add_key(s, w, 0)
    for rnd in range(1, nr + 1):
        for r in range(4):
            for c in range(4):
                s[r][c] = SBOX[s[r][c]]
        for r in range(1, 4):
            s[r] = s[r][r:] + s[r][:r]
        if rnd != nr:
            for c in range(4):
                a = [s[r][c] for r in range(4)]
                s[0][c] = _mul(a[0], 2) ^ _mul(a[1], 3) ^ a[2] ^ a[3]
                s[1][c] = a[0] ^ _mul(a[1], 2) ^ _mul(a[2], 3) ^ a[3]
                s[2][c] = a[0] ^ a[1] ^ _mul(a[2], 2) ^ _mul(a[3], 3)
                s[3][c] = _mul(a[0], 3) ^ a[1] ^ a[2] ^ _mul(a[3], 2)
        _add_key(s, w, rnd)
    return bytes(s[r][c] for c in range(4) for r in range(4))


def _ghash(h: int, data: bytes) -> int:
    # Y_i = Y_{i-1} * H, i.e. the accumulator supplies the multiplier bits
    # (MSB first) while H is the value that gets shifted-and-reduced.
    y = 0
    for i in range(0, len(data), BLOCK):
        chunk = data[i : i + BLOCK].ljust(BLOCK, b"\x00")
        y ^= int.from_bytes(chunk, "big")
        z = 0
        v = h
        for j in range(128):
            if (y >> (127 - j)) & 1:
                z ^= v
            v = (v >> 1) ^ _R if v & 1 else v >> 1
        y = z
    return y


def _pad16(data: bytes) -> bytes:
    return data + b"\x00" * ((-len(data)) % BLOCK)


def _gctr(w: list[list[int]], nr: int, icb: bytes, data: bytes) -> bytes:
    out = bytearray()
    counter = int.from_bytes(icb, "big")
    for i in range(0, len(data), BLOCK):
        counter = (counter & ~0xFFFFFFFF) | ((counter + 1) & 0xFFFFFFFF)
        ks = _encrypt_block(counter.to_bytes(BLOCK, "big"), w, nr)
        out += bytes(a ^ b for a, b in zip(ks, data[i : i + BLOCK]))
    return bytes(out)


def _j0(w: list[list[int]], nr: int, h: int, iv: bytes) -> bytes:
    if len(iv) == 12:
        return iv + b"\x00\x00\x00\x01"
    blob = _pad16(iv) + b"\x00" * 8 + (len(iv) * 8).to_bytes(8, "big")
    return _ghash(h, blob).to_bytes(BLOCK, "big")


def _tag(
    w: list[list[int]], nr: int, h: int, j0: bytes, aad: bytes, ct: bytes
) -> bytes:
    blob = (
        _pad16(aad)
        + _pad16(ct)
        + (len(aad) * 8).to_bytes(8, "big")
        + (len(ct) * 8).to_bytes(8, "big")
    )
    # The tag block masks GHASH with CIPH_K(J0) itself, not with the first
    # GCTR counter block (J0+1) used for the ciphertext.
    s = _ghash(h, blob).to_bytes(BLOCK, "big")
    return bytes(a ^ b for a, b in zip(s, _encrypt_block(j0, w, nr)))


def encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """Return ciphertext || 16-byte tag."""
    if len(key) not in (16, 24, 32):
        raise ValueError("bad_key_length")
    if not nonce:
        raise ValueError("empty_nonce")
    w, nr = _expand(key)
    h = int.from_bytes(_encrypt_block(b"\x00" * BLOCK, w, nr), "big")
    j0 = _j0(w, nr, h, nonce)
    ct = _gctr(w, nr, j0, plaintext)
    return ct + _tag(w, nr, h, j0, aad, ct)


def decrypt(key: bytes, nonce: bytes, sealed: bytes, aad: bytes = b"") -> bytes:
    """Verify the tag in constant-ish time, then decrypt. Raises ValueError on tamper."""
    if len(sealed) < TAG:
        raise ValueError("ciphertext_too_short")
    ct, tag = sealed[:-TAG], sealed[-TAG:]
    w, nr = _expand(key)
    h = int.from_bytes(_encrypt_block(b"\x00" * BLOCK, w, nr), "big")
    j0 = _j0(w, nr, h, nonce)
    want = _tag(w, nr, h, j0, aad, ct)
    diff = 0
    for a, b in zip(want, tag):
        diff |= a ^ b
    if diff:
        raise ValueError("auth_tag_mismatch")
    return _gctr(w, nr, j0, ct)
