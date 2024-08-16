# Copyright (C) 2018 The python-bitcointx developers
#
# This file is part of python-bitcointx.
#
# It is subject to the license terms in the LICENSE-PYTHON-BITCOINTX file found in the top-level
# directory of this distribution.
#
# No part of python-bitcointx, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.
#
# This code is ported from C++ code from Bitcoin Core.
# Original C++ code was Copyright (c) 2014-2017 The Bitcoin Core developers
# Original C++ code was licensed under MIT software license.

"""
This is needed for midstate SHA256, that is not available
from hashlib.sha256. Runtime performance will be slow, but oftentimes this
is acceptable. IMPORTANT: code is not constant-time! This should NOT be used
for working with # secret data, such as, for example  building a MAC (message
authentication code), etc.
"""

# pylama:ignore=E501

import struct
from typing import Union, List, TypeVar

SHA256_MAX = 0x1FFFFFFFFFFFFFFF


def Ch(x: int, y: int, z: int) -> int:
    return z ^ (x & (y ^ z))


def Maj(x: int, y: int, z: int) -> int:
    return (x & y) | (z & (x | y))


def Sigma0(x: int) -> int:
    return (x >> 2 | x << 30) ^ (x >> 13 | x << 19) ^ (x >> 22 | x << 10)


def Sigma1(x: int) -> int:
    return (x >> 6 | x << 26) ^ (x >> 11 | x << 21) ^ (x >> 25 | x << 7)


def sigma0(x: int) -> int:
    return (x >> 7 | x << 25) ^ (x >> 18 | x << 14) ^ (x >> 3)


def sigma1(x: int) -> int:
    return (x >> 17 | x << 15) ^ (x >> 19 | x << 13) ^ (x >> 10)


def uint32(x: int) -> int:
    return x & 0xFFFFFFFF


# One round of SHA-256.
def Round(a: int, b: int, c: int, d: int, e: int, f: int, g: int, h: int,
          k: int, w: int, x: List[int]) -> None:
    t1 = uint32(x[h] + Sigma1(x[e]) + Ch(x[e], x[f], x[g]) + k + w)
    t2 = uint32(Sigma0(x[a]) + Maj(x[a], x[b], x[c]))
    x[d] = uint32(x[d] + t1)
    x[h] = uint32(t1 + t2)


def ReadBE32(buf: bytes) -> int:
    return int(struct.unpack(b">I", buf[:4])[0])


T_CSHA256 = TypeVar('T_CSHA256', bound='CSHA256')


class CSHA256():
    """
    This class provides access to SHA256 routines, with access to
    SHA256 midstate (which is not available from hashlib.sha256)

    The code is not constant-time! This should NOT be used for working with
    secret data, such as, for example  building a MAC (message authentication
    code), etc.
    """

    __slots__ = ['s', 'buf', 'bytes_count']

    buf: bytes
    bytes_count: int
    s: List[int]

    # Initialize SHA-256 state.
    def __init__(self) -> None:
        self.Reset()

    # Perform a number of SHA-256 transformations, processing 64-byte chunks.
    def Transform(self, chunk: Union[bytes, bytearray], blocks: int) -> None:
        if not isinstance(blocks, int):
            raise TypeError('blocks must be an instance of int')
        if not isinstance(chunk, (bytes, bytearray)):
            raise TypeError('chunk must be an instance of bytes or bytearray')
        s = self.s
        while blocks:
            blocks -= 1
            a, b, c, d, e, f, g, h = range(8)
            x = s.copy()

            w0 = ReadBE32(chunk[0:])
            Round(a, b, c, d, e, f, g, h, 0x428a2f98, w0, x)
            w1 = ReadBE32(chunk[4:])
            Round(h, a, b, c, d, e, f, g, 0x71374491, w1, x)
            w2 = ReadBE32(chunk[8:])
            Round(g, h, a, b, c, d, e, f, 0xb5c0fbcf, w2, x)
            w3 = ReadBE32(chunk[12:])
            Round(f, g, h, a, b, c, d, e, 0xe9b5dba5, w3, x)
            w4 = ReadBE32(chunk[16:])
            Round(e, f, g, h, a, b, c, d, 0x3956c25b, w4, x)
            w5 = ReadBE32(chunk[20:])
            Round(d, e, f, g, h, a, b, c, 0x59f111f1, w5, x)
            w6 = ReadBE32(chunk[24:])
            Round(c, d, e, f, g, h, a, b, 0x923f82a4, w6, x)
            w7 = ReadBE32(chunk[28:])
            Round(b, c, d, e, f, g, h, a, 0xab1c5ed5, w7, x)
            w8 = ReadBE32(chunk[32:])
            Round(a, b, c, d, e, f, g, h, 0xd807aa98, w8, x)
            w9 = ReadBE32(chunk[36:])
            Round(h, a, b, c, d, e, f, g, 0x12835b01, w9, x)
            w10 = ReadBE32(chunk[40:])
            Round(g, h, a, b, c, d, e, f, 0x243185be, w10, x)
            w11 = ReadBE32(chunk[44:])
            Round(f, g, h, a, b, c, d, e, 0x550c7dc3, w11, x)
            w12 = ReadBE32(chunk[48:])
            Round(e, f, g, h, a, b, c, d, 0x72be5d74, w12, x)
            w13 = ReadBE32(chunk[52:])
            Round(d, e, f, g, h, a, b, c, 0x80deb1fe, w13, x)
            w14 = ReadBE32(chunk[56:])
            Round(c, d, e, f, g, h, a, b, 0x9bdc06a7, w14, x)
            w15 = ReadBE32(chunk[60:])
            Round(b, c, d, e, f, g, h, a, 0xc19bf174, w15, x)

            w0 = uint32(w0 + sigma1(w14) + w9 + sigma0(w1))
            Round(a, b, c, d, e, f, g, h, 0xe49b69c1, w0, x)
            w1 = uint32(w1 + sigma1(w15) + w10 + sigma0(w2))
            Round(h, a, b, c, d, e, f, g, 0xefbe4786, w1, x)
            w2 = uint32(w2 + sigma1(w0) + w11 + sigma0(w3))
            Round(g, h, a, b, c, d, e, f, 0x0fc19dc6, w2, x)
            w3 = uint32(w3 + sigma1(w1) + w12 + sigma0(w4))
            Round(f, g, h, a, b, c, d, e, 0x240ca1cc, w3, x)
            w4 = uint32(w4 + sigma1(w2) + w13 + sigma0(w5))
            Round(e, f, g, h, a, b, c, d, 0x2de92c6f, w4, x)
            w5 = uint32(w5 + sigma1(w3) + w14 + sigma0(w6))
            Round(d, e, f, g, h, a, b, c, 0x4a7484aa, w5, x)
            w6 = uint32(w6 + sigma1(w4) + w15 + sigma0(w7))
            Round(c, d, e, f, g, h, a, b, 0x5cb0a9dc, w6, x)
            w7 = uint32(w7 + sigma1(w5) + w0 + sigma0(w8))
            Round(b, c, d, e, f, g, h, a, 0x76f988da, w7, x)
            w8 = uint32(w8 + sigma1(w6) + w1 + sigma0(w9))
            Round(a, b, c, d, e, f, g, h, 0x983e5152, w8, x)
            w9 = uint32(w9 + sigma1(w7) + w2 + sigma0(w10))
            Round(h, a, b, c, d, e, f, g, 0xa831c66d, w9, x)
            w10 = uint32(w10 + sigma1(w8) + w3 + sigma0(w11))
            Round(g, h, a, b, c, d, e, f, 0xb00327c8, w10, x)
            w11 = uint32(w11 + sigma1(w9) + w4 + sigma0(w12))
            Round(f, g, h, a, b, c, d, e, 0xbf597fc7, w11, x)
            w12 = uint32(w12 + sigma1(w10) + w5 + sigma0(w13))
            Round(e, f, g, h, a, b, c, d, 0xc6e00bf3, w12, x)
            w13 = uint32(w13 + sigma1(w11) + w6 + sigma0(w14))
            Round(d, e, f, g, h, a, b, c, 0xd5a79147, w13, x)
            w14 = uint32(w14 + sigma1(w12) + w7 + sigma0(w15))
            Round(c, d, e, f, g, h, a, b, 0x06ca6351, w14, x)
            w15 = uint32(w15 + sigma1(w13) + w8 + sigma0(w0))
            Round(b, c, d, e, f, g, h, a, 0x14292967, w15, x)

            w0 = uint32(w0 + sigma1(w14) + w9 + sigma0(w1))
            Round(a, b, c, d, e, f, g, h, 0x27b70a85, w0, x)
            w1 = uint32(w1 + sigma1(w15) + w10 + sigma0(w2))
            Round(h, a, b, c, d, e, f, g, 0x2e1b2138, w1, x)
            w2 = uint32(w2 + sigma1(w0) + w11 + sigma0(w3))
            Round(g, h, a, b, c, d, e, f, 0x4d2c6dfc, w2, x)
            w3 = uint32(w3 + sigma1(w1) + w12 + sigma0(w4))
            Round(f, g, h, a, b, c, d, e, 0x53380d13, w3, x)
            w4 = uint32(w4 + sigma1(w2) + w13 + sigma0(w5))
            Round(e, f, g, h, a, b, c, d, 0x650a7354, w4, x)
            w5 = uint32(w5 + sigma1(w3) + w14 + sigma0(w6))
            Round(d, e, f, g, h, a, b, c, 0x766a0abb, w5, x)
            w6 = uint32(w6 + sigma1(w4) + w15 + sigma0(w7))
            Round(c, d, e, f, g, h, a, b, 0x81c2c92e, w6, x)
            w7 = uint32(w7 + sigma1(w5) + w0 + sigma0(w8))
            Round(b, c, d, e, f, g, h, a, 0x92722c85, w7, x)
            w8 = uint32(w8 + sigma1(w6) + w1 + sigma0(w9))
            Round(a, b, c, d, e, f, g, h, 0xa2bfe8a1, w8, x)
            w9 = uint32(w9 + sigma1(w7) + w2 + sigma0(w10))
            Round(h, a, b, c, d, e, f, g, 0xa81a664b, w9, x)
            w10 = uint32(w10 + sigma1(w8) + w3 + sigma0(w11))
            Round(g, h, a, b, c, d, e, f, 0xc24b8b70, w10, x)
            w11 = uint32(w11 + sigma1(w9) + w4 + sigma0(w12))
            Round(f, g, h, a, b, c, d, e, 0xc76c51a3, w11, x)
            w12 = uint32(w12 + sigma1(w10) + w5 + sigma0(w13))
            Round(e, f, g, h, a, b, c, d, 0xd192e819, w12, x)
            w13 = uint32(w13 + sigma1(w11) + w6 + sigma0(w14))
            Round(d, e, f, g, h, a, b, c, 0xd6990624, w13, x)
            w14 = uint32(w14 + sigma1(w12) + w7 + sigma0(w15))
            Round(c, d, e, f, g, h, a, b, 0xf40e3585, w14, x)
            w15 = uint32(w15 + sigma1(w13) + w8 + sigma0(w0))
            Round(b, c, d, e, f, g, h, a, 0x106aa070, w15, x)

            w0 = uint32(w0 + sigma1(w14) + w9 + sigma0(w1))
            Round(a, b, c, d, e, f, g, h, 0x19a4c116, w0, x)
            w1 = uint32(w1 + sigma1(w15) + w10 + sigma0(w2))
            Round(h, a, b, c, d, e, f, g, 0x1e376c08, w1, x)
            w2 = uint32(w2 + sigma1(w0) + w11 + sigma0(w3))
            Round(g, h, a, b, c, d, e, f, 0x2748774c, w2, x)
            w3 = uint32(w3 + sigma1(w1) + w12 + sigma0(w4))
            Round(f, g, h, a, b, c, d, e, 0x34b0bcb5, w3, x)
            w4 = uint32(w4 + sigma1(w2) + w13 + sigma0(w5))
            Round(e, f, g, h, a, b, c, d, 0x391c0cb3, w4, x)
            w5 = uint32(w5 + sigma1(w3) + w14 + sigma0(w6))
            Round(d, e, f, g, h, a, b, c, 0x4ed8aa4a, w5, x)
            w6 = uint32(w6 + sigma1(w4) + w15 + sigma0(w7))
            Round(c, d, e, f, g, h, a, b, 0x5b9cca4f, w6, x)
            w7 = uint32(w7 + sigma1(w5) + w0 + sigma0(w8))
            Round(b, c, d, e, f, g, h, a, 0x682e6ff3, w7, x)
            w8 = uint32(w8 + sigma1(w6) + w1 + sigma0(w9))
            Round(a, b, c, d, e, f, g, h, 0x748f82ee, w8, x)
            w9 = uint32(w9 + sigma1(w7) + w2 + sigma0(w10))
            Round(h, a, b, c, d, e, f, g, 0x78a5636f, w9, x)
            w10 = uint32(w10 + sigma1(w8) + w3 + sigma0(w11))
            Round(g, h, a, b, c, d, e, f, 0x84c87814, w10, x)
            w11 = uint32(w11 + sigma1(w9) + w4 + sigma0(w12))
            Round(f, g, h, a, b, c, d, e, 0x8cc70208, w11, x)
            w12 = uint32(w12 + sigma1(w10) + w5 + sigma0(w13))
            Round(e, f, g, h, a, b, c, d, 0x90befffa, w12, x)
            w13 = uint32(w13 + sigma1(w11) + w6 + sigma0(w14))
            Round(d, e, f, g, h, a, b, c, 0xa4506ceb, w13, x)
            Round(c, d, e, f, g, h, a, b, 0xbef9a3f7, w14 + sigma1(w12) + w7 + sigma0(w15), x)
            Round(b, c, d, e, f, g, h, a, 0xc67178f2, w15 + sigma1(w13) + w8 + sigma0(w0), x)

            s[0] = uint32(s[0] + x[a])
            s[1] = uint32(s[1] + x[b])
            s[2] = uint32(s[2] + x[c])
            s[3] = uint32(s[3] + x[d])
            s[4] = uint32(s[4] + x[e])
            s[5] = uint32(s[5] + x[f])
            s[6] = uint32(s[6] + x[g])
            s[7] = uint32(s[7] + x[h])

            chunk = chunk[64:]

    def Write(self: T_CSHA256, data: Union[bytes, bytearray]) -> T_CSHA256:
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError('data must be instance of bytes or bytearray')

        if self.bytes_count + len(data) > SHA256_MAX:
            raise ValueError('total bytes count beyond max allowed value')

        bufsize = self.bytes_count % 64
        assert len(self.buf) == bufsize
        if bufsize and bufsize + len(data) >= 64:
            # Fill the buffer, and process it.
            remainder_len = 64 - bufsize
            buf = self.buf + data[:remainder_len]
            data = data[remainder_len:]
            self.bytes_count += remainder_len
            self.Transform(buf, 1)
            self.buf = b''
            bufsize = 0

        if len(data) >= 64:
            blocks = len(data) // 64
            self.Transform(data, blocks)
            data = data[64 * blocks:]
            self.bytes_count += 64 * blocks

        if len(data) > 0:
            assert len(data) < 64
            # Fill the buffer with what remains.
            self.buf = self.buf + data
            self.bytes_count += len(data)

        return self

    def Finalize(self) -> bytes:
        pad = b'\x80'+b'\x00'*63
        sizedesc = struct.pack(b">q", self.bytes_count << 3)
        self.Write(pad[:1 + ((119 - (self.bytes_count % 64)) % 64)])
        self.Write(sizedesc)
        return self.Midstate()

    def Midstate(self) -> bytes:
        s = self.s

        def ToBE32(x: int) -> bytes:
            return struct.pack(b">I", x)

        hash_chunks = []
        hash_chunks.append(ToBE32(s[0]))
        hash_chunks.append(ToBE32(s[1]))
        hash_chunks.append(ToBE32(s[2]))
        hash_chunks.append(ToBE32(s[3]))
        hash_chunks.append(ToBE32(s[4]))
        hash_chunks.append(ToBE32(s[5]))
        hash_chunks.append(ToBE32(s[6]))
        hash_chunks.append(ToBE32(s[7]))

        return b''.join(hash_chunks)

    def Reset(self) -> 'CSHA256':
        self.buf = b''  # type: bytes
        self.bytes_count = 0  # type: int
        self.s = [0x6a09e667,
                  0xbb67ae85,
                  0x3c6ef372,
                  0xa54ff53a,
                  0x510e527f,
                  0x9b05688c,
                  0x1f83d9ab,
                  0x5be0cd19]
        return self


__all__ = ('CSHA256',)
