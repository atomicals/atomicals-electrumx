# Copyright (C) 2011 Sam Rushing
# Copyright (C) 2013-2014 The python-bitcoinlib developers
# Copyright (C) 2018-2019 The python-bitcointx developers
#
# This file is part of python-bitcointx.
#
# It is subject to the license terms in the LICENSE-PYTHON-BITCOINTX file found in the top-level
# directory of this distribution.
#
# No part of python-bitcointx, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

# pylama:ignore=E501

"""Base58 encoding and decoding"""

import binascii
import bitcointx.core

from typing import TypeVar, Type, List

B58_DIGITS = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


T_CBase58Data = TypeVar('T_CBase58Data', bound='CBase58Data')


class Base58Error(bitcointx.core.AddressDataEncodingError):
    pass


class UnexpectedBase58PrefixError(Base58Error):
    """Raised by base58_from_bytes_match_prefix() when unexpected prefix encountered

    """
    pass


class InvalidBase58Error(Base58Error):
    """Raised on generic invalid base58 data, such as bad characters.

    Checksum failures raise Base58ChecksumError specifically.
    """
    pass


def encode(b: bytes) -> str:
    """Encode bytes to a base58-encoded string"""

    # Convert big-endian bytes to integer
    n = int('0x0' + binascii.hexlify(b).decode('utf8'), 16)

    # Divide that integer into bas58
    res = []
    while n > 0:
        n, r = divmod(n, 58)
        res.append(B58_DIGITS[r])
    res_str = ''.join(res[::-1])

    # Encode leading zeros as base58 zeros
    czero = 0
    pad = 0
    for c in b:
        if c == czero:
            pad += 1
        else:
            break
    return B58_DIGITS[0] * pad + res_str


def decode(s: str) -> bytes:
    """Decode a base58-encoding string, returning bytes"""
    if not s:
        return b''

    # Convert the string to an integer
    n = 0
    for c in s:
        n *= 58
        if c not in B58_DIGITS:
            raise InvalidBase58Error('Character %r is not a valid base58 character' % c)
        digit = B58_DIGITS.index(c)
        n += digit

    # Convert the integer to bytes
    h = '%x' % n
    if len(h) % 2:
        h = '0' + h
    res = binascii.unhexlify(h.encode('utf8'))

    # Add padding back.
    pad = 0
    for c in s[:-1]:
        if c == B58_DIGITS[0]:
            pad += 1
        else:
            break
    return b'\x00' * pad + res


class Base58ChecksumError(Base58Error):
    """Raised on Base58 checksum errors"""
    pass


class CBase58Data(bytes):
    """Base58-encoded data

    Includes prefix and checksum.

    prefix is empty by default.
    """

    base58_prefix = b''
    _data_length: int

    def __new__(cls: Type[T_CBase58Data], s: str) -> T_CBase58Data:
        k = decode(s)
        if len(k) < 4:
            raise Base58Error('data too short')
        data, check0 = k[0:-4], k[-4:]
        check1 = bitcointx.core.Hash(data)[:4]
        if check0 != check1:
            raise Base58ChecksumError('Checksum mismatch: expected %r, calculated %r' % (check0, check1))
        return cls.base58_from_bytes_match_prefix(data)

    def __init__(self, s: str) -> None:
        """Initialize from base58-encoded string

        Note: subclasses put your initialization routines here, but ignore the
        argument - that's handled by __new__(), and .from_bytes() will call
        __init__() with None in place of the string.
        """

    def __str__(self) -> str:
        """Convert to string"""
        check = bitcointx.core.Hash(self.base58_prefix + self)[0:4]
        return encode(self.base58_prefix + self + check)

    @classmethod
    def base58_get_match_candidates(cls: Type[T_CBase58Data]
                                    ) -> List[Type[T_CBase58Data]]:
        if cls.base58_prefix:
            return [cls]
        return []

    @classmethod
    def base58_from_bytes_match_prefix(cls: Type[T_CBase58Data], data: bytes
                                       ) -> T_CBase58Data:
        """Instantiate from data with prefix.
        if prefix is empty, this is equivalent of from_bytes()"""
        candidates = cls.base58_get_match_candidates()
        if not candidates:
            return cls.from_bytes(data)

        for candidate in candidates:
            pfx = candidate.base58_prefix
            if not pfx:
                try:
                    return candidate.base58_from_bytes_match_prefix(data)
                except UnexpectedBase58PrefixError:
                    pass
            elif data.startswith(pfx):
                return candidate.from_bytes(data[len(pfx):])

        if len(candidates) == 1:
            raise UnexpectedBase58PrefixError(
                'Incorrect prefix bytes for {}: {}, expected {}'
                .format(cls.__name__,
                        bitcointx.core.b2x(data[:len(pfx)]),
                        bitcointx.core.b2x(cls.base58_prefix)))

        raise UnexpectedBase58PrefixError(
            'base58 prefix does not match any known base58 address class')

    @classmethod
    def from_bytes(cls: Type[T_CBase58Data], data: bytes) -> T_CBase58Data:
        """Instantiate from data"""
        self = bytes.__new__(cls, data)
        self.__init__(None)  # type: ignore
        return self

    def to_bytes(self) -> bytes:
        """Convert to bytes instance

        Note that it's the data represented that is converted;
        the prefix is not included.
        """
        return b'' + self

    def __repr__(self) -> str:
        return '%s(%r)' % (self.__class__.__name__, str(self))


__all__ = (
    'B58_DIGITS',
    'Base58Error',
    'InvalidBase58Error',
    'encode',
    'decode',
    'Base58ChecksumError',
    'CBase58Data',
)
