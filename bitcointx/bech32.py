# Copyright (C) 2017 The python-bitcoinlib developers
#
# This file is part of python-bitcointx.
#
# It is subject to the license terms in the LICENSE-PYTHON-BITCOINTX file found in the top-level
# directory of this distribution.
#
# No part of python-bitcointx, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

"""Bech32 encoding and decoding"""

from typing import TypeVar, Type, List, Optional, cast

import bitcointx
import bitcointx.core
from bitcointx.segwit_addr import encode, decode


T_CBech32Data = TypeVar('T_CBech32Data', bound='CBech32Data')
T_unbounded = TypeVar('T_unbounded')


class Bech32Error(bitcointx.core.AddressDataEncodingError):
    pass


class Bech32ChecksumError(Bech32Error):
    pass


class UnexpectedBech32LenghOrVersion(Bech32Error):
    """Raised by bech32_match_progam_and_version()
    when unexpected prefix encountered

    """


class CBech32Data(bytes):
    """Bech32-encoded data

    Includes a witver and checksum.
    """
    bech32_hrp: str
    bech32_witness_version: int = -1
    _data_length: int

    def __new__(cls: Type[T_CBech32Data], s: str) -> T_CBech32Data:
        """from bech32 addr to """
        if cls.bech32_hrp is None:
            raise TypeError(
                'CBech32Data subclasses should define bech32_hrp attribute')
        witver, data = decode(cls.bech32_hrp, s)
        if witver is None or data is None:
            assert witver is None and data is None
            raise Bech32Error('Bech32 decoding error')

        return cls.bech32_match_progam_and_version(data, witver)

    def __init__(self, s: str) -> None:
        """Initialize from bech32-encoded string

        Note: subclasses put your initialization routines here, but ignore the
        argument - that's handled by __new__(), and .from_bytes() will call
        __init__() with None in place of the string.
        """

    @classmethod
    def bech32_get_match_candidates(cls: Type[T_CBech32Data]
                                    ) -> List[Type[T_CBech32Data]]:
        if cls.bech32_witness_version >= 0:
            return [cls]
        return []

    @classmethod
    def bech32_match_progam_and_version(cls: Type[T_CBech32Data],
                                        data: bytes, witver: int
                                        ) -> T_CBech32Data:
        """Instantiate from data and witver.
        if witver is not set for class, this is equivalent of from_bytes()"""
        candidates = cls.bech32_get_match_candidates()
        if not candidates:
            return cls.from_bytes(data, witver=witver)

        for candidate in candidates:
            wv = candidate.bech32_witness_version
            if wv < 0:
                try:
                    return candidate.bech32_match_progam_and_version(
                        data, witver)
                except UnexpectedBech32LenghOrVersion:
                    pass
            elif len(data) == candidate._data_length and witver == wv:
                return candidate.from_bytes(data, witver=witver)

        if len(candidates) == 1:
            raise UnexpectedBech32LenghOrVersion(
                f'Incorrect length/version for {cls.__name__}: '
                f'{len(data)}/{witver}, expected '
                f'{cls._data_length}/{cls.bech32_witness_version}')

        raise UnexpectedBech32LenghOrVersion(
            'witness program or version does not match any known Bech32 '
            'address class')

    @classmethod
    def from_bytes(cls: Type[T_unbounded], witprog: bytes,
                   witver: Optional[int] = None) -> T_unbounded:
        """Instantiate from witver and data"""
        assert issubclass(cls, CBech32Data)
        cls_wv = cls.bech32_witness_version
        if witver is None:
            if cls_wv < 0:
                raise ValueError(
                    f'witver must be specified, {cls.__name__} does not '
                    f'specify bech32_witness_version')
            witver = cls_wv
        elif witver < 0:
            raise ValueError('negative witver specified')
        elif cls_wv >= 0 and witver != cls_wv:
            raise ValueError(
                f'witver specified but is not the same as '
                f'{cls.__name__}.bech32_witness_version')

        if not (0 <= witver <= 16):
            raise ValueError(
                'witver must be in range 0 to 16 inclusive; got %r' % witver)

        self = bytes.__new__(cls, witprog)
        if cls_wv < 0:
            self.bech32_witness_version = witver
        self.__init__(None)  # type: ignore

        return cast(T_unbounded, self)

    def to_bytes(self) -> bytes:
        """Convert to bytes instance

        Note that it's the data represented that is converted; the checkum and
        witver is not included.
        """
        return b'' + self

    def __str__(self) -> str:
        """Convert to string"""
        result = encode(self.bech32_hrp, self.bech32_witness_version, self)
        if result is None:
            raise AssertionError(
                'encode should not fail, this is data that '
                'was successfully decoded earlier')
        return result

    def __repr__(self) -> str:
        return '%s(%r)' % (self.__class__.__name__, str(self))


__all__ = (
    'Bech32Error',
    'Bech32ChecksumError',
    'CBech32Data',
)
