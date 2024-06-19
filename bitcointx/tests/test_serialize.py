# Copyright (C) 2013-2014 The python-bitcoinlib developers
#
# This file is part of python-bitcointx.
#
# It is subject to the license terms in the LICENSE-PYTHON-BITCOINTX file found in the top-level
# directory of this distribution.
#
# No part of python-bitcointx, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

import unittest
import random

from binascii import unhexlify

from typing import Any

from bitcointx.core.serialize import (
    Serializable, VarIntSerializer, BytesSerializer, SerializationError,
    SerializationTruncationError, DeserializationExtraDataError,
    DeserializationValueBoundsError, uint256_from_bytes, uint256_to_bytes,
    ByteStream_Type
)


class Test_Serializable(unittest.TestCase):
    def test_extra_data(self) -> None:
        """Serializable.deserialize() fails if extra data is present"""

        class FooSerializable(Serializable):
            @classmethod
            def stream_deserialize(cls, f: ByteStream_Type, **kwargs: Any
                                   ) -> 'FooSerializable':
                return cls()

            def stream_serialize(self, f: ByteStream_Type, **kwargs: Any
                                 ) -> None:
                pass

        try:
            FooSerializable.deserialize(b'\x00')
        except DeserializationExtraDataError as err:
            self.assertEqual(err.obj, FooSerializable())
            self.assertEqual(err.padding, b'\x00')

        else:
            self.fail("DeserializationExtraDataError not raised")

        FooSerializable.deserialize(b'\x00', allow_padding=True)


class Test_VarIntSerializer(unittest.TestCase):
    def test(self) -> None:
        def T(value: int, expected: bytes) -> None:
            expected = unhexlify(expected)
            expected_int = VarIntSerializer.deserialize(expected)
            self.assertEqual(value, expected_int)
            actual = VarIntSerializer.serialize(value)
            self.assertEqual(actual, expected)
            roundtrip = VarIntSerializer.deserialize(actual)
            self.assertEqual(value, roundtrip)

        T(0x0, b'00')
        T(0xfc, b'fc')
        T(0xfd, b'fdfd00')
        T(0xffff, b'fdffff')
        T(0x1234, b'fd3412')
        T(0x10000, b'fe00000100')
        T(0x1234567, b'fe67452301')
        T(0x2000000, b'fe00000002')

        with self.assertRaises(DeserializationValueBoundsError):
            T(0x2000001, b'fe01000002')

        with self.assertRaises(DeserializationValueBoundsError):
            T(0xffffffff, b'feffffffff')

        with self.assertRaises(DeserializationValueBoundsError):
            T(0x100000000, b'ff0000000001000000')

        with self.assertRaises(DeserializationValueBoundsError):
            T(0xffffffffffffffff, b'ffffffffffffffffff')

        with self.assertRaises(DeserializationValueBoundsError):
            T(0, b'fd0000')

        with self.assertRaises(DeserializationValueBoundsError):
            T(0, b'fe00000000')

        with self.assertRaises(DeserializationValueBoundsError):
            T(0, b'ff0000000000000000')

        with self.assertRaises(DeserializationValueBoundsError):
            T(0x123456789abcdef, b'ffefcdab8967452301')

    def test_truncated(self) -> None:
        def T(serialized: bytes) -> None:
            serialized = unhexlify(serialized)
            with self.assertRaises(SerializationTruncationError):
                VarIntSerializer.deserialize(serialized)
        T(b'')
        T(b'fd')
        T(b'fd00')
        T(b'fe')
        T(b'fe00')
        T(b'fe0000')
        T(b'fe000000')
        T(b'ff')
        T(b'ff00000000000000')


class Test_BytesSerializer(unittest.TestCase):
    def test(self) -> None:
        def T(value: bytes, expected: bytes) -> None:
            value = unhexlify(value)
            expected = unhexlify(expected)
            actual = BytesSerializer.serialize(value)
            self.assertEqual(actual, expected)
            roundtrip = BytesSerializer.deserialize(actual)
            self.assertEqual(value, roundtrip)
        T(b'', b'00')
        T(b'00', b'0100')
        T(b'00'*0xffff, b'fdffff' + b'00'*0xffff)

    def test_truncated(self) -> None:
        def T(serialized: bytes, ex_cls: type = SerializationTruncationError
              ) -> None:
            serialized = unhexlify(serialized)
            with self.assertRaises(ex_cls):
                BytesSerializer.deserialize(serialized)
        T(b'')
        T(b'01')
        T(b'0200')
        T(b'ff00000000000000ff11223344', SerializationError)  # > max_size


class Test_Uint256_Serialize(unittest.TestCase):
    def test_fixed(self) -> None:
        values = []
        values.append(0)
        values.append(
            0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
        for x in range(100):
            values.append(random.getrandbits(256))
        for n in values:
            assert uint256_from_bytes(uint256_to_bytes(n)) == n
