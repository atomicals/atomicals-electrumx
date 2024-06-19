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

# pylama:ignore=E501

import json
import os
import unittest

from typing import Iterator, Tuple

from binascii import unhexlify

from bitcointx.core.script import CScript, OP_0, OP_1, OP_16
from bitcointx.bech32 import CBech32Data, Bech32Error
from bitcointx.segwit_addr import encode, decode


def load_test_vectors(name: str) -> Iterator[Tuple[str, str]]:
    with open(os.path.dirname(__file__) + '/data/' + name, 'r') as fd:
        for testcase in json.load(fd):
            yield testcase


def to_scriptPubKey(witver: int, witprog: bytes) -> CScript:
    """Decoded bech32 address to script"""
    return CScript([witver]) + CScript(bytes(witprog))


class Test_bech32(unittest.TestCase):

    def op_decode(self, witver: int) -> int:
        """OP encoding to int"""
        if witver == OP_0:
            return 0
        if OP_1 <= witver <= OP_16:
            return witver - OP_1 + 1
        self.fail('Wrong witver: %d' % witver)

    def test_encode_decode(self) -> None:
        for exp_bin_str, exp_bech32 in load_test_vectors('bech32_encode_decode.json'):
            exp_bin = unhexlify(exp_bin_str.encode('utf8'))
            witver = self.op_decode(exp_bin[0])
            hrp = exp_bech32[:exp_bech32.rindex('1')].lower()
            self.assertEqual(exp_bin[1], len(exp_bin[2:]))
            act_bech32 = encode(hrp, witver, exp_bin[2:])
            assert act_bech32 is not None
            act_bin = decode(hrp, exp_bech32)
            wv, wp = act_bin
            assert wv is not None
            assert wp is not None

            self.assertEqual(act_bech32.lower(), exp_bech32.lower())
            self.assertEqual(to_scriptPubKey(wv, wp), bytes(exp_bin))


class MockBech32Data(CBech32Data):
    bech32_hrp = 'bc'


class Test_CBech32Data(unittest.TestCase):
    def test_from_data(self) -> None:
        test_bytes = unhexlify('751e76e8199196d454941c45d1b3a323f1433bd6')
        b = MockBech32Data.from_bytes(test_bytes, witver=0)
        self.assertEqual(b.bech32_witness_version, 0)
        self.assertEqual(b.__class__.bech32_witness_version, -1)
        self.assertEqual(str(b).upper(), 'BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4')

        with self.assertRaises(ValueError):
            MockBech32Data.from_bytes(test_bytes, witver=-1)

        MockBech32Data.bech32_witness_version = 16

        with self.assertRaises(ValueError):
            MockBech32Data.from_bytes(test_bytes, witver=-1)

        with self.assertRaises(ValueError):
            MockBech32Data.from_bytes(test_bytes, witver=0)

        b = MockBech32Data.from_bytes(test_bytes, witver=16)
        self.assertEqual(b.bech32_witness_version, 16)
        self.assertEqual(MockBech32Data.bech32_witness_version, 16)

        witver, data = decode(MockBech32Data.bech32_hrp, str(b))
        self.assertEqual(data, test_bytes)
        self.assertEqual(witver, 16)

    def test_invalid_bech32_exception(self) -> None:

        for testdata in load_test_vectors("bech32_invalid.json"):
            assert len(testdata) in (2, 3)
            if len(testdata) == 3:
                assert isinstance(testdata[0], int)
                invalid = chr(testdata[0]) + testdata[1]
            elif len(testdata) == 2:
                invalid = testdata[0]

            msg = '%r should have raised Bech32Error but did not' % invalid
            with self.assertRaises(Bech32Error, msg=msg):
                MockBech32Data(invalid)
