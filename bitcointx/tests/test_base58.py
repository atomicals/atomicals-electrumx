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

from bitcointx.base58 import CBase58Data, encode, decode, Base58Error


def load_test_vectors(name: str) -> Iterator[Tuple[str, str]]:
    with open(os.path.dirname(__file__) + '/data/' + name, 'r') as fd:
        for testcase in json.load(fd):
            yield testcase


class Test_base58(unittest.TestCase):
    def test_encode_decode(self) -> None:
        for exp_bin_str, exp_base58 in load_test_vectors('base58_encode_decode.json'):
            exp_bin = unhexlify(exp_bin_str.encode('utf8'))

            act_base58 = encode(exp_bin)
            act_bin = decode(exp_base58)

            self.assertEqual(act_base58, exp_base58)
            self.assertEqual(act_bin, exp_bin)


class Test_CBase58Data(unittest.TestCase):

    def test_from_data(self) -> None:
        def T(nVersion: int, data: bytes, address: str) -> None:
            prefix = bytes([nVersion])

            class MockBase58Address(CBase58Data):
                @classmethod
                def from_bytes(cls, data: bytes) -> 'MockBase58Address':
                    return super(MockBase58Address, cls).from_bytes(data)

            b = CBase58Data.from_bytes(prefix + data)
            self.assertEqual(str(b), address)

            MockBase58Address.base58_prefix = bytes(prefix)
            ma = MockBase58Address(address)
            self.assertEqual(str(ma), address)
            self.assertEqual(bytes(ma), data)

            MockBase58Address.base58_prefix = bytes([(nVersion + 1) & 0xFF])
            with self.assertRaises(Base58Error):
                ma = MockBase58Address(address)

        T(0, b"b\xe9\x07\xb1\\\xbf'\xd5BS\x99\xeb\xf6\xf0\xfbP\xeb\xb8\x8f\x18", '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa')
        T(196, b'Bf\xfco,(a\xd7\xfe"\x9b\'\x9ay\x80:\xfc\xa7\xba4', '2MyJKxYR2zNZZsZ39SgkCXWCfQtXKhnWSWq')

    def test_invalid_base58_exception(self) -> None:
        invalids = ('',  # missing everything
                    '#',  # invalid character
                    '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb',  # invalid checksum
                    )

        for invalid in invalids:
            msg = '%r should have raised InvalidBase58Error but did not' % invalid
            with self.assertRaises(Base58Error, msg=msg):
                CBase58Data(invalid)
