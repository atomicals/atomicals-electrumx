# Copyright (C) 2013-2015 The python-bitcoinlib developers
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

from typing import Iterator, Dict, Any

from bitcointx.core.secp256k1 import get_secp256k1
from bitcointx.wallet import CBitcoinKey, P2PKHCoinAddress
from bitcointx.signmessage import BitcoinMessage, VerifyMessage, SignMessage
import os
import json


def load_test_vectors(name: str) -> Iterator[Dict[str, Any]]:
    with open(os.path.dirname(__file__) + '/data/' + name, 'r') as fd:
        for testcase in json.load(fd):
            yield testcase


class Test_SignVerifyMessage(unittest.TestCase):

    @unittest.skipIf(
        not get_secp256k1().cap.has_pubkey_recovery,
        "secp256k1 compiled without pubkey recovery functions"
    )
    def test_verify_message_simple(self) -> None:
        address = P2PKHCoinAddress("1F26pNMrywyZJdr22jErtKcjF8R3Ttt55G")
        message = str(address)
        signature = ("H85WKpqtNZDrajOnYDgUY+abh0KCAcOsAIOQwx2PftAbLEPRA7mzXA"
                     "/CjXRxzz0MC225pR/hx02Vf2Ag2x33kU4=")

        message_to_verify = BitcoinMessage(message)

        self.assertTrue(VerifyMessage(address, message_to_verify, signature))

    @unittest.skipIf(
        not get_secp256k1().cap.has_pubkey_recovery,
        "secp256k1 compiled without pubkey recovery functions"
    )
    def test_verify_message_vectors(self) -> None:
        for vector in load_test_vectors('signmessage.json'):
            message = BitcoinMessage(vector['address'])
            self.assertTrue(VerifyMessage(
                P2PKHCoinAddress(vector['address']),
                message,
                vector['signature']
            ))

    @unittest.skipIf(
        not get_secp256k1().cap.has_pubkey_recovery,
        "secp256k1 compiled without pubkey recovery functions"
    )
    def test_sign_message_simple(self) -> None:

        key = CBitcoinKey(
            "L4vB5fomsK8L95wQ7GFzvErYGht49JsCPJyJMHpB4xGM6xgi2jvG")
        address = P2PKHCoinAddress("1F26pNMrywyZJdr22jErtKcjF8R3Ttt55G")
        message = str(address)

        message_to_sign = BitcoinMessage(message)
        signature = SignMessage(key, message_to_sign)

        self.assertTrue(signature)
        self.assertTrue(VerifyMessage(address, message_to_sign, signature))

    @unittest.skipIf(
        not get_secp256k1().cap.has_pubkey_recovery,
        "secp256k1 compiled without pubkey recovery functions"
    )
    def test_sign_message_vectors(self) -> None:
        for vector in load_test_vectors('signmessage.json'):
            key = CBitcoinKey(vector['wif'])
            message = BitcoinMessage(vector['address'])

            signature = SignMessage(key, message)

            self.assertTrue(
                signature,
                "Failed to sign for [%s]" % vector['address']
            )
            self.assertTrue(
                VerifyMessage(vector['address'], message, vector['signature']),
                "Failed to verify signature for [%s]" % vector['address']
            )


if __name__ == "__main__":
    unittest.main()
