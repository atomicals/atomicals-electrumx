# Copyright (C) 2020 The python-bitcointx developers
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

import ctypes
import binascii
from bitcointx.core.secp256k1 import (
    secp256k1_load_library, Secp256k1
)


class Test_Load_Secp256k1(unittest.TestCase):
    def test(self) -> None:

        def check_pub_parse(secp256k1: Secp256k1) -> None:
            pub = binascii.unhexlify('037b6e1e0cb249ae1c8320543a8f1d3f43c093529d9e838c47616c9c9f587ad818')  # noqa
            raw_pub = ctypes.create_string_buffer(64)
            result = secp256k1.lib.secp256k1_ec_pubkey_parse(
                secp256k1.ctx.verify, raw_pub, pub, len(pub))
            assert result == 1

            result = secp256k1.lib.secp256k1_ec_pubkey_parse(
                secp256k1.ctx.verify, raw_pub, b'\xFF'*32, 32)
            assert result == 0

            k = binascii.unhexlify('309355fdb2cd1de2edc859012f451d5009147d0bf3a52cee02d2511cca483132') # noqa
            result = secp256k1.lib.secp256k1_ec_privkey_tweak_add(
                secp256k1.ctx.sign, k, b'\xAA'*32)
            assert result == 1

        # check with system-defined path search
        secp256k1_def = secp256k1_load_library()
        assert isinstance(secp256k1_def.lib, ctypes.CDLL)
        check_pub_parse(secp256k1_def)

        # check with explicit path
        path = ctypes.util.find_library('secp256k1')
        secp256k1_ep = secp256k1_load_library(path=path)
        assert isinstance(secp256k1_ep.lib, ctypes.CDLL)
        check_pub_parse(secp256k1_ep)
