# Copyright (C) 2019 The python-bitcointx developers
#
# This file is part of python-bitcointx.
#
# It is subject to the license terms in the LICENSE-PYTHON-BITCOINTX file found in the top-level
# directory of this distribution.
#
# No part of python-bitcointx, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

# pylama:ignore=E501,C901

import unittest
import warnings
import threading
import asyncio
import ctypes

from typing import Dict, Union

from bitcointx import (
    select_chain_params, get_current_chain_params, BitcoinMainnetParams
)
from bitcointx.util import ContextVarsCompat
from bitcointx.core import x, Hash160, CTransaction
from bitcointx.core.key import CPubKey
from bitcointx.core.script import CScript
from bitcointx.core.secp256k1 import (
    secp256k1_get_last_error, get_secp256k1
)
from bitcointx.wallet import (
    P2PKHCoinAddress, P2SHCoinAddress, P2WPKHCoinAddress,
    P2WPKHBitcoinRegtestAddress
)
import bitcointx.bech32
from bitcointx.base58 import CBase58Data


class Test_Threading(unittest.TestCase):

    def test_addresses(self) -> None:
        pub = CPubKey(x('0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71'))

        events: Dict[str, Union[threading.Event, asyncio.Event]]
        events = {
            'mainnet': threading.Event(),
            'testnet': threading.Event(),
            'regtest': threading.Event(),
        }

        # list append is thread-safe, can use just the list.
        finished_successfully = []

        def wait(name: str) -> None:
            evt = events[name]
            assert isinstance(evt, threading.Event)
            not_timed_out = evt.wait(timeout=5.0)
            assert not_timed_out

        async def wait_async(name: str) -> None:
            evt = events[name]
            assert isinstance(evt, asyncio.Event)
            await asyncio.wait_for(evt.wait(), 5.0)

        def ready(name: str) -> None:
            events[name].set()

        def finish(name: str) -> None:
            finished_successfully.append(name)

        def check_core_modules() -> None:
            # check that mutable/immutable thread-local context works
            CTransaction().to_mutable().to_immutable()

            secp256k1 = get_secp256k1()

            # check secp256k1 error handling (which uses thread-local storage)
            secp256k1.lib.secp256k1_ec_pubkey_tweak_add(
                secp256k1.ctx.verify,
                ctypes.c_char_p(0), ctypes.c_char_p(0))
            err = secp256k1_get_last_error()
            assert err['code'] == -2
            assert err['type'] == 'illegal_argument'
            assert 'message' in err

        def mainnet() -> None:
            select_chain_params('bitcoin/mainnet')
            wait('testnet')
            a = P2PKHCoinAddress.from_pubkey(pub)
            assert CBase58Data(str(a))[0] == 0
            check_core_modules()
            ready('mainnet')
            finish('mainnet')
            self.assertEqual(get_current_chain_params().NAME, 'bitcoin')

        async def async_mainnet() -> None:
            select_chain_params('bitcoin/mainnet')
            await wait_async('testnet')
            a = P2PKHCoinAddress.from_pubkey(pub)
            assert CBase58Data(str(a))[0] == 0
            check_core_modules()
            ready('mainnet')
            finish('mainnet')
            self.assertEqual(get_current_chain_params().NAME, 'bitcoin')

        def testnet() -> None:
            select_chain_params('bitcoin/testnet')
            wait('regtest')
            a = P2SHCoinAddress.from_redeemScript(
                CScript(b'\xa9' + Hash160(pub) + b'\x87'))
            assert CBase58Data(str(a))[0] == 196
            check_core_modules()
            ready('testnet')
            wait('mainnet')
            self.assertEqual(get_current_chain_params().NAME,
                             'bitcoin/testnet')
            finish('testnet')

        async def async_testnet() -> None:
            select_chain_params('bitcoin/testnet')
            await wait_async('regtest')
            a = P2SHCoinAddress.from_redeemScript(
                CScript(b'\xa9' + Hash160(pub) + b'\x87'))
            assert CBase58Data(str(a))[0] == 196
            check_core_modules()
            ready('testnet')
            await wait_async('mainnet')
            self.assertEqual(get_current_chain_params().NAME,
                             'bitcoin/testnet')
            finish('testnet')

        def regtest() -> None:
            select_chain_params('bitcoin/regtest')
            a = P2WPKHCoinAddress.from_pubkey(pub)
            witver, data = bitcointx.segwit_addr.decode(
                P2WPKHBitcoinRegtestAddress.bech32_hrp, str(a))
            assert witver == 0
            assert data == Hash160(pub)
            check_core_modules()
            ready('regtest')
            wait('testnet')
            wait('mainnet')
            self.assertEqual(get_current_chain_params().NAME,
                             'bitcoin/regtest')
            finish('regtest')

        async def async_regtest() -> None:
            select_chain_params('bitcoin/regtest')
            a = P2WPKHCoinAddress.from_pubkey(pub)
            witver, data = bitcointx.segwit_addr.decode(
                P2WPKHBitcoinRegtestAddress.bech32_hrp, str(a))
            assert witver == 0
            assert data == Hash160(pub)
            check_core_modules()
            ready('regtest')
            await wait_async('testnet')
            await wait_async('mainnet')
            self.assertEqual(get_current_chain_params().NAME,
                             'bitcoin/regtest')
            finish('regtest')

        assert isinstance(get_current_chain_params(), BitcoinMainnetParams), \
            "tests assume bitcoin params in effect by default"

        mainnet_thread = threading.Thread(target=mainnet)
        testnet_thread = threading.Thread(target=testnet)
        regtest_thread = threading.Thread(target=regtest)
        mainnet_thread.start()
        testnet_thread.start()
        regtest_thread.start()
        mainnet_thread.join()
        testnet_thread.join()
        regtest_thread.join()

        self.assertEqual(set(finished_successfully),
                         set(['mainnet', 'testnet', 'regtest']))
        self.assertIsInstance(get_current_chain_params(),
                              BitcoinMainnetParams)

        if issubclass(ContextVarsCompat, threading.local):
            warnings.warn(
                'contextvars.ContextVar is unavailable, asyncio contexts '
                'when switching chain params will be broken. '
                'Use python >= 3.7 if you want asyncio compatibility, or '
                'just don\'set chainparams in concurrent code.')
            return

        finished_successfully = []

        events = {
            'mainnet': asyncio.Event(),
            'testnet': asyncio.Event(),
            'regtest': asyncio.Event(),
        }

        async def go() -> None:
            f1 = asyncio.ensure_future(async_mainnet())
            f2 = asyncio.ensure_future(async_testnet())
            f3 = asyncio.ensure_future(async_regtest())
            await asyncio.gather(f1, f2, f3)

        asyncio.get_event_loop().run_until_complete(go())

        self.assertEqual(set(finished_successfully),
                         set(['mainnet', 'testnet', 'regtest']))
        self.assertIsInstance(get_current_chain_params(),
                              BitcoinMainnetParams)
