# Copyright (C) 2013-2015 The python-bitcoinlib developers
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

import os
import json
import hashlib
import unittest

from typing import Iterable, Optional, Callable, Union, Type, List, Any

import bitcointx
from bitcointx import (
    ChainParams,
    BitcoinSignetParams,
    BitcoinRegtestParams,
    BitcoinMainnetParams,
    get_current_chain_params,
    select_chain_params
)
from bitcointx.util import dispatcher_mapped_list
from bitcointx.core import (
    b2x, x, Hash160, CTransaction, CMutableTransaction, CTxOut,
    CMutableTxInWitness, CoreCoinParams
)
from bitcointx.core.script import (
    CScript, IsLowDERSignature, TaprootScriptTree,
    SignatureHashSchnorr, CScriptWitness, SIGHASH_Type,
    TaprootScriptTreeLeaf_Type
)
from bitcointx.core.key import (
    CPubKey, XOnlyPubKey, compute_tap_tweak_hash
)
from bitcointx.wallet import (
    CCoinAddressError as CBitcoinAddressError,
    CCoinAddress,
    CBitcoinAddress,
    CBase58BitcoinAddress,
    CBech32BitcoinAddress,
    P2PKHCoinAddress,
    P2SHCoinAddress,
    P2WPKHCoinAddress,
    P2WSHCoinAddress,
    P2TRCoinAddress,
    P2PKHBitcoinAddress,
    P2SHBitcoinAddress,
    P2WPKHBitcoinAddress,
    P2WSHBitcoinAddress,
    P2TRBitcoinAddress,
    CBitcoinKey, CCoinKey
)


def _test_address_implementations(
    test: unittest.TestCase,
    paramclasses: Optional[Iterable[type]] = None,
    extra_addr_testfunc: Callable[..., bool] = lambda *args: False
) -> None:
    pub = CPubKey(x('0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71'))
    if paramclasses is None:
        paramclasses = bitcointx.get_registered_chain_params()
    for paramclass in paramclasses:
        with ChainParams(paramclass):
            def recursive_check(aclass: type) -> None:
                assert issubclass(aclass, CCoinAddress)

                if extra_addr_testfunc(aclass, pub):
                    pass
                else:
                    a = None

                    if getattr(aclass, 'from_xonly_pubkey', None):
                        xa = aclass.from_xonly_pubkey(XOnlyPubKey(pub))
                        a = aclass.from_pubkey(pub)
                        test.assertEqual(a, xa)
                        xoa = aclass.from_xonly_output_pubkey(XOnlyPubKey(pub))
                        a_from_spk = aclass.from_scriptPubKey(
                            CScript(b'\x51\x20' + pub[1:]))
                        test.assertEqual(a_from_spk, xoa)
                    elif getattr(aclass, 'from_pubkey', None):
                        a = aclass.from_pubkey(pub)
                    elif getattr(aclass, 'from_redeemScript', None):
                        a = aclass.from_redeemScript(
                            CScript(b'\xa9' + Hash160(pub) + b'\x87'))
                    else:
                        assert len(dispatcher_mapped_list(aclass)) > 0, \
                            ("dispatcher mapped list for {} "
                                "must not be empty".format(aclass))

                    if a is not None:
                        spk = a.to_scriptPubKey()
                        test.assertEqual(a, aclass.from_scriptPubKey(spk))
                        a2 = aclass.from_bytes(a)
                        test.assertEqual(bytes(a), bytes(a2))
                        test.assertEqual(str(a), str(a2))
                        a3 = aclass(str(a))
                        test.assertEqual(bytes(a), bytes(a3))
                        test.assertEqual(str(a), str(a3))

                for next_aclass in dispatcher_mapped_list(aclass):
                    recursive_check(next_aclass)

            recursive_check(CCoinAddress)


class Test_CCoinAddress(unittest.TestCase):

    def test_address_implementations(self) -> None:
        _test_address_implementations(self)

    def test_get_output_size(self) -> None:
        pub = CPubKey(x('0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71'))
        a0 = P2PKHCoinAddress.from_pubkey(pub)
        self.assertEqual(P2PKHCoinAddress.get_output_size(), 34)
        self.assertEqual(a0.get_output_size(), 34)
        a1 = P2WPKHCoinAddress.from_pubkey(pub)
        self.assertEqual(P2WPKHCoinAddress.get_output_size(), 31)
        self.assertEqual(a1.get_output_size(), 31)
        a2 = P2SHCoinAddress.from_redeemScript(
            CScript(b'\xa9' + Hash160(pub) + b'\x87'))
        self.assertEqual(P2SHCoinAddress.get_output_size(), 32)
        self.assertEqual(a2.get_output_size(), 32)
        a3 = P2WSHCoinAddress.from_redeemScript(
            CScript(b'\xa9' + Hash160(pub) + b'\x87'))
        self.assertEqual(P2WSHCoinAddress.get_output_size(), 43)
        self.assertEqual(a3.get_output_size(), 43)
        a4 = P2TRCoinAddress.from_pubkey(pub)
        self.assertEqual(P2TRCoinAddress.get_output_size(), 43)
        self.assertEqual(a4.get_output_size(), 43)

    def test_scriptpubkey_type(self) -> None:
        for l1_cls in dispatcher_mapped_list(CCoinAddress):
            for l2_cls in dispatcher_mapped_list(l1_cls):
                for l3_cls in dispatcher_mapped_list(l2_cls):
                    spk_type = l3_cls.get_scriptPubKey_type()
                    matched_cls = CCoinAddress.match_scriptPubKey_type(spk_type)
                    self.assertTrue(l3_cls is matched_cls)


class Test_CBitcoinAddress(unittest.TestCase):
    def test_create_from_string(self) -> None:
        """Create CBitcoinAddress's from strings"""

        def T(str_addr: str, expected_bytes: bytes, expected_version: int,
              expected_class: type) -> None:
            addr = CCoinAddress(str_addr)
            addr2 = CBitcoinAddress(str_addr)
            self.assertEqual(addr, addr2)
            self.assertEqual(type(addr), type(addr2))
            self.assertEqual(bytes(addr), expected_bytes)
            self.assertEqual(addr.__class__, expected_class)
            if isinstance(addr, CBase58BitcoinAddress):
                self.assertEqual(addr.base58_prefix[0], expected_version)
            elif isinstance(addr, CBech32BitcoinAddress):
                self.assertEqual(addr.bech32_witness_version, expected_version)

        T('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
          x('62e907b15cbf27d5425399ebf6f0fb50ebb88f18'), 0,
          P2PKHBitcoinAddress)

        T('37k7toV1Nv4DfmQbmZ8KuZDQCYK9x5KpzP',
          x('4266fc6f2c2861d7fe229b279a79803afca7ba34'), 5,
          P2SHBitcoinAddress)

        T('BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4',
          x('751e76e8199196d454941c45d1b3a323f1433bd6'), 0,
          P2WPKHBitcoinAddress)

        T('bc1qc7slrfxkknqcq2jevvvkdgvrt8080852dfjewde450xdlk4ugp7szw5tk9',
          x('c7a1f1a4d6b4c1802a59631966a18359de779e8a6a65973735a3ccdfdabc407d'), 0,
          P2WSHBitcoinAddress)

        T('bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0',
          x('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'), 1,
          P2TRBitcoinAddress)

    def test_wrong_nVersion(self) -> None:
        """Creating a CBitcoinAddress from a unknown nVersion fails"""

        # tests run in mainnet, so both of the following should fail
        with self.assertRaises(CBitcoinAddressError):
            CBitcoinAddress('mpXwg4jMtRhuSpVq4xS3HFHmCmWp9NyGKt')

        with self.assertRaises(CBitcoinAddressError):
            CBitcoinAddress('2MyJKxYR2zNZZsZ39SgkCXWCfQtXKhnWSWq')

    def test_from_scriptPubKey(self) -> None:
        def T(hex_scriptpubkey: str, expected_str_address: str,
              expected_class: type) -> None:
            scriptPubKey = CScript(x(hex_scriptpubkey))
            addr = CBitcoinAddress.from_scriptPubKey(scriptPubKey)
            self.assertEqual(str(addr), expected_str_address)
            self.assertEqual(addr.__class__, expected_class)

        T('a914000000000000000000000000000000000000000087', '31h1vYVSYuKP6AhS86fbRdMw9XHieotbST',
          P2SHBitcoinAddress)
        T('76a914000000000000000000000000000000000000000088ac', '1111111111111111111114oLvT2',
          P2PKHBitcoinAddress)
        T('0014751e76e8199196d454941c45d1b3a323f1433bd6',
          'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4',
          P2WPKHBitcoinAddress)
        T('0020c7a1f1a4d6b4c1802a59631966a18359de779e8a6a65973735a3ccdfdabc407d',
          'bc1qc7slrfxkknqcq2jevvvkdgvrt8080852dfjewde450xdlk4ugp7szw5tk9',
          P2WSHBitcoinAddress)
        T('512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
          'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0',
          P2TRBitcoinAddress)

    def test_from_invalid_scriptPubKey(self) -> None:
        """CBitcoinAddress.from_scriptPubKey() with non-standard or invalid scriptPubKeys"""

        # Bad P2SH scriptPubKeys

        # non-canonical pushdata
        scriptPubKey = CScript(x('a94c14000000000000000000000000000000000000000087'))
        with self.assertRaises(CBitcoinAddressError):
            CBitcoinAddress.from_scriptPubKey(scriptPubKey)

        # Truncated P2SH
        scriptPubKey = CScript(x('a91400000000000000000000000000000000000000'))
        with self.assertRaises(CBitcoinAddressError):
            CBitcoinAddress.from_scriptPubKey(scriptPubKey)

        # Bad P2PKH scriptPubKeys

        # Truncated P2PKH
        scriptPubKey = CScript(x('76a91400000000000000000000000000000000000000'))
        with self.assertRaises(CBitcoinAddressError):
            CBitcoinAddress.from_scriptPubKey(scriptPubKey)

        # Missing a byte
        scriptPubKey = CScript(x('76a914000000000000000000000000000000000000000088'))
        with self.assertRaises(CBitcoinAddressError):
            CBitcoinAddress.from_scriptPubKey(scriptPubKey)

        # One extra byte
        scriptPubKey = CScript(x('76a914000000000000000000000000000000000000000088acac'))
        with self.assertRaises(CBitcoinAddressError):
            CBitcoinAddress.from_scriptPubKey(scriptPubKey)

        # One byte changed
        scriptPubKey = CScript(x('76a914000000000000000000000000000000000000000088ad'))
        with self.assertRaises(CBitcoinAddressError):
            CBitcoinAddress.from_scriptPubKey(scriptPubKey)

        # Bad P2TR scriptPubKey

        # Truncated
        scriptPubKey = CScript(x('79be667ef9dcbbac55a06295ce870b07029bfcdb2d'))
        with self.assertRaises(CBitcoinAddressError):
            CBitcoinAddress.from_scriptPubKey(scriptPubKey)

        # Missing a byte
        scriptPubKey = CScript(x('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817'))
        with self.assertRaises(CBitcoinAddressError):
            CBitcoinAddress.from_scriptPubKey(scriptPubKey)

        # One extra byte
        scriptPubKey = CScript(x('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac'))
        with self.assertRaises(CBitcoinAddressError):
            CBitcoinAddress.from_scriptPubKey(scriptPubKey)

        # One byte changed
        scriptPubKey = CScript(x('79be667ef9dcbbac55a06295ce870b07029bfcdb1dce28d959f2815b16f81798'))
        with self.assertRaises(CBitcoinAddressError):
            CBitcoinAddress.from_scriptPubKey(scriptPubKey)

    def test_to_redeemScript_ok(self) -> None:
        def T(str_addr: str, expected_scriptPubKey_hexbytes: str) -> None:
            addr = CBitcoinAddress(str_addr)

            actual_scriptPubKey = addr.to_redeemScript()
            self.assertEqual(b2x(actual_scriptPubKey),
                             expected_scriptPubKey_hexbytes)

        T('1111111111111111111114oLvT2',
          '76a914000000000000000000000000000000000000000088ac')

        T('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4',
          '76a914751e76e8199196d454941c45d1b3a323f1433bd688ac')

    def test_to_redeemScript_fail(self) -> None:
        def T(str_addr: str) -> None:
            addr = CBitcoinAddress(str_addr)

            with self.assertRaises(NotImplementedError):
                addr.to_redeemScript()

        T('31h1vYVSYuKP6AhS86fbRdMw9XHieotbST')
        T('bc1qc7slrfxkknqcq2jevvvkdgvrt8080852dfjewde450xdlk4ugp7szw5tk9')

    def test_to_scriptPubKey(self) -> None:
        """CBitcoinAddress.to_scriptPubKey() works"""
        def T(str_addr: str, expected_scriptPubKey_hexbytes: str) -> None:
            addr = CBitcoinAddress(str_addr)

            actual_scriptPubKey = addr.to_scriptPubKey()
            self.assertEqual(b2x(actual_scriptPubKey), expected_scriptPubKey_hexbytes)

        T('31h1vYVSYuKP6AhS86fbRdMw9XHieotbST',
          'a914000000000000000000000000000000000000000087')

        T('1111111111111111111114oLvT2',
          '76a914000000000000000000000000000000000000000088ac')

        T('31h1vYVSYuKP6AhS86fbRdMw9XHieotbST',
          'a914000000000000000000000000000000000000000087')
        T('1111111111111111111114oLvT2',
          '76a914000000000000000000000000000000000000000088ac')
        T('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4',
          '0014751e76e8199196d454941c45d1b3a323f1433bd6')
        T('bc1qc7slrfxkknqcq2jevvvkdgvrt8080852dfjewde450xdlk4ugp7szw5tk9',
          '0020c7a1f1a4d6b4c1802a59631966a18359de779e8a6a65973735a3ccdfdabc407d')
        T('bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0',
          '512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')

    def test_from_redeemScript(self) -> None:
        def T(script: CScript, expected_str_address: str,
              cls: Union[Type[P2SHCoinAddress], Type[P2WSHCoinAddress]]
              ) -> None:
            addr = cls.from_redeemScript(script)
            self.assertEqual(str(addr), expected_str_address)

        T(CScript(), '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy', P2SHBitcoinAddress)
        T(CScript(x('76a914751e76e8199196d454941c45d1b3a323f1433bd688ac')),
          '3LRW7jeCvQCRdPF8S3yUCfRAx4eqXFmdcr', P2SHBitcoinAddress)
        T(CScript(),
          'bc1quwcvgs5clswpfxhm7nyfjmaeysn6us0yvjdexn9yjkv3k7zjhp2sfl5g83',
          P2WSHBitcoinAddress)
        T(CScript(x('76a914751e76e8199196d454941c45d1b3a323f1433bd688ac')),
          'bc1q8a9wr6e7whe40py3sywj066euga9zt8ep3emz0r2e4zfna7y629s6kegdt',
          P2WSHBitcoinAddress)

    def test_from_valid_pubkey(self) -> None:
        """Create P2PKHBitcoinAddress's from valid pubkeys"""

        def T(
            pubkey: bytes, expected_str_addr: str,
            cls: Union[Type[P2PKHCoinAddress], Type[P2WPKHCoinAddress], Type[P2TRCoinAddress]],
            accept_uncompressed: bool = False
        ) -> None:
            if len(pubkey) == 32:
                addr = cls.from_output_pubkey(pubkey)
            else:
                if accept_uncompressed:
                    assert len(pubkey) == 65
                    assert issubclass(cls, P2PKHCoinAddress)
                    addr = cls.from_pubkey(pubkey, accept_uncompressed=accept_uncompressed)
                else:
                    assert len(pubkey) == 33
                    if issubclass(cls, P2TRCoinAddress):
                        addr = cls.from_output_pubkey(pubkey)
                    else:
                        addr = cls.from_pubkey(pubkey)
            self.assertEqual(str(addr), expected_str_addr)

        T(x('0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71'),
          '1C7zdTfnkzmr13HfA2vNm5SJYRK6nEKyq8', P2PKHBitcoinAddress)
        T(x('0478d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a1518063243acd4dfe96b66e3f2ec8013c8e072cd09b3834a19f81f659cc3455'),
          '1JwSSubhmg6iPtRjtyqhUYYH7bZg3Lfy1T', P2PKHBitcoinAddress, True)

        T(x('0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71'),
          'bc1q08alc0e5ua69scxhvyma568nvguqccrv4cc9n4', P2WPKHBitcoinAddress)

        # P2TR from ordinary pubkey
        T(x('0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71'),
          'bc1p0r2rqf60330vzvsn8q23a8e87nr8dgqghhux8rg8czmtax4nt3csc0rfcn',
          P2TRBitcoinAddress)
        # P2TR from x-only pubkey
        T(x('78d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71'),
          'bc1p0r2rqf60330vzvsn8q23a8e87nr8dgqghhux8rg8czmtax4nt3csc0rfcn',
          P2TRBitcoinAddress)

        T(CPubKey(x('0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71')),
          '1C7zdTfnkzmr13HfA2vNm5SJYRK6nEKyq8', P2PKHBitcoinAddress)
        T(CPubKey(x('0478d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a1518063243acd4dfe96b66e3f2ec8013c8e072cd09b3834a19f81f659cc3455')),
          '1JwSSubhmg6iPtRjtyqhUYYH7bZg3Lfy1T', P2PKHBitcoinAddress, True)

        T(CPubKey(x('0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71')),
          'bc1q08alc0e5ua69scxhvyma568nvguqccrv4cc9n4', P2WPKHBitcoinAddress)
        T(CPubKey(x('0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71')),
          'bc1p0r2rqf60330vzvsn8q23a8e87nr8dgqghhux8rg8czmtax4nt3csc0rfcn',
          P2TRBitcoinAddress)

        T(XOnlyPubKey(CPubKey(x('0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71'))),
            'bc1p0r2rqf60330vzvsn8q23a8e87nr8dgqghhux8rg8czmtax4nt3csc0rfcn',
            P2TRBitcoinAddress)

    def test_from_invalid_pubkeys(self) -> None:
        """Create P2PKHBitcoinAddress's from invalid pubkeys"""

        # first test with accept_invalid=True
        def T(invalid_pubkey: bytes, expected_str_addr: str,
              cls: Union[Type[P2PKHBitcoinAddress], Type[P2WPKHBitcoinAddress],
                         Type[P2TRBitcoinAddress]]
              ) -> None:
            addr: Union[P2PKHBitcoinAddress, P2WPKHBitcoinAddress,
                        P2TRBitcoinAddress]
            if issubclass(cls, P2TRCoinAddress):
                addr = cls.from_output_pubkey(invalid_pubkey, accept_invalid=True)
            else:
                addr = cls.from_pubkey(invalid_pubkey, accept_invalid=True)

            self.assertEqual(str(addr), expected_str_addr)

        inv_pub_bytes = x('0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c72')

        T(x(''), '1HT7xU2Ngenf7D4yocz2SAcnNLW7rK8d4E', P2PKHBitcoinAddress)
        T(inv_pub_bytes, '1L9V4NXbNtZsLjrD3nkU7gtEYLWRBWXLiZ', P2PKHBitcoinAddress)
        T(x(''), 'bc1qk3e2yekshkyuzdcx5sfjena3da7rh87t4thq9p', P2WPKHBitcoinAddress)
        T(inv_pub_bytes, 'bc1q6gzj82cpgy0pe9jgh0utalfp2kyvvm72m0zlrt',
          P2WPKHBitcoinAddress)
        T(b'\x00'*32, 'bc1pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpqqenm',
          P2TRBitcoinAddress)
        T(CPubKey(inv_pub_bytes), 'bc1p0r2rqf60330vzvsn8q23a8e87nr8dgqghhux8rg8czmtax4nt3eqznytxx',
          P2TRBitcoinAddress)

        # With accept_invalid=False we should get CBitcoinAddressError's

        for inv_pub in (x(''), inv_pub_bytes, CPubKey(inv_pub_bytes)):
            for cls in (P2PKHBitcoinAddress, P2WPKHBitcoinAddress,
                        P2TRBitcoinAddress):
                with self.assertRaises(CBitcoinAddressError):
                    if issubclass(cls, P2TRCoinAddress):
                        cls.from_output_pubkey(inv_pub)
                    else:
                        cls.from_pubkey(inv_pub)

            with self.assertRaises(CBitcoinAddressError):
                P2TRCoinAddress.from_pubkey(inv_pub)

        for inv_pub in (x(''), inv_pub_bytes[1:],
                        XOnlyPubKey(inv_pub_bytes[1:])):
            with self.assertRaises(CBitcoinAddressError):
                P2TRCoinAddress.from_xonly_output_pubkey(inv_pub)
            with self.assertRaises(CBitcoinAddressError):
                P2TRCoinAddress.from_xonly_pubkey(inv_pub)


class Test_P2PKHBitcoinAddress(unittest.TestCase):
    def test_from_non_canonical_scriptPubKey(self) -> None:
        def T(hex_scriptpubkey: str, expected_str_address: str) -> None:
            scriptPubKey = CScript(x(hex_scriptpubkey))
            # now test that CBitcoinAddressError is raised, non-canonical
            # pushdata is not allowed
            with self.assertRaises(CBitcoinAddressError):
                P2PKHBitcoinAddress.from_scriptPubKey(scriptPubKey)

        T('76a94c14000000000000000000000000000000000000000088ac', '1111111111111111111114oLvT2')
        T('76a94d1400000000000000000000000000000000000000000088ac', '1111111111111111111114oLvT2')
        T('76a94e14000000000000000000000000000000000000000000000088ac', '1111111111111111111114oLvT2')

        # make sure invalid scripts raise CBitcoinAddressError
        with self.assertRaises(CBitcoinAddressError):
            P2PKHBitcoinAddress.from_scriptPubKey(CScript(x('76a94c14')))

    def test_from_bare_checksig_scriptPubKey(self) -> None:
        def T(hex_scriptpubkey: str, expected_str_address: str) -> None:
            scriptPubKey = CScript(x(hex_scriptpubkey))
            # test that CBitcoinAddressError is raised, we do not support
            # bare checksig
            with self.assertRaises(CBitcoinAddressError):
                P2PKHBitcoinAddress.from_scriptPubKey(scriptPubKey)

        # compressed
        T('21000000000000000000000000000000000000000000000000000000000000000000ac', '14p5cGy5DZmtNMQwTQiytBvxMVuTmFMSyU')

        # uncompressed
        T('410000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ac', '13VmALKHkCdSN1JULkP6RqW3LcbpWvgryV')

        # non-canonical encoding
        T('4c21000000000000000000000000000000000000000000000000000000000000000000ac', '14p5cGy5DZmtNMQwTQiytBvxMVuTmFMSyU')

        # odd-lengths are *not* accepted
        with self.assertRaises(CBitcoinAddressError):
            P2PKHBitcoinAddress.from_scriptPubKey(CScript(x('2200000000000000000000000000000000000000000000000000000000000000000000ac')))


class Test_CBitcoinKey(unittest.TestCase):
    def test(self) -> None:
        def T(base58_privkey: str, expected_hex_pubkey: str, expected_is_compressed_value: bool) -> None:
            key = CBitcoinKey(base58_privkey)
            self.assertEqual(b2x(key.pub), expected_hex_pubkey)
            self.assertEqual(key.is_compressed(), expected_is_compressed_value)

        T('5KJvsngHeMpm884wtkJNzQGaCErckhHJBGFsvd3VyK5qMZXj3hS',
          '0478d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a1518063243acd4dfe96b66e3f2ec8013c8e072cd09b3834a19f81f659cc3455',
          False)
        T('L3p8oAcQTtuokSCRHQ7i4MhjWc9zornvpJLfmg62sYpLRJF9woSu',
          '0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71',
          True)

    def test_sign(self) -> None:
        key = CBitcoinKey('5KJvsngHeMpm884wtkJNzQGaCErckhHJBGFsvd3VyK5qMZXj3hS')
        hash = b'\x00' * 32
        sig = key.sign(hash)

        # Check a valid signature
        self.assertTrue(key.pub.verify(hash, sig))
        self.assertTrue(IsLowDERSignature(sig))

        # Check that invalid hash returns false
        self.assertFalse(key.pub.verify(b'\xFF'*32, sig))

        # Check that invalid signature returns false.
        #
        # Note the one-in-four-billion chance of a false positive :)
        self.assertFalse(key.pub.verify(hash, sig[0:-4] + b'\x00\x00\x00\x00'))

    def test_sign_invalid_hash(self) -> None:
        key = CBitcoinKey('5KJvsngHeMpm884wtkJNzQGaCErckhHJBGFsvd3VyK5qMZXj3hS')
        with self.assertRaises(TypeError):
            key.sign('0' * 32)  # type: ignore

        hash = b'\x00' * 32
        with self.assertRaises(ValueError):
            key.sign(hash[0:-2])

    def test_from_to_compressed(self) -> None:
        def T(keydata: str, compressed: str, uncompressed: str) -> None:
            k = CBitcoinKey.from_secret_bytes(x(keydata))
            k_u = CBitcoinKey.from_secret_bytes(x(keydata), False)

            self.assertTrue(k.is_compressed())
            self.assertEqual(k.pub, x(compressed))

            k2 = CBitcoinKey(str(k))
            self.assertTrue(k2.is_compressed())
            self.assertEqual(k, k2)

            k = k.to_uncompressed()
            self.assertEqual(k, k_u)
            self.assertEqual(len(k), 32)
            self.assertFalse(k.is_compressed())
            self.assertEqual(k.pub, x(uncompressed))

            k2 = CBitcoinKey(str(k))
            self.assertFalse(k2.is_compressed())
            self.assertEqual(k, k2)

            k = k.to_compressed()
            self.assertEqual(len(k), 33)
            self.assertEqual(k[-1], 1)
            self.assertTrue(k.is_compressed())
            self.assertEqual(k.pub, x(compressed))

        T('0de5306487851213f0aae1454f4e4449949a755802b60f6eb47906149395d080',
          '023bd76d581c4823f66d8f3f6462dfdb3c8823ba77c7e8b5284d04b41b83659811',
          '043bd76d581c4823f66d8f3f6462dfdb3c8823ba77c7e8b5284d04b41b836598111af4e26a83ff8e3e0eef15eca09953f9a3d3c2c15807c5ef68a180fb8d4260c6')
        T('c9ff05edfbfb4710267ccf212fbb0414284b09fce621f8ab61a5b1cf0f3a5bf2',
          '029925633a4ba7d5f6f60d94213f65dfc482aa9b0f3cadb1ce20d7b7d792428209',
          '049925633a4ba7d5f6f60d94213f65dfc482aa9b0f3cadb1ce20d7b7d792428209973a2e2e14e13d6263c894fefd5374d1d2b0e637b2215209b55604c0bb4f1196')


class Test_RFC6979(unittest.TestCase):
    def test(self) -> None:
        # Test Vectors for RFC 6979 ECDSA, secp256k1, SHA-256
        # (private key, message, expected k, expected signature)
        test_vectors = [
            (0x1, "Satoshi Nakamoto", 0x8F8A276C19F4149656B280621E358CCE24F5F52542772691EE69063B74F15D15, "934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d82442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5"),
            (0x1, "All those moments will be lost in time, like tears in rain. Time to die...", 0x38AA22D72376B4DBC472E06C3BA403EE0A394DA63FC58D88686C611ABA98D6B3, "8600dbd41e348fe5c9465ab92d23e3db8b98b873beecd930736488696438cb6b547fe64427496db33bf66019dacbf0039c04199abb0122918601db38a72cfc21"),
            (0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140, "Satoshi Nakamoto", 0x33A19B60E25FB6F4435AF53A3D42D493644827367E6453928554F43E49AA6F90, "fd567d121db66e382991534ada77a6bd3106f0a1098c231e47993447cd6af2d06b39cd0eb1bc8603e159ef5c20a5c8ad685a45b06ce9bebed3f153d10d93bed5"),
            (0xf8b8af8ce3c7cca5e300d33939540c10d45ce001b8f252bfbc57ba0342904181, "Alan Turing", 0x525A82B70E67874398067543FD84C83D30C175FDC45FDEEE082FE13B1D7CFDF1, "7063ae83e7f62bbb171798131b4a0564b956930092b33b07b395615d9ec7e15c58dfcc1e00a35e1572f366ffe34ba0fc47db1e7189759b9fb233c5b05ab388ea"),
            (0xe91671c46231f833a6406ccbea0e3e392c76c167bac1cb013f6f1013980455c2, "There is a computer disease that anybody who works with computers knows about. It's a very serious disease and it interferes completely with the work. The trouble with computers is that you 'play' with them!", 0x1F4B84C23A86A221D233F2521BE018D9318639D5B8BBD6374A8A59232D16AD3D, "b552edd27580141f3b2a5463048cb7cd3e047b97c9f98076c32dbdf85a68718b279fa72dd19bfae05577e06c7c0c1900c371fcd5893f7e1d56a37d30174671f6")
        ]
        for vector in test_vectors:
            secret = CBitcoinKey.from_secret_bytes(x('{:064x}'.format(vector[0])))
            encoded_sig = secret.sign(hashlib.sha256(vector[1].encode('utf8')).digest(),
                                      _ecdsa_sig_grind_low_r=False)

            assert encoded_sig[0] == 0x30
            assert encoded_sig[1] == len(encoded_sig)-2
            assert encoded_sig[2] == 0x02

            rlen = encoded_sig[3]
            rpos = 4
            assert rlen in (32, 33)

            if rlen == 33:
                assert encoded_sig[rpos] == 0
                rpos += 1
                rlen -= 1

            rval = encoded_sig[rpos:rpos+rlen]
            spos = rpos+rlen
            assert encoded_sig[spos] == 0x02

            spos += 1
            slen = encoded_sig[spos]
            assert slen in (32, 33)

            spos += 1
            if slen == 33:
                assert encoded_sig[spos] == 0
                spos += 1
                slen -= 1

            sval = encoded_sig[spos:spos+slen]
            sig = b2x(rval + sval)
            assert str(sig) == vector[3]


class TestChainParams(unittest.TestCase):
    def setUp(self) -> None:
        self.current_params = get_current_chain_params()

    def test_chain_params_context_manager(self) -> None:
        with ChainParams(BitcoinRegtestParams) as p1:
            assert isinstance(p1, BitcoinRegtestParams)
            with ChainParams(BitcoinSignetParams) as p2:
                assert isinstance(
                    p2,
                    BitcoinSignetParams
                )
                assert isinstance(
                    get_current_chain_params(),
                    BitcoinSignetParams
                )
            assert isinstance(
                get_current_chain_params(),
                BitcoinRegtestParams
            )

    def test_select_chain_params(self) -> None:
        prev_params, cur_params = select_chain_params('bitcoin/regtest')
        assert isinstance(prev_params, BitcoinMainnetParams)
        assert isinstance(cur_params, BitcoinRegtestParams)

    def tearDown(self) -> None:
        select_chain_params(self.current_params)


class Test_BIP341_standard_vectors(unittest.TestCase):
    def setUp(self) -> None:
        with open(os.path.dirname(__file__) + '/data/bip341-wallet-test-vectors.json', 'r') as fd:
            data = json.load(fd)
            assert data['version'] == 1

            self.spk_cases = data['scriptPubKey']
            self.keypath_spending_cases = data['keyPathSpending']

    def test_bip341_scriptPubKey(self) -> None:
        for tcase in self.spk_cases:
            given = tcase['given']
            intermediary = tcase['intermediary']
            expected = tcase['expected']
            int_pub = XOnlyPubKey(x(given['internalPubkey']))
            stree_data = given['scriptTree']
            scripts = {}
            stree = None

            if stree_data:
                if isinstance(stree_data, dict):
                    stree_data = [stree_data]

                assert isinstance(stree_data, list)

                def process_leaves(leaves_data: List[Any]
                                   ) -> List[TaprootScriptTreeLeaf_Type]:
                    leaves = []
                    for ld in leaves_data:
                        leaf: TaprootScriptTreeLeaf_Type
                        if isinstance(ld, dict):
                            sname = f'id_{ld["id"]}'
                            leaf = CScript(x(ld['script']), name=sname)
                            scripts[sname] = leaf
                            if ld["leafVersion"] != CoreCoinParams.TAPROOT_LEAF_TAPSCRIPT:
                                leaf = TaprootScriptTree(
                                    [leaf], leaf_version=ld["leafVersion"])
                        else:
                            assert isinstance(ld, list)
                            leaf = TaprootScriptTree(process_leaves(ld))

                        leaves.append(leaf)

                    return leaves

                stree = TaprootScriptTree(process_leaves(stree_data),
                                          internal_pubkey=int_pub)
                merkle_root = stree.merkle_root
                adr = P2TRCoinAddress.from_script_tree(stree)
            else:
                merkle_root = b''
                adr = P2TRCoinAddress.from_pubkey(int_pub)

            if intermediary['merkleRoot']:
                self.assertEqual(merkle_root.hex(), intermediary['merkleRoot'])

            tweak = compute_tap_tweak_hash(int_pub, merkle_root=merkle_root)

            self.assertEqual(tweak.hex(), intermediary['tweak'])
            self.assertEqual(adr.hex(), intermediary['tweakedPubkey'])

            spk = adr.to_scriptPubKey()

            self.assertEqual(str(adr), expected['bip350Address'])
            self.assertEqual(b2x(spk), expected['scriptPubKey'])

            cblocks = expected.get('scriptPathControlBlocks', [])

            for s_id, expected_cb in enumerate(cblocks):
                sname = f'id_{s_id}'
                assert stree is not None
                swcb = stree.get_script_with_control_block(sname)
                assert swcb is not None
                s, cb = swcb
                assert s == scripts[sname]
                self.assertEqual(b2x(cb), expected_cb)

    def test_bip341_keyPathSpending(self) -> None:
        for tcase in self.keypath_spending_cases:
            tx = CMutableTransaction.deserialize(
                x(tcase['given']['rawUnsignedTx']))
            spent_outputs = [CTxOut(u['amountSats'],
                                    CScript(x(u['scriptPubKey'])))
                             for u in tcase['given']['utxosSpent']]

            signed_inputs = set()
            for inp_tcase in tcase['inputSpending']:
                given = inp_tcase['given']
                intermediary = inp_tcase['intermediary']
                expected = inp_tcase['expected']
                in_idx = given['txinIndex']
                signed_inputs.add(in_idx)
                k = CCoinKey.from_secret_bytes(x(given['internalPrivkey']))

                self.assertEqual(k.xonly_pub.hex(),
                                 intermediary['internalPubkey'])

                ht = None
                if given['hashType']:
                    ht = SIGHASH_Type(given['hashType'])

                if given['merkleRoot']:
                    mr = x(given['merkleRoot'])
                else:
                    mr = b''

                tweak = compute_tap_tweak_hash(k.xonly_pub, merkle_root=mr)
                self.assertEqual(tweak.hex(), intermediary['tweak'])

                # No check for intermediary['tweakedPrivkey'],
                # we would need to do secp256k1_keypair_* stuff here for that

                sh = SignatureHashSchnorr(tx, in_idx, spent_outputs,
                                          hashtype=ht)

                # No check for intermediary['sigMsg'],
                # we would need to adjust SignatureHashSchnorr to return
                # non-hashed data for this

                self.assertEqual(sh.hex(), intermediary['sigHash'])

                sig = k.sign_schnorr_tweaked(sh, merkle_root=mr)
                if ht:
                    wstack = [(sig + bytes([ht]))]
                else:
                    wstack = [sig]

                self.assertEqual([elt.hex() for elt in wstack],
                                 expected['witness'])

                tx.wit.vtxinwit[in_idx] = CMutableTxInWitness(CScriptWitness(wstack))

            signed_tx = CTransaction.deserialize(
                x(tcase['auxiliary']['fullySignedTx']))

            for in_idx, inp in enumerate(signed_tx.vin):
                if in_idx not in signed_inputs:
                    tx.vin[in_idx].scriptSig = inp.scriptSig
                    tx.wit.vtxinwit[in_idx] = signed_tx.wit.vtxinwit[in_idx].to_mutable()

            self.assertEqual(tx.serialize().hex(),
                             tcase['auxiliary']['fullySignedTx'])
