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

import os
import csv
import unittest
import warnings
import hashlib

from bitcointx.core.key import CKey, CPubKey, XOnlyPubKey
from bitcointx.core import x
from bitcointx.core.secp256k1 import get_secp256k1


class Test_CPubKey(unittest.TestCase):
    def test(self) -> None:
        def T(hex_pubkey: str,
              is_nonempty: bool, is_fullyvalid: bool, is_compressed: bool
              ) -> None:
            key = CPubKey(x(hex_pubkey))
            self.assertEqual(key.is_nonempty(), is_nonempty)
            self.assertEqual(key.is_fullyvalid(), is_fullyvalid)
            self.assertEqual(key.is_compressed(), is_compressed)

        T('', False, False, False)
        T('00', True, False, False)  # Note: deemed valid by OpenSSL for some reason
        T('01', True, False, False)
        T('02', True, False, False)

        T('0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71',
          True, True, True)
        T('0478d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71',
          True, False, True)

        T('0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71',
          True, True, True)

        T('0478d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71a1518063243acd4dfe96b66e3f2ec8013c8e072cd09b3834a19f81f659cc3455',
          True, True, False)


class Test_CKey(unittest.TestCase):
    def test(self) -> None:
        data = x('5586e3531b857c5a3d7af6d512ec84161f4531b66daf2ad72a6f647e4164c8ae')
        k = CKey(data)
        self.assertEqual(k, data)
        expected_pub = x('0392aef1ad6db10a2da4aa9f9e874fa28d5423eaa29ee83aa9acec01cc812903df')
        self.assertEqual(k.pub, expected_pub)
        expected_uncompressed_pub = x('0492aef1ad6db10a2da4aa9f9e874fa28d5423eaa29ee83aa9acec01cc812903df4c9b555eb62f0bf6dc4406b271365768737733ec8af4024809348ea594eef1f3')
        k = CKey(data, compressed=False)
        self.assertEqual(k.pub, expected_uncompressed_pub)

    def test_ECDH(self) -> None:
        sk1 = CKey(x('5586e3531b857c5a3d7af6d512ec84161f4531b66daf2ad72a6f647e4164c8ae'))
        sk2 = CKey(x('9e77dd4f6693461578e32e60e9c095023e1fc98ae3eaf0c53f645d53a5ead91e'))
        pk1 = sk1.pub
        pk2 = sk2.pub
        shared1 = sk1.ECDH(pk2)
        shared2 = sk2.ECDH(pk1)
        self.assertEqual(shared1, shared2)

    def test_add_sub(self) -> None:
        k1 = CKey(x('5586e3531b857c5a3d7af6d512ec84161f4531b66daf2ad72a6f647e4164c8ae'))
        k2 = CKey(x('9e77dd4f6693461578e32e60e9c095023e1fc98ae3eaf0c53f645d53a5ead91e'))
        k_sum = CKey.add(k1, k2)
        pub_sum = CPubKey.add(k1.pub, k2.pub)
        self.assertEqual(pub_sum, k_sum.pub)
        secp256k1 = get_secp256k1()
        if secp256k1.cap.has_pubkey_negate:
            k_diff = CKey.sub(k1, k2)
            pub_diff = CPubKey.sub(k1.pub, k2.pub)
            self.assertEqual(pub_diff, k_diff.pub)
            self.assertEqual(k1, CKey.sub(k_sum, k2))
            self.assertEqual(k2, CKey.sub(k_sum, k1))
            self.assertEqual(k1, CKey.add(k_diff, k2))
            self.assertEqual(k2.negated(), CKey.sub(k_diff, k1))
            self.assertEqual(CKey.add(k2, k2), CKey.sub(k_sum, k_diff))
            self.assertEqual(k1.pub, CPubKey.sub(pub_sum, k2.pub))
            self.assertEqual(k2.pub, CPubKey.sub(pub_sum, k1.pub))
            self.assertEqual(k1.pub, CPubKey.add(pub_diff, k2.pub))
            self.assertEqual(k2.pub.negated(), CPubKey.sub(pub_diff, k1.pub))
            self.assertEqual(CPubKey.add(k2.pub, k2.pub),
                             CPubKey.sub(pub_sum, pub_diff))
            self.assertEqual(k1,
                             CKey.combine(k1, k2, k_sum,
                                          k2.negated(), k_sum.negated()))
            self.assertEqual(k1.pub,
                             CPubKey.combine(k1.pub, k2.pub, k_sum.pub,
                                             k2.pub.negated(),
                                             k_sum.pub.negated()))
            self.assertEqual(CKey.combine(k_sum, k2, k1, k_diff),
                             CKey.combine(k1, k2, k_sum, k_diff))
            self.assertEqual(CPubKey.combine(k_sum.pub, k2.pub, k1.pub,
                                             k_diff.pub),
                             CPubKey.combine(k1.pub, k2.pub, k_sum.pub,
                                             k_diff.pub))
            with self.assertRaises(ValueError):
                CKey.sub(k1, k1)
            with self.assertRaises(ValueError):
                CKey.combine(k1, k2, k1.negated(), k2.negated())
            with self.assertRaises(ValueError):
                CPubKey.sub(k1.pub, k1.pub)
            with self.assertRaises(ValueError):
                CPubKey.combine(k1.pub, k2.pub,
                                k1.pub.negated(), k2.pub.negated())
        else:
            warnings.warn('secp256k1 does not export pubkey negation function. '
                          'You should use newer version of secp256k1 library. '
                          'Tests that involve key substraction are skipped')

    def test_invalid_key(self) -> None:
        with self.assertRaises(ValueError):
            CKey(b'\x00'*32)

        with self.assertRaises(ValueError):
            CKey(b'\xff'*32)

    def test_signature_grind(self) -> None:
        k = CKey(x('12b004fff7f4b69ef8650e767f18f11ede158148b425660723b9f9a66e61f747'))

        msg = "A message to be signed"
        msg_hash = hashlib.sha256(msg.encode('ascii')).digest()

        # When explicit entropy is specified, we should see at least one
        # high R signature within 20 signatures
        high_r_found = False
        for i in range(1, 21):
            sig = k.sign(msg_hash,
                         _ecdsa_sig_grind_low_r=False,
                         _ecdsa_sig_extra_entropy=i)
            if sig[3] == 0x21:
                self.assertEqual(sig[4], 0x00)
                high_r_found = True
                break

        self.assertTrue(high_r_found)

        # When grinding for low-R, we should always see low R signatures
        # that are less than 70 bytes in 256 tries
        # We should see at least one signature that is less than 70 bytes.
        small_sig_found = False
        for i in range(256):
            msg = "A message to be signed" + str(i)
            msg_hash = hashlib.sha256(msg.encode('ascii')).digest()
            sig = k.sign(msg_hash)

            self.assertLessEqual(len(sig), 70)
            self.assertLessEqual(sig[3], 0x20)

            if len(sig) < 70:
                small_sig_found = True

        self.assertTrue(small_sig_found)

    def test_schnorr(self) -> None:
        # adapted from reference code of BIP340
        # at https://github.com/bitcoin/bips/blob/master/bip-0340/reference.py
        with open(os.path.dirname(__file__) + '/data/schnorr-sig-test-vectors.csv', 'r') as fd:
            reader = csv.reader(fd)
            reader.__next__()
            for row in reader:
                (
                    _testcase_idx,
                    seckey_hex, pubkey_hex, aux_rand_hex, msg_hex, sig_hex,
                    result_str, _comment
                ) = row

                pubkey = XOnlyPubKey(x(pubkey_hex))
                msg = x(msg_hex)
                assert len(msg) == 32
                sig = x(sig_hex)
                result = (result_str == 'TRUE')

                if seckey_hex != '':
                    seckey = CKey(x(seckey_hex))
                    pubkey_actual = seckey.xonly_pub
                    self.assertEqual(pubkey, pubkey_actual)
                    aux_rand = x(aux_rand_hex)
                    sig_actual = seckey.sign_schnorr_no_tweak(
                        msg, aux=aux_rand)
                    self.assertEqual(sig, sig_actual)
                if pubkey.is_fullyvalid():
                    result_actual = pubkey.verify_schnorr(msg, sig)
                else:
                    result_actual = False

                self.assertEqual(result, result_actual)
