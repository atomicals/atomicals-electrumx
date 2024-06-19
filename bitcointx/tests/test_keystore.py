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

# pylama:ignore=E501

import unittest

from bitcointx.core import x
from bitcointx.core.key import (
    CPubKey, KeyStore, BIP32Path, BIP32PathTemplate, KeyDerivationInfo,
    BIP32PathTemplateViolation
)
from bitcointx.wallet import CCoinKey, CCoinExtKey, CCoinExtPubKey


class Test_KeyStore(unittest.TestCase):
    def test(self) -> None:
        xpriv1 = CCoinExtKey('xprv9s21ZrQH143K4TFwadu5VoGfAChTWXUw49YyTWE8SRqC9ZC9AQpHspzgbAcScTmC4MURiMT7pmCbci5oKbWijJmARiUeRiLXYehCtsoVdYf')
        xpriv2 = CCoinExtKey('xprv9uZ4jKNZFfGEQTTunEuy2cLQMckzuy5saCmiKuxYJgHX5pGFCx3KQ8mTkSfuLNaWGNQ9LKCg5YzUihxoQv493ErnkcaS3q1udx9X8WZbwZc')
        priv1 = CCoinKey('L27zAtDgjDC34sG5ZSey1wvdZ9JyZsNnvZEwbbZYWUYXXQtgri5R')
        xpub1 = CCoinExtPubKey('xpub69b6hm71WMe1PGpgUmaDPkbxYoTzpmswX8KGeinv7SPRcKT22RdMM4416kqtEUuXqXCAi7oGx7tHwCRTd3JHatE3WX1Zms6Lgj5mrbFyuro')
        xpub1.assign_derivation_info(KeyDerivationInfo(xpub1.parent_fp, BIP32Path('m/0')))
        pub1 = CPubKey(x('03b0fe9cfc88fed9fcecf9dcb7bb5c90dd1a4500f4cfc5c854ffc8e54d639d6bc5'))

        kstore = KeyStore(
            external_privkey_lookup=(
                lambda key_id, dinfo: priv1 if key_id == priv1.pub.key_id
                else None),
            external_pubkey_lookup=(
                lambda key_id, dinfo: pub1 if key_id == pub1.key_id
                else None)
        )
        self.assertEqual(kstore.get_privkey(priv1.pub.key_id), priv1)
        self.assertEqual(kstore.get_pubkey(pub1.key_id), pub1)
        self.assertEqual(kstore.get_pubkey(priv1.pub.key_id), priv1.pub)

        kstore = KeyStore(xpriv1, priv1, xpub1, pub1,
                          require_path_templates=False)
        self.assertEqual(kstore.get_privkey(priv1.pub.key_id), priv1)
        self.assertEqual(kstore.get_pubkey(priv1.pub.key_id), priv1.pub)
        self.assertEqual(kstore.get_pubkey(pub1.key_id), pub1)

        # check that no-derivation lookup for (priv, pub) of extended keys
        # does not return anything if derivation is not supplied,
        # but returns pubkey when empty path is supplied
        self.assertEqual(kstore.get_privkey(xpriv1.pub.key_id), None)
        self.assertEqual(
            kstore.get_privkey(xpriv1.pub.key_id,
                               KeyDerivationInfo(xpriv1.fingerprint,
                                                 BIP32Path("m"))),
            xpriv1.priv)
        self.assertEqual(kstore.get_pubkey(xpriv1.pub.key_id), None)
        self.assertEqual(
            kstore.get_pubkey(xpriv1.pub.key_id,
                              KeyDerivationInfo(xpriv1.fingerprint,
                                                BIP32Path("m"))),
            xpriv1.pub)

        # can't find xpub1's pub without derivation
        self.assertEqual(kstore.get_pubkey(xpub1.pub.key_id), None)

        # can find with correct derivation info supplied
        self.assertEqual(
            kstore.get_pubkey(xpub1.pub.key_id,
                              KeyDerivationInfo(xpub1.parent_fp,
                                                BIP32Path("m/0"))),
            xpub1.pub)

        # but not with incorrect derivation info
        self.assertEqual(
            kstore.get_pubkey(xpub1.pub.key_id,
                              KeyDerivationInfo(xpub1.parent_fp,
                                                BIP32Path("m"))),
            None)

        # check longer derivations
        self.assertEqual(
            kstore.get_privkey(xpriv1.derive_path("0'/1'/2'").pub.key_id),
            None)
        self.assertEqual(
            kstore.get_privkey(xpriv1.derive_path("0'/1'/2'").pub.key_id,
                               KeyDerivationInfo(xpriv1.fingerprint,
                                                 BIP32Path("m/0'/1'/2'"))),
            xpriv1.derive_path("0'/1'/2'").priv)
        self.assertEqual(
            kstore.get_pubkey(xpriv1.derive_path("0'/1'/2'").pub.key_id,
                              KeyDerivationInfo(xpriv1.fingerprint,
                                                BIP32Path("m/0'/1'/2'"))),
            xpriv1.derive_path("0'/1'/2'").pub)

        self.assertEqual(
            kstore.get_pubkey(xpub1.derive_path("0/1/2").pub.key_id,
                              KeyDerivationInfo(xpub1.parent_fp,
                                                BIP32Path('m/0/0/1/2'))),
            xpub1.derive_path("0/1/2").pub)

        path = BIP32Path("0'/1'/2'")
        derived_xpub = xpriv2.derive_path(path).neuter()
        derived_pub = derived_xpub.derive_path('3/4/5').pub
        self.assertEqual(kstore.get_pubkey(derived_pub.key_id), None)
        kstore.add_key(derived_xpub)
        self.assertEqual(
            kstore.get_pubkey(
                derived_pub.key_id,
                KeyDerivationInfo(xpriv2.parent_fp, BIP32Path("m/0/0'/1'/2'/3/4/5"))),
            derived_pub)

        kstore.add_key(xpriv2)

        derived_pub = xpriv2.derive_path('3h/4h/5h').pub
        self.assertEqual(
            kstore.get_pubkey(
                derived_pub.key_id,
                KeyDerivationInfo(xpriv2.parent_fp,
                                  BIP32Path("m/0/3'/4'/5'"))),
            derived_pub)

        derived_priv = xpriv2.derive_path('3h/4h/5h').priv
        self.assertEqual(
            kstore.get_privkey(
                derived_priv.pub.key_id,
                KeyDerivationInfo(xpriv2.parent_fp,
                                  BIP32Path("m/0/3'/4'/5'"))),
            derived_priv)

        # check that .remove_key() works
        kstore.remove_key(xpriv1)
        kstore.remove_key(xpub1)
        kstore.remove_key(priv1)
        kstore.remove_key(pub1)

        self.assertEqual(kstore.get_privkey(priv1.pub.key_id), None)
        self.assertEqual(kstore.get_pubkey(pub1.key_id), None)
        self.assertEqual(
            kstore.get_privkey(xpriv1.derive_path("0'/1'/2'").pub.key_id,
                               KeyDerivationInfo(xpriv1.fingerprint,
                                                 BIP32Path("m/0'/1'/2'"))),
            None)
        self.assertEqual(
            kstore.get_pubkey(xpub1.derive_path("0/1/2").pub.key_id),
            None)

    def test_path_template_enforcement(self) -> None:
        xpriv1 = CCoinExtKey('xprv9s21ZrQH143K4TFwadu5VoGfAChTWXUw49YyTWE8SRqC9ZC9AQpHspzgbAcScTmC4MURiMT7pmCbci5oKbWijJmARiUeRiLXYehCtsoVdYf')
        xpriv2 = CCoinExtKey('xprv9s21ZrQH143K3QgBvK4tkeHuvuWc6KETTTcgGQ4NmW7g16AtCPV4hZpujiimpLM9ivFPgsMdNNVuVUnDwChutxczNKYHzP1Mo5HuqG7CNYv')
        assert xpriv2.derivation_info
        assert len(xpriv2.derivation_info.path) == 0
        priv1 = CCoinKey('L27zAtDgjDC34sG5ZSey1wvdZ9JyZsNnvZEwbbZYWUYXXQtgri5R')
        xpub1 = CCoinExtPubKey('xpub69b6hm71WMe1PGpgUmaDPkbxYoTzpmswX8KGeinv7SPRcKT22RdMM4416kqtEUuXqXCAi7oGx7tHwCRTd3JHatE3WX1Zms6Lgj5mrbFyuro')
        xpub2 = xpriv2.derive(333).neuter()
        xpub1.assign_derivation_info(KeyDerivationInfo(xpub1.parent_fp, BIP32Path('m/0')))
        pub1 = CPubKey(x('03b0fe9cfc88fed9fcecf9dcb7bb5c90dd1a4500f4cfc5c854ffc8e54d639d6bc5'))

        xpub3 = xpub1.derive(0)
        xpub3.assign_derivation_info(KeyDerivationInfo(x('abcdef10'),
                                                       BIP32Path('m/0/0')))

        # No error when require_path_templates is not set
        KeyStore(xpriv1, xpriv2, priv1, xpub1, pub1,
                 require_path_templates=False)

        with self.assertRaisesRegex(ValueError, 'only make sense for extended keys'):
            KeyStore((priv1, BIP32PathTemplate('')))  # type: ignore
        with self.assertRaisesRegex(ValueError, 'only make sense for extended keys'):
            KeyStore((pub1, [BIP32PathTemplate('')]))  # type: ignore
        with self.assertRaisesRegex(ValueError, 'path templates must be specified'):
            KeyStore(xpriv1)
        with self.assertRaisesRegex(ValueError, 'path templates must be specified'):
            KeyStore(xpub1)

        # same but via add_key
        ks = KeyStore()
        with self.assertRaisesRegex(ValueError, 'only make sense for extended keys'):
            ks.add_key((priv1, BIP32PathTemplate('')))  # type: ignore
        with self.assertRaisesRegex(ValueError, 'only make sense for extended keys'):
            ks.add_key((pub1, [BIP32PathTemplate('')]))  # type: ignore
        with self.assertRaisesRegex(ValueError, 'path templates list is empty'):
            ks.add_key((pub1, []))  # type: ignore
        with self.assertRaisesRegex(ValueError, 'only make sense for extended keys'):
            ks.add_key((pub1, ''))  # type: ignore
        with self.assertRaisesRegex(ValueError, 'index template format is not valid'):
            ks.add_key((xpub1, 'abc'))
        with self.assertRaisesRegex(TypeError, 'is expected to be an instance of '):
            ks.add_key((xpub1, [10]))  # type: ignore
        with self.assertRaisesRegex(ValueError, 'path templates must be specified'):
            ks.add_key(xpriv1)
        with self.assertRaisesRegex(ValueError, 'path templates must be specified'):
            ks.add_key(xpub1)

        # No error when path templates are specified for extended keys
        ks = KeyStore((xpriv1, BIP32PathTemplate('m')),
                      (xpriv2, 'm/{44,49,84}h/0h/0h/{0-1}/*'),
                      (xpub1, ''),  # '' same as BIP32PathTemplate('')
                      (xpub2, ['0/1', 'm/333/3/33']),
                      (xpub3, BIP32PathTemplate('m/0/0/1')),
                      priv1, pub1)

        self.assertEqual(ks.get_privkey(priv1.pub.key_id), priv1)
        self.assertEqual(ks.get_pubkey(pub1.key_id), pub1)

        # still can find non-extended priv even if derivation info is
        # specified, because there's exact match.
        self.assertEqual(
            ks.get_privkey(priv1.pub.key_id,
                           KeyDerivationInfo(xpriv1.parent_fp, BIP32Path("m"))),
            priv1)
        self.assertEqual(ks.get_pubkey(pub1.key_id), pub1)

        # can't find without derivation specified
        self.assertEqual(ks.get_privkey(xpriv1.pub.key_id), None)
        # but can find with derivation specified
        self.assertEqual(
            ks.get_privkey(xpriv1.pub.key_id,
                           KeyDerivationInfo(xpriv1.fingerprint, BIP32Path('m'))),
            xpriv1.priv)

        # can't find without derivation specified
        self.assertEqual(ks.get_pubkey(xpub1.pub.key_id), None)

        # can find with derivation specified
        self.assertEqual(
            ks.get_pubkey(xpub1.pub.key_id,
                          KeyDerivationInfo(xpub1.parent_fp, BIP32Path('m/0'))),
            xpub1.pub)

        # exception when derivation goes beyond template
        with self.assertRaises(BIP32PathTemplateViolation):
            ks.get_pubkey(xpub1.derive(1).pub.key_id,
                          KeyDerivationInfo(xpub1.parent_fp, BIP32Path('m/0/1')))

        # success when template allows
        self.assertEqual(
            ks.get_pubkey(xpub3.derive(1).pub.key_id,
                          KeyDerivationInfo(x('abcdef10'), BIP32Path('m/0/0/1'))),
            xpub3.derive(1).pub)

        # fails when template not allows
        with self.assertRaises(BIP32PathTemplateViolation):
            ks.get_pubkey(xpub3.derive(2).pub.key_id,
                          KeyDerivationInfo(x('abcdef10'), BIP32Path('m/0/0/2')))

        long_path = BIP32Path(
            "m/43435/646/5677/5892/58885/2774/9943/75532/8888")

        with self.assertRaises(BIP32PathTemplateViolation):
            ks.get_privkey(xpriv2.derive_path(long_path).pub.key_id,
                           KeyDerivationInfo(xpriv2.fingerprint, long_path))

        with self.assertRaises(BIP32PathTemplateViolation):
            ks.get_privkey(xpriv2.derive_path("44'/0'/0'/3/25").pub.key_id,
                           KeyDerivationInfo(xpriv2.fingerprint,
                                             BIP32Path('m/44h/0h/0h/3/25')))

        with self.assertRaises(BIP32PathTemplateViolation):
            ks.get_privkey(xpriv2.derive_path("44'/0'/0'/0/1'").pub.key_id,
                           KeyDerivationInfo(xpriv2.fingerprint,
                                             BIP32Path('m/44h/0h/0h/0/1h')))

        self.assertEqual(
            ks.get_privkey(xpriv2.derive_path("44'/0'/0'/1/25").pub.key_id,
                           KeyDerivationInfo(xpriv2.fingerprint,
                                             BIP32Path('m/44h/0h/0h/1/25'))),
            xpriv2.derive_path("44'/0'/0'/1/25").priv
        )

        with self.assertRaises(BIP32PathTemplateViolation):
            ks.get_pubkey(xpub2.derive_path('0').pub.key_id,
                          KeyDerivationInfo(xpub2.parent_fp,
                                            BIP32Path('m/333/0')))

        with self.assertRaises(BIP32PathTemplateViolation):
            ks.get_pubkey(xpub2.derive_path('3/34').pub.key_id,
                          KeyDerivationInfo(xpub2.parent_fp,
                                            BIP32Path('m/333/3/34')))

        self.assertEqual(
            ks.get_pubkey(xpub2.derive_path('3/33').pub.key_id,
                          KeyDerivationInfo(xpub2.parent_fp,
                                            BIP32Path('m/333/3/33'))),
            xpub2.derive_path('3/33').pub
        )

        xpub49 = xpriv2.derive_path("m/49'/0'/0'/0").neuter()

        with self.assertRaisesRegex(ValueError, 'must specify full path'):
            ks = KeyStore(xpriv2, xpub49,
                          default_path_template='{44,49,84}h/0h/0h/{0-1}/{0-50000}')

        ks = KeyStore(xpriv2, xpub49,
                      default_path_template='m/{44,49,84}h/0h/0h/{0-1}/{0-50000}')

        with self.assertRaises(BIP32PathTemplateViolation):
            ks.get_privkey(xpriv2.derive_path(long_path).pub.key_id,
                           KeyDerivationInfo(xpriv2.fingerprint, long_path))

        with self.assertRaises(BIP32PathTemplateViolation):
            ks.get_privkey(xpriv2.derive_path("44'/0'/0'/1/50001").pub.key_id,
                           KeyDerivationInfo(xpriv2.fingerprint,
                                             BIP32Path('m/44h/0h/0h/1/50001')))

        self.assertEqual(
            ks.get_privkey(xpriv2.derive_path("44'/0'/0'/1/25").pub.key_id,
                           KeyDerivationInfo(xpriv2.fingerprint,
                                             BIP32Path('m/44h/0h/0h/1/25'))),
            xpriv2.derive_path("44'/0'/0'/1/25").priv
        )

        with self.assertRaises(BIP32PathTemplateViolation):
            ks.get_pubkey(xpub49.derive_path('50001').pub.key_id,
                          KeyDerivationInfo(xpriv2.fingerprint,
                                            BIP32Path('m/49h/0h/0h/0/50001')))

        with self.assertRaises(BIP32PathTemplateViolation):
            ks.get_pubkey(xpub49.derive_path('50000/3').pub.key_id,
                          KeyDerivationInfo(xpriv2.fingerprint,
                                            BIP32Path('m/49h/0h/0h/0/50000/3')))

        self.assertEqual(
            ks.get_pubkey(xpub49.derive_path('50000').pub.key_id,
                          KeyDerivationInfo(xpriv2.fingerprint,
                                            BIP32Path('m/49h/0h/0h/0/50000'))),
            xpub49.derive_path('50000').pub
        )
