# Copyright (C) 2018 The python-bitcointx developers
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
import unittest

from typing import List, Tuple, Dict, Union

from bitcointx.core import b2x, x
from bitcointx.base58 import Base58Error
from bitcointx.core.key import (
    CExtKey, CExtPubKey, BIP32Path, BIP32PathTemplate,
    BIP32_HARDENED_KEY_OFFSET
)
from bitcointx.wallet import CBitcoinExtKey, CBitcoinExtPubKey


BIP32_TEST_VECTORS: List[List[Tuple[str, str, int]]] = [
    [
        ("vector1", "000102030405060708090a0b0c0d0e0f", 0),
        ("xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
         "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
         0x80000000),
        ("xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
         "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
         1),
        ("xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
         "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
         0x80000002),
        ("xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
         "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
         2),
        ("xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
         "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
         1000000000),
        ("xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
         "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
         0)
    ],
    [
        ("vector2", "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542", 0),
        ("xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
         "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
         0),
        ("xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
         "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
         0xFFFFFFFF),
        ("xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a",
         "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9",
         1),
        ("xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon",
         "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef",
         0xFFFFFFFE),
        ("xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL",
         "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc",
         2),
        ("xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt",
         "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j",
         0)
    ],
    [
        ("vector3", "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be", 0),
        ("xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13",
         "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6",
         0x80000000),
        ("xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y",
         "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L",
         0)
    ],
    [
        ("vector4", "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678", 0),
        ("xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa",
         "xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv",
         0x80000000),
        ("xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m",
         "xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G",
         0x80000001),
        ("xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt",
         "xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1",
         0)
    ]
]

BIP32_TEST_VECTOR_INVALIDXKEYS = [
    ("xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6LBpB85b3D2yc8sfvZU521AAwdZafEz7mnzBBsz4wKY5fTtTQBm", "(pubkey version / prvkey mismatch)",
     Base58Error),
    ("xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGTQQD3dC4H2D5GBj7vWvSQaaBv5cxi9gafk7NF3pnBju6dwKvH", "(prvkey version / pubkey mismatch)",
     ValueError),
    ("xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Txnt3siSujt9RCVYsx4qHZGc62TG4McvMGcAUjeuwZdduYEvFn", "(invalid pubkey prefix 04)",
     Base58Error),
    ("xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGpWnsj83BHtEy5Zt8CcDr1UiRXuWCmTQLxEK9vbz5gPstX92JQ", "(invalid prvkey prefix 04)",
     ValueError),
    ("xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6N8ZMMXctdiCjxTNq964yKkwrkBJJwpzZS4HS2fxvyYUA4q2Xe4", "(invalid pubkey prefix 01)",
     Base58Error),
    ("xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD9y5gkZ6Eq3Rjuahrv17fEQ3Qen6J", "(invalid prvkey prefix 01)",
     ValueError),
    ("xprv9s2SPatNQ9Vc6GTbVMFPFo7jsaZySyzk7L8n2uqKXJen3KUmvQNTuLh3fhZMBoG3G4ZW1N2kZuHEPY53qmbZzCHshoQnNf4GvELZfqTUrcv", "(zero depth with non-zero parent fingerprint)",
     ValueError),
    ("xpub661no6RGEX3uJkY4bNnPcw4URcQTrSibUZ4NqJEw5eBkv7ovTwgiT91XX27VbEXGENhYRCf7hyEbWrR3FewATdCEebj6znwMfQkhRYHRLpJ", "(zero depth with non-zero parent fingerprint)",
     Base58Error),
    ("xprv9s21ZrQH4r4TsiLvyLXqM9P7k1K3EYhA1kkD6xuquB5i39AU8KF42acDyL3qsDbU9NmZn6MsGSUYZEsuoePmjzsB3eFKSUEh3Gu1N3cqVUN", "(zero depth with non-zero index)",
     ValueError),
    ("xpub661MyMwAuDcm6CRQ5N4qiHKrJ39Xe1R1NyfouMKTTWcguwVcfrZJaNvhpebzGerh7gucBvzEQWRugZDuDXjNDRmXzSZe4c7mnTK97pTvGS8", "(zero depth with non-zero index)",
     Base58Error),
    ("DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHGMQzT7ayAmfo4z3gY5KfbrZWZ6St24UVf2Qgo6oujFktLHdHY4", "(unknown extended key version)",
     Base58Error),
    ("DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHPmHJiEDXkTiJTVV9rHEBUem2mwVbbNfvT2MTcAqj3nesx8uBf9", "(unknown extended key version)",
     Base58Error),
    ("xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF93Y5wvzdUayhgkkFoicQZcP3y52uPPxFnfoLZB21Teqt1VvEHx", "(private key 0 not in 1..n-1)",
     ValueError),
    ("xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD5SDKr24z3aiUvKr9bJpdrcLg1y3G", "(private key n not in 1..n-1)",
     ValueError),
    ("xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Q5JXayek4PRsn35jii4veMimro1xefsM58PgBMrvdYre8QyULY", "(invalid pubkey 020000000000000000000000000000000000000000000000000000000000000007)",
     Base58Error),
    ("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHL", "(invalid checksum)",
     Base58Error)
]


def load_path_teplate_test_vectors(name: str) -> Dict[
    str, List[Union[str, List[str]]]
]:
    with open(os.path.dirname(__file__) + '/data/' + name, 'r') as fd:
        return json.load(fd)  # type: ignore


class Test_CBitcoinExtKey(unittest.TestCase):
    def test(self) -> None:
        def T(base58_xprivkey: str, expected_hex_xprivkey: str) -> None:
            key = CBitcoinExtKey(base58_xprivkey)
            self.assertEqual(b2x(key), expected_hex_xprivkey)
            key2 = CBitcoinExtKey.from_bytes(x(expected_hex_xprivkey))
            self.assertEqual(b2x(key), b2x(key2))

        T('xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6',
          '00000000000000000001d28a3e53cffa419ec122c968b3259e16b65076495494d97cae10bbfec3c36f0000ddb80b067e0d4993197fe10f2657a844a384589847602d56f0c629c81aae32')
        T('xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9',
          '025a61ff8effffffffbe17a268474a6bb9c61e1d720cf6215e2a88c5406c4aee7b38547f585c9a37d900877c779ad9687164e9c2f4f0f4ff0340814392330693ce95a58fe18fd52e6e93')

    def test_invalid_xprivkey(self) -> None:
        invalid_xpriv_str = 'xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD9y5gkZ6Eq3Rjuahrv17fENZ3QzxW'
        with self.assertRaises(ValueError):
            CBitcoinExtKey(invalid_xpriv_str)

        valid_xprivkey = CBitcoinExtKey('xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9')
        with self.assertRaises(ValueError):
            CExtKey(valid_xprivkey[:-1])  # short length

        with self.assertRaises(ValueError):
            CExtKey(valid_xprivkey + b'\x00')  # long length

    def test_from_xpriv(self) -> None:
        xpriv_str = 'xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt'
        xpriv = CBitcoinExtKey(xpriv_str)
        self.assertEqual(xpriv_str, str(CBitcoinExtKey.from_bytes(xpriv)))

    def test_invalid_derivation(self) -> None:
        xpriv = CBitcoinExtKey(
            'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi'
        )

        with self.assertRaises(ValueError):
            xpriv.derive(1 << 32)

        final_xpriv_str = 'xprvJ9DiCzes6yvKjEy8duXR1Qg6Et6CBmrR4yFJvnburXG4X6VnKbNxoTYhvVdpsxkjdXwX3D2NJHFCAnnN1DdAJCVQitnFbFWv3fL3oB2BFo4'
        for _ in range(255):
            xpriv = xpriv.derive(0)
        self.assertEqual(str(CBitcoinExtKey.from_bytes(xpriv)), final_xpriv_str)

        with self.assertRaises(ValueError):
            xpriv.derive(0)  # depth > 255

    def test_standard_bip32_vectors(self) -> None:
        for vector in BIP32_TEST_VECTORS:
            _, seed, _ = vector[0]
            base_key = CBitcoinExtKey.from_seed(x(seed))
            self.assertEqual(base_key.parent_fp, b'\x00\x00\x00\x00')
            key = base_key
            path = []
            for xpub, xpriv, child_num in vector[1:]:
                self.assertEqual(xpub, str(key.neuter()))
                self.assertEqual(xpriv, str(key))
                parent_fp = key.fingerprint
                key = key.derive(child_num)
                self.assertEqual(key.parent_fp, parent_fp)
                path.append(child_num)

            key_from_path = base_key.derive_path(str(BIP32Path(path)))
            self.assertEqual(key, key_from_path)

    def test_standard_bip32_vector_invalidxkeys(self) -> None:
        for xkey_str, descr, extype in BIP32_TEST_VECTOR_INVALIDXKEYS:
            with self.assertRaises(extype):
                CBitcoinExtKey(xkey_str)


class Test_CBitcoinExtPubKey(unittest.TestCase):
    def test(self) -> None:
        def T(base58_xpubkey: str, expected_hex_xpubkey: str) -> None:
            key = CBitcoinExtPubKey(base58_xpubkey)
            self.assertEqual(b2x(key), expected_hex_xpubkey)
            key2 = CBitcoinExtPubKey.from_bytes(x(expected_hex_xpubkey))
            self.assertEqual(b2x(key), b2x(key2))

        T('xpub661MyMwAqRbcFMfe2ZGFSPef9xMXWrZUDta7RXKPbtxuNyepg8ewAWVV5qME4omB67Ek4eDrpyFtMcUcznxCf8sV8DCnsZeWj6Z2N3RXqPo',
          '00000000000000000051cba4db213938e74101b4264be4f45a9f3a7b2c0005963331c7a0ffaa5978b903782da1cfa3f03b9ae2bfa3077296410f5f80cf92eaa2f87d738a320b8486f326')
        T('xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a',
          '025a61ff8effffffffbe17a268474a6bb9c61e1d720cf6215e2a88c5406c4aee7b38547f585c9a37d903c01e7425647bdefa82b12d9bad5e3e6865bee0502694b94ca58b666abc0a5c3b')

    def test_derive(self) -> None:
        def T(base_xpub: str, expected_child: str, path: List[int]) -> None:
            xpub = CBitcoinExtPubKey(base_xpub)
            self.assertEqual(xpub.parent_fp, b'\x00\x00\x00\x00')
            for child_num in path:
                parent_fp = xpub.fingerprint
                xpub = xpub.derive(child_num)
                self.assertEqual(xpub.parent_fp, parent_fp)

            self.assertEqual(str(CBitcoinExtPubKey.from_bytes(xpub)), expected_child)

            xpub = CBitcoinExtPubKey(base_xpub).derive_path(str(BIP32Path(path)))
            self.assertEqual(str(CBitcoinExtPubKey.from_bytes(xpub)), expected_child)

        T('xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB',
          'xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH',
          [0])

        T('xpub661MyMwAqRbcG2veuy7DxC7yfKodTbY46UKYgnrERu9WADL5pBjRzthJtxMpWYeofw5rHWtemkgJAcSCup19Vorze6H3etYGbiEU4MumRV7',
          'xpub6E6u1x8dM8qBkicTyJnnM3wYfbYSfsnRPYgNXTkD1PqF2AVasRGPckvaewHDzErwSMG9HhvcEc1QYHeGGp8pybcQr2RSXcGBs9YrcJ83NEo',
          [0, 1, 88430, 42])

    def test_invalid_xpubkey(self) -> None:
        invalid_xpub_str = 'xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Txnt3siSujt9RCVYsx4qHZGc62TG4McvMGcAUjeuwZdcaHQwzT'
        with self.assertRaises(ValueError):
            CBitcoinExtPubKey(invalid_xpub_str)

        valid_xpubkey = CBitcoinExtPubKey('xpub661MyMwAqRbcG2veuy7DxC7yfKodTbY46UKYgnrERu9WADL5pBjRzthJtxMpWYeofw5rHWtemkgJAcSCup19Vorze6H3etYGbiEU4MumRV7')
        with self.assertRaises(ValueError):
            CExtPubKey(valid_xpubkey[:-1])  # short length

        with self.assertRaises(ValueError):
            CExtPubKey(valid_xpubkey + b'\x00')  # long length

    def test_from_xpub(self) -> None:
        xpub_str = 'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB'
        xpub = CBitcoinExtPubKey(xpub_str)
        self.assertEqual(xpub_str, str(CBitcoinExtPubKey.from_bytes(xpub)))

    def test_invalid_derivation(self) -> None:
        xpub = CBitcoinExtPubKey(
            'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB'
        )

        with self.assertRaises(ValueError):
            xpub.derive(BIP32_HARDENED_KEY_OFFSET)

        final_xpub_str = 'xpubEPPCAoZp7t6CN5GGoyYTEr91FCaPpQonRouneRKmRCzgfcWNHnyHMuQPCDn8wLv1vYyPrFpSK26VeA9dDXTKMCLm7FaSY9aVTWw5mTZLC7F'
        for _ in range(255):
            xpub = xpub.derive(0)
        self.assertEqual(str(CBitcoinExtPubKey.from_bytes(xpub)), final_xpub_str)

        with self.assertRaises(ValueError):
            xpub.derive(0)  # depth > 255


class Test_CExtPubKey(unittest.TestCase):
    def test(self) -> None:
        xpub_str = 'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB'
        xpub = CBitcoinExtPubKey(xpub_str)
        xpub2 = CExtPubKey(xpub)
        self.assertEqual(xpub_str, str(CBitcoinExtPubKey.from_bytes(xpub2)))
        self.assertEqual(xpub, CBitcoinExtPubKey.from_bytes(xpub2))
        self.assertEqual(xpub.derive(0), xpub2.derive(0))


class Test_CExtKey(unittest.TestCase):
    def test_extkey(self) -> None:
        xprv_str = 'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi'
        xprv = CBitcoinExtKey(xprv_str)
        xprv2 = CExtKey(xprv)
        self.assertEqual(xprv_str, str(CBitcoinExtKey.from_bytes(xprv2)))
        self.assertEqual(bytes(xprv.derive(BIP32_HARDENED_KEY_OFFSET)),
                         bytes(xprv2.derive(BIP32_HARDENED_KEY_OFFSET)))
        self.assertEqual(str(xprv.neuter()), str(CBitcoinExtPubKey.from_bytes(xprv2.neuter())))


class Test_BIP32Path(unittest.TestCase):
    def do_common_tests(self, cls: type) -> None:
        with self.assertRaises(ValueError):
            cls('m/')  # empty path that is not 'm' or ''
        with self.assertRaises(ValueError):
            cls('/')
        with self.assertRaises(ValueError):
            cls('nonsense')
        with self.assertRaises(ValueError):
            cls('m/-1')
        with self.assertRaises(ValueError):
            cls('m/1-')
        with self.assertRaises(ValueError):
            cls('m/-')
        with self.assertRaises(ValueError):
            cls('m/,')
        with self.assertRaises(ValueError):
            cls('m/{-1,}')
        with self.assertRaises(ValueError):
            cls('m/{-1,0}')
        with self.assertRaises(ValueError):
            cls('m/1,')
        with self.assertRaises(ValueError):
            cls('m/,2')
        with self.assertRaises(ValueError):
            cls('m/{1,}')
        with self.assertRaises(ValueError):
            cls('m/{,}')
        with self.assertRaises(ValueError):
            cls('m/abc')
        with self.assertRaises(ValueError):
            cls('m/{1,}')
        with self.assertRaises(ValueError):
            cls('m/{,3}')
        with self.assertRaises(ValueError):
            cls('m/{3-}')
        with self.assertRaises(ValueError):
            cls('m/[3-5]')
        with self.assertRaises(ValueError):
            cls('m/{3-7,*}')
        with self.assertRaises(ValueError):
            cls('m/{7-3}')  # second bound less than first
        with self.assertRaises(ValueError):
            cls('m/{3-7, 23}')  # space in template
        with self.assertRaises(ValueError):
            cls('m/{*}')
        with self.assertRaises(ValueError):
            cls('m/4/')  # slash at the end of the path
        with self.assertRaises(ValueError):
            cls("m/4h/1'")  # inconsistent use of markers
        with self.assertRaises(ValueError):
            cls("m/2147483648'/1'")  # hardened index too big
        with self.assertRaises(ValueError):
            cls("m/{0-2147483648}'/1'")  # hardened index too big
        with self.assertRaises(ValueError):
            cls("m/2147483648/1")  # non-hardened index too big
        with self.assertRaises(ValueError):
            cls("m/{1-2147483648}/1")  # non-hardened index too big
        with self.assertRaises(ValueError):
            # wrong markers
            cls("m/2147483647'/1'/0", hardened_marker='h')
        with self.assertRaises(ValueError):
            # wrong markers
            cls("m/2147483647h/1h/0", hardened_marker="'")
        with self.assertRaises(ValueError):
            # invalid marker
            cls("m/2147483647h/1h/0", hardened_marker="?")
        with self.assertRaises(ValueError):
            # too long path
            cls('m/'+'/'.join('0' for _ in range(256)))
        with self.assertRaises(ValueError):
            # non-partial with is_partial=True
            cls('m/0', is_partial=True)
        with self.assertRaises(ValueError):
            # partial with is_partial=False
            cls('0', is_partial=False)
        with self.assertRaises(ValueError):
            # partial with is_partial=False
            cls(cls('0'), is_partial=False)
        with self.assertRaises(ValueError):
            # non-partial with is_partial=True
            cls(cls('m/0'), is_partial=True)

        # check that markers correctly picked up from the string
        self.assertEqual(str(cls("m/4h/5h/1/4")), "m/4h/5h/1/4")
        self.assertEqual(str(cls("m/4'/5'/1/4")), "m/4'/5'/1/4")

        self.assertTrue(cls('').is_partial())
        self.assertFalse(cls('m').is_partial())
        self.assertTrue(cls('0/1/2').is_partial())
        self.assertFalse(cls('m/0/1/2').is_partial())

        self.assertEqual(list(cls('m')), [])
        self.assertEqual(list(cls('')), [])

    def test_from_string(self) -> None:
        self.do_common_tests(BIP32Path)
        self.do_common_tests(BIP32PathTemplate)

    def test_path_as_list(self) -> None:
        self.assertEqual(list(BIP32Path('m/0')), [0])
        self.assertEqual(list(BIP32Path('0')), [0])

        self.assertEqual(list(BIP32Path("m/4h/5/1h")),
                         [4+BIP32_HARDENED_KEY_OFFSET, 5,
                          1+BIP32_HARDENED_KEY_OFFSET])

        self.assertEqual(list(BIP32Path("m/0'/2147483647'/1/10")),
                         [BIP32_HARDENED_KEY_OFFSET, 0xFFFFFFFF, 1, 10])

        self.assertEqual(
            list(BIP32Path(
                'm/'+'/'.join("%u'" % n for n in range(128))
                + '/' + '/'.join("%u" % (BIP32_HARDENED_KEY_OFFSET-n-1)
                                 for n in range(127)))),
            [n+BIP32_HARDENED_KEY_OFFSET for n in range(128)]
            + [BIP32_HARDENED_KEY_OFFSET-n-1 for n in range(127)])

    def test_tempate_as_list(self) -> None:
        self.assertEqual(list(BIP32PathTemplate('m/0')), [((0, 0),)])
        self.assertEqual(list(BIP32PathTemplate('0')), [((0, 0),)])
        self.assertEqual(list(BIP32PathTemplate('{0-10,12,59}/*')),
                         [((0, 10), (12, 12), (59, 59)),
                          ((0, BIP32_HARDENED_KEY_OFFSET-1),)])

        self.assertEqual(
            list(BIP32PathTemplate("m/4h/{5-10,15}/1h")),
            [((4+BIP32_HARDENED_KEY_OFFSET, 4+BIP32_HARDENED_KEY_OFFSET),),
             ((5, 10), (15, 15)),
             ((1+BIP32_HARDENED_KEY_OFFSET, 1+BIP32_HARDENED_KEY_OFFSET),)])

        self.assertEqual(
            list(BIP32PathTemplate("m/0'/2147483647'/1/10")),
            [((BIP32_HARDENED_KEY_OFFSET, BIP32_HARDENED_KEY_OFFSET),),
             ((0xFFFFFFFF, 0xFFFFFFFF),), ((1, 1),), ((10, 10),)])

        self.assertEqual(
            list(BIP32PathTemplate(
                'm/'+'/'.join("%u'" % n for n in range(128))
                + '/' + '/'.join("%u" % (BIP32_HARDENED_KEY_OFFSET-n-1)
                                 for n in range(127)))),
            [((n+BIP32_HARDENED_KEY_OFFSET, n+BIP32_HARDENED_KEY_OFFSET),)
             for n in range(128)]
            + [((BIP32_HARDENED_KEY_OFFSET-n-1, BIP32_HARDENED_KEY_OFFSET-n-1),)
               for n in range(127)])

    def test_path_from_list(self) -> None:
        with self.assertRaisesRegex(ValueError, 'cannot be negative'):
            BIP32Path([-1])
        with self.assertRaisesRegex(ValueError, 'derivation index cannot be'):
            BIP32Path([0xFFFFFFFF+1])  # more than 32bit
        with self.assertRaisesRegex(ValueError, 'unsupported hardened_marker'):
            # only apostrophe and "h" markers are allowed
            BIP32Path([0xFFFFFFFF, 0, 0x80000000],
                      hardened_marker='b')

        with self.assertRaisesRegex(ValueError, 'derivation path longer than 255 elements'):
            # too long path
            BIP32Path([0 for _ in range(256)])

        self.assertEqual(str(BIP32Path([0], is_partial=False)), "m/0")
        self.assertEqual(str(BIP32Path(BIP32Path([0], is_partial=False))),
                         "m/0")
        self.assertEqual(str(BIP32Path(BIP32Path([0], is_partial=True))),
                         "0")
        self.assertEqual(str(BIP32Path([], is_partial=False)), "m")
        self.assertEqual(str(BIP32Path([0])), "0")
        self.assertEqual(str(BIP32Path([])), "")

        self.assertEqual(
            str(BIP32Path([0xFFFFFFFF, 0x80000001, 1, 0x80000002])),
            "2147483647'/1'/1/2'")

        self.assertEqual(
            str(BIP32Path([0xFFFFFFFF, 0x80000001, 1, 2],
                          hardened_marker='h', is_partial=False)),
            "m/2147483647h/1h/1/2")

        self.assertEqual(
            str(BIP32Path([n+BIP32_HARDENED_KEY_OFFSET for n in range(128)]
                          + [n for n in range(127)], is_partial=False)),
            'm/'+'/'.join("%u'" % n for n in range(128))
            + '/' + '/'.join("%u" % n for n in range(127)))

    def test_path_template_from_list(self) -> None:
        with self.assertRaisesRegex(ValueError, 'cannot be negative'):
            BIP32PathTemplate([((-1, 0),)])
        with self.assertRaisesRegex(ValueError, 'only increase'):
            BIP32PathTemplate([((10, 10), (10, 10))])
        with self.assertRaisesRegex(ValueError, 'index_from cannot be larger than index_to'):
            BIP32PathTemplate([((10, 9),)])
        with self.assertRaisesRegex(TypeError, 'is expected to be an instance of '):
            BIP32PathTemplate([(0, 0)])  # type: ignore
        with self.assertRaisesRegex(ValueError, 'derivation index cannot be'):
            BIP32PathTemplate([[(0xFFFFFFFF+1, 0xFFFFFFFF+2)]])  # more than 32bit
        with self.assertRaisesRegex(ValueError, 'unsupported hardened_marker'):
            # only apostrophe and "h" markers are allowed
            BIP32PathTemplate([[(0xFFFFFFFF, 0xFFFFFFFF)], [(0, 0)],
                               [(0x80000000, 0x80000000)]],
                              hardened_marker='b')

        with self.assertRaisesRegex(ValueError, 'derivation path longer than 255 elements'):
            # too long path
            BIP32PathTemplate([((n, n),) for n in range(256)])

        self.assertEqual(str(BIP32PathTemplate([((0, 0),)], is_partial=False)),
                         "m/0")
        self.assertEqual(str(BIP32PathTemplate([((0, 1),)], is_partial=True)),
                         "{0-1}")
        self.assertEqual(str(BIP32PathTemplate([((0, 0),)], is_partial=True)),
                         "0")

        self.assertEqual(str(BIP32PathTemplate(
            [((0, BIP32_HARDENED_KEY_OFFSET-1),)], is_partial=False)), "m/*")

        self.assertEqual(str(BIP32PathTemplate(
            [((BIP32_HARDENED_KEY_OFFSET, 0xFFFFFFFF),)], is_partial=False)),
            "m/*'")
        self.assertEqual(str(BIP32PathTemplate(
            [((BIP32_HARDENED_KEY_OFFSET, 0xFFFFFFFF),)], is_partial=False,
            hardened_marker='h')),
            "m/*h")
        self.assertEqual(str(BIP32PathTemplate(
            [((BIP32_HARDENED_KEY_OFFSET, 0xFFFFFFFF),)], is_partial=True,
            hardened_marker='h')),
            "*h")
        self.assertEqual(str(BIP32PathTemplate([], is_partial=False)), "m")
        self.assertEqual(str(BIP32PathTemplate([((0, 0),)])), "0")
        self.assertEqual(str(BIP32PathTemplate([])), "")

        self.assertEqual(
            str(BIP32PathTemplate(
                [[(0xFFFFFFFF, 0xFFFFFFFF)],
                 [(0x80000001, 0x80000001)],
                 [(1, 2)],
                 [(0x80000002, 0x80000003), (0x80000004, 0x80000004)]
                 ])),
            "2147483647'/1'/{1-2}/{2-3,4}'")

        self.assertEqual(
            str(BIP32PathTemplate(
                [[(0xFFFFFFFF, 0xFFFFFFFF)],
                 [(0x80000001, 0x80000001)],
                 [(1, 2)],
                 [(0x80000002, 0x80000003), (0x80000004, 0x80000004)]
                 ],
                hardened_marker='h', is_partial=False)),
            "m/2147483647h/1h/{1-2}/{2-3,4}h")

        self.assertEqual(
            str(BIP32PathTemplate(
                [((n+BIP32_HARDENED_KEY_OFFSET, n+BIP32_HARDENED_KEY_OFFSET),)
                 for n in range(128)]
                + [((n, n),) for n in range(127)],
                is_partial=False)),
            'm/'+'/'.join("%u'" % n for n in range(128))
            + '/' + '/'.join("%u" % n for n in range(127)))

    def test_from_BIP32Path(self) -> None:
        p = BIP32Path("m/4h/5h/1/4")
        self.assertEqual(str(BIP32Path(p)), "m/4h/5h/1/4")
        self.assertEqual(str(BIP32Path(p, hardened_marker="'")), "m/4'/5'/1/4")
        p = BIP32Path("m/4'/5'/1/4")
        self.assertEqual(str(BIP32Path(p)), "m/4'/5'/1/4")
        self.assertEqual(str(BIP32Path(p, hardened_marker='h')), "m/4h/5h/1/4")
        p = BIP32Path("4'/5'/1/4")
        self.assertEqual(str(BIP32Path(p)), "4'/5'/1/4")
        self.assertEqual(str(BIP32Path(p, hardened_marker='h')), "4h/5h/1/4")

    def test_from_BIP32PathTemplate(self) -> None:
        p = BIP32PathTemplate("m/{4-44}h/{5-555555}h/1/4/*h")
        self.assertEqual(str(BIP32PathTemplate(p)),
                         "m/{4-44}h/{5-555555}h/1/4/*h")
        self.assertEqual(str(BIP32PathTemplate(p, hardened_marker="'")),
                         "m/{4-44}'/{5-555555}'/1/4/*'")
        p = BIP32PathTemplate("m/4'/5'/*/4")
        self.assertEqual(str(BIP32PathTemplate(p)), "m/4'/5'/*/4")
        self.assertEqual(str(BIP32PathTemplate(p, hardened_marker='h')),
                         "m/4h/5h/*/4")
        p = BIP32PathTemplate("4'/5'/1/{3,4,5-10}")
        self.assertEqual(str(BIP32PathTemplate(p)), "4'/5'/1/{3-10}")
        self.assertEqual(str(BIP32PathTemplate(p, hardened_marker='h')),
                         "4h/5h/1/{3-10}")

    def test_random_access(self) -> None:
        p = BIP32Path("m/4h/5h/1/4")
        self.assertEqual(p[0], 4+BIP32_HARDENED_KEY_OFFSET)
        self.assertEqual(p[1], 5+BIP32_HARDENED_KEY_OFFSET)
        self.assertEqual(p[2], 1)
        self.assertEqual(p[3], 4)
        p = BIP32Path([0xFFFFFFFF-n for n in range(255)])
        self.assertEqual(p[254], 0xFFFFFF01)

        pt = BIP32PathTemplate("m/4h/5h/{1-2}/{4,7}")
        self.assertEqual(pt[0][0][0], 4+BIP32_HARDENED_KEY_OFFSET)
        self.assertEqual(pt[0][0][1], 4+BIP32_HARDENED_KEY_OFFSET)
        self.assertEqual(pt[1][0][0], 5+BIP32_HARDENED_KEY_OFFSET)
        self.assertEqual(pt[1][0][1], 5+BIP32_HARDENED_KEY_OFFSET)
        self.assertEqual(pt[2][0][0], 1)
        self.assertEqual(pt[2][0][1], 2)
        self.assertEqual(pt[3][0][0], 4)
        self.assertEqual(pt[3][0][1], 4)
        self.assertEqual(pt[3][1][0], 7)
        self.assertEqual(pt[3][1][1], 7)
        pt = BIP32PathTemplate([[(0xFFFFFFFF-n, 0xFFFFFFFF-n)]
                               for n in range(255)])
        self.assertEqual(pt[254][0][0], 0xFFFFFF01)
        self.assertEqual(pt[254][0][1], 0xFFFFFF01)

    def test_BIP32PathTemplate_match_path(self) -> None:
        t_partial = BIP32PathTemplate("4'/5'/1/{3,4,5-50}")
        t_full = BIP32PathTemplate("m/4'/5'/1/{3,4,5-50}")

        for v in [3, 4] + list(range(5, 50)):
            self.assertTrue(t_partial.match_path(BIP32Path(f"4'/5'/1/{v}")))

        for v in [3, 4] + list(range(5, 50)):
            self.assertTrue(t_full.match_path(BIP32Path(f"m/4'/5'/1/{v}")))

        self.assertFalse(t_full.match_path(BIP32Path("4'/5'/1/3")))
        self.assertFalse(t_partial.match_path(BIP32Path("m/4'/5'/1/3")))

        self.assertFalse(t_full.match_path(BIP32Path("m/4'/5'/1")))
        self.assertFalse(t_partial.match_path(BIP32Path("4'/5'/1")))

        self.assertFalse(t_full.match_path(BIP32Path("m/4'/5'/1/3/1")))
        self.assertFalse(t_partial.match_path(BIP32Path("4'/5'/1/3/1")))

        self.assertTrue(
            BIP32PathTemplate("m/4'/5'/1/{3,4,5-50}/*").match_path(
                BIP32Path("m/4'/5'/1/3/1")))

        self.assertTrue(
            BIP32PathTemplate("4h/5h/1h/{3,4,5-50}h/*h").match_path(
                BIP32Path("4'/5'/1'/3'/323452'")))

        self.assertFalse(
            BIP32PathTemplate("4h/5h/1h/{3,4,5-50}h/*h").match_path(
                BIP32Path("4'/5'/1'/3/323452'")))

        self.assertFalse(
            BIP32PathTemplate("4h/5h/1h/{3,4,5-50}h/*h").match_path(
                BIP32Path("4'/5'/1'/3'/323452")))

        self.assertTrue(BIP32PathTemplate("*h").match_path(BIP32Path("323452h")))
        self.assertTrue(BIP32PathTemplate("{0-100,200-300}h").match_path(BIP32Path("99h")))
        self.assertTrue(BIP32PathTemplate("{0-100,200-300}h").match_path(BIP32Path("299h")))
        self.assertFalse(BIP32PathTemplate("{0-100,200-300}h").match_path(BIP32Path("199h")))
        self.assertTrue(BIP32PathTemplate("m").match_path(BIP32Path("m")))
        self.assertTrue(BIP32PathTemplate("").match_path(BIP32Path("")))
        self.assertFalse(BIP32PathTemplate("m").match_path(BIP32Path("")))
        self.assertFalse(BIP32PathTemplate("").match_path(BIP32Path("m")))

        self.assertTrue(
            BIP32PathTemplate('/'.join(str(v) for v in range(255))).match_path(
                BIP32Path('/'.join(str(v) for v in range(255)))))

    def test_BIP32PathTemplate_with_generated_data(self) -> None:
        test_dict = load_path_teplate_test_vectors('bip32_template.json')
        for status, data in test_dict.items():
            if status == "normal_finish":
                for elt in data:
                    assert isinstance(elt, list)
                    tmpl_str, tmpl = elt
                    tmpl_tuple = tuple(tuple(tuple(range) for range in section)
                                       for section in json.loads(tmpl))
                    pt = BIP32PathTemplate(tmpl_str)
                    self.assertEqual(tuple(pt), tmpl_tuple)
            else:
                for elt in data:
                    assert isinstance(elt, str)
                    tmpl_str = elt
                    try:
                        pt = BIP32PathTemplate(tmpl_str)
                    except ValueError as e:
                        if str(e).startswith("incorrect path template index bound"):
                            assert status in ["error_range_start_equals_end",
                                              "error_ranges_intersect",
                                              "error_range_order_bad"], (tmpl_str, status)
                        elif str(e).startswith("index range equals wildcard range"):
                            assert status == "error_range_equals_wildcard", (tmpl_str, status)
                        elif str(e).startswith("non-digit character found"):
                            assert status in ["error_unexpected_char",
                                              "error_invalid_char",
                                              "error_digit_expected"], (tmpl_str, status)
                        elif str(e).startswith("index template format is not valid"):
                            assert status in ["error_unexpected_char",
                                              "error_invalid_char",
                                              "error_unexpected_finish",
                                              "error_digit_expected"], (tmpl_str, status)
                        elif str(e).startswith("leading zeroes are not allowed"):
                            assert status == "error_index_has_leading_zero", (tmpl_str, status)
                        elif str(e).startswith("index_from cannot be larger than index_to in an index tuple"):
                            assert status == "error_range_order_bad", (tmpl_str, status)
                        elif str(e).startswith('derivation path must not end with "/"'):
                            assert status == "error_unexpected_slash", (tmpl_str, status)
                        elif str(e).startswith('partial derivation path must not start with "/"'):
                            assert status == "error_unexpected_slash", (tmpl_str, status)
                        elif str(e).startswith('duplicate slashes are not allowed'):
                            assert status == "error_unexpected_slash", (tmpl_str, status)
                        elif str(e).startswith('Unexpected hardened marker'):
                            assert status == "error_unexpected_hardened_marker", (tmpl_str, status)
                        elif str(e).startswith('whitespace found'):
                            assert status == "error_unexpected_space", (tmpl_str, status)
                        elif str(e).startswith('derivation index string cannot represent value > 2147483647'):
                            assert status == "error_index_too_big", (tmpl_str, status)
                        else:
                            raise
