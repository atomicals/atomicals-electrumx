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
import unittest
import os

from typing import Iterator, Tuple, Dict

from bitcointx.core import (
    x, lx, b2x,
    CTransaction, CMutableTransaction, COutPoint, CMutableOutPoint,
    CTxIn, CTxOut, CMutableTxIn, CMutableTxOut,
    CTxWitness, CTxInWitness,
    CMutableTxWitness, CMutableTxInWitness,
    CheckTransaction, CheckTransactionError, ValidationError
)
from bitcointx.core.script import CScript, CScriptWitness
from bitcointx.core.scripteval import VerifyScript, SCRIPT_VERIFY_P2SH

from bitcointx.tests.test_scripteval import parse_script


def load_test_vectors(name: str) -> Iterator[
    Tuple[Dict[COutPoint, CScript], CTransaction, bytes, bool]
]:
    with open(os.path.dirname(__file__) + '/data/' + name, 'r') as fd:
        for test_case in json.load(fd):
            # Comments designated by single length strings
            if len(test_case) == 1:
                continue
            assert len(test_case) == 3

            prevouts = {}
            for json_prevout in test_case[0]:
                assert len(json_prevout) == 3
                n = json_prevout[1]
                if n == -1:
                    n = 0xffffffff
                prevout = COutPoint(lx(json_prevout[0]), n)
                prevouts[prevout] = parse_script(json_prevout[2])

            tx_data = x(test_case[1])
            tx = CTransaction.deserialize(tx_data)
            enforceP2SH = test_case[2]

            yield (prevouts, tx, tx_data, enforceP2SH)


class Test_COutPoint(unittest.TestCase):
    def test_is_null(self) -> None:
        self.assertTrue(COutPoint().is_null())
        self.assertTrue(COutPoint(hash=b'\x00'*32, n=0xffffffff).is_null())
        self.assertFalse(COutPoint(hash=b'\x00'*31 + b'\x01').is_null())
        self.assertFalse(COutPoint(n=1).is_null())

    def test_repr(self) -> None:
        def T(outpoint: COutPoint, expected: str) -> None:
            actual = repr(outpoint)
            self.assertEqual(actual, expected)
        T(COutPoint(),
          'CBitcoinOutPoint()')
        T(COutPoint(lx('4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'), 0),
          "CBitcoinOutPoint(lx('4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'), 0)")

    def test_str(self) -> None:
        def T(outpoint: COutPoint, expected: str) -> None:
            actual = str(outpoint)
            self.assertEqual(actual, expected)
        T(COutPoint(),
          '0000000000000000000000000000000000000000000000000000000000000000:4294967295')
        T(COutPoint(lx('4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'), 0),
          '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b:0')
        T(COutPoint(lx('4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'), 10),
          '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b:10')

    def test_immutable(self) -> None:
        """COutPoint shall not be mutable"""
        outpoint = COutPoint()
        with self.assertRaises(AttributeError):
            outpoint.n = 1  # type: ignore

    def test_clone(self) -> None:
        outpoint = COutPoint(lx('4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'), 0)
        self.assertEqual(outpoint.serialize(), outpoint.clone().serialize())


class Test_CMutableOutPoint(unittest.TestCase):
    def test_GetHash(self) -> None:
        """CMutableOutPoint.GetHash() is not cached"""
        outpoint = CMutableOutPoint()

        h1 = outpoint.GetHash()
        outpoint.n = 1

        self.assertNotEqual(h1, outpoint.GetHash())

    def test_repr(self) -> None:
        def T(outpoint: COutPoint, expected: str) -> None:
            actual = repr(outpoint)
            self.assertEqual(actual, expected)
        T(CMutableOutPoint(),
          'CBitcoinMutableOutPoint()')
        T(CMutableOutPoint(lx('4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'), 0),
          "CBitcoinMutableOutPoint(lx('4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'), 0)")

    def test_clone(self) -> None:
        outpoint = CMutableOutPoint(lx('4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'), 0)
        self.assertEqual(outpoint.serialize(), outpoint.clone().serialize())


class Test_CTxIn(unittest.TestCase):
    def test_is_final(self) -> None:
        self.assertTrue(CTxIn().is_final())
        self.assertTrue(CTxIn(nSequence=0xffffffff).is_final())
        self.assertFalse(CTxIn(nSequence=0).is_final())

    def test_repr(self) -> None:
        def T(txin: CTxIn, expected: str) -> None:
            actual = repr(txin)
            self.assertEqual(actual, expected)
        T(CTxIn(),
          'CBitcoinTxIn(CBitcoinOutPoint(), CBitcoinScript([]), 0xffffffff)')

    def test_immutable(self) -> None:
        """CTxIn shall not be mutable"""
        txin = CTxIn()
        with self.assertRaises(AttributeError):
            txin.nSequence = 1  # type: ignore

    def test_clone(self) -> None:
        outpoint = COutPoint(lx('4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'), 0)
        txin = CTxIn(prevout=outpoint, scriptSig=CScript(b'\x03abc'), nSequence=0xffffffff)
        self.assertEqual(txin.serialize(), txin.clone().serialize())


class Test_CMutableTxIn(unittest.TestCase):
    def test_GetHash(self) -> None:
        """CMutableTxIn.GetHash() is not cached"""
        txin = CMutableTxIn()

        h1 = txin.GetHash()
        txin.prevout.n = 1

        self.assertNotEqual(h1, txin.GetHash())

    def test_repr(self) -> None:
        def T(txin: CTxIn, expected: str) -> None:
            actual = repr(txin)
            self.assertEqual(actual, expected)
        T(CMutableTxIn(),
          'CBitcoinMutableTxIn(CBitcoinMutableOutPoint(), CBitcoinScript([]), 0xffffffff)')

    def test_clone(self) -> None:
        outpoint = COutPoint(lx('4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b'), 0)
        txin = CMutableTxIn(prevout=outpoint, scriptSig=CScript(b'\x03abc'), nSequence=0xffffffff)
        self.assertEqual(txin.serialize(), txin.clone().serialize())


class Test_CTxOut(unittest.TestCase):
    def test_repr(self) -> None:
        def T(txout: CTxOut, expected: str) -> None:
            actual = repr(txout)
            self.assertEqual(actual, expected)
        T(CTxOut(1000, CScript(b'\x03abc')),
          "CBitcoinTxOut(0.00001*COIN, CBitcoinScript([x('616263')]))")

    def test_immutable(self) -> None:
        txout = CTxOut()
        with self.assertRaises(AttributeError):
            txout.Value = 1

    def test_clone(self) -> None:
        txout = CTxOut(1000, CScript(b'\x03abc'))
        self.assertEqual(txout.serialize(), txout.clone().serialize())


class Test_CMutableTxOut(unittest.TestCase):
    def test_repr(self) -> None:
        def T(txout: CTxOut, expected: str) -> None:
            actual = repr(txout)
            self.assertEqual(actual, expected)
        T(CMutableTxOut(1000, CScript(b'\x03abc')),
            "CBitcoinMutableTxOut(0.00001*COIN, CBitcoinScript([x('616263')]))")

    def test_clone(self) -> None:
        txout = CMutableTxOut(1000, CScript(b'\x03abc'))
        self.assertEqual(txout.serialize(), txout.clone().serialize())


class Test_CTxWitness(unittest.TestCase):
    def test_repr(self) -> None:
        def T(txwitness: CTxWitness, expected: str) -> None:
            actual = repr(txwitness)
            self.assertEqual(actual, expected)
        T(CTxWitness([CTxInWitness(CScriptWitness([1]))]),
            "CBitcoinTxWitness([CBitcoinTxInWitness(CScriptWitness([x('01')]))])")

    def test_immutable(self) -> None:
        wit = CTxWitness([CTxInWitness(CScriptWitness([1]))])
        with self.assertRaises(AttributeError):
            wit.vtxinwit = []  # type: ignore

    def test_clone(self) -> None:
        wit = CTxWitness([CTxInWitness(CScriptWitness([1]))])
        self.assertEqual(wit.serialize(), wit.clone().serialize())


class Test_CMutableTxWitness(unittest.TestCase):
    def test_repr(self) -> None:
        def T(txwitness: CTxWitness, expected: str) -> None:
            actual = repr(txwitness)
            self.assertEqual(actual, expected)
        T(CMutableTxWitness([CTxInWitness(CScriptWitness([1]))]),
            "CBitcoinMutableTxWitness([CBitcoinMutableTxInWitness(CScriptWitness([x('01')]))])")

    def test_clone(self) -> None:
        wit = CMutableTxWitness([CTxInWitness(CScriptWitness([1]))])
        self.assertEqual(wit.serialize(), wit.clone().serialize())


class Test_CTxInWitness(unittest.TestCase):
    def test_repr(self) -> None:
        def T(txinwitness: CTxInWitness, expected: str) -> None:
            actual = repr(txinwitness)
            self.assertEqual(actual, expected)
        T(CTxInWitness(CScriptWitness([1])),
            "CBitcoinTxInWitness(CScriptWitness([x('01')]))")

    def test_immutable(self) -> None:
        wit = CTxInWitness(CScriptWitness([1]))
        with self.assertRaises(AttributeError):
            wit.scriptWitness = CScriptWitness()  # type: ignore

    def test_clone(self) -> None:
        txinwit = CTxInWitness(CScriptWitness([1]))
        self.assertEqual(txinwit.serialize(), txinwit.clone().serialize())


class Test_CMutableTxInWitness(unittest.TestCase):
    def test_repr(self) -> None:
        def T(txinwitness: CTxInWitness, expected: str) -> None:
            actual = repr(txinwitness)
            self.assertEqual(actual, expected)
        T(CMutableTxInWitness(CScriptWitness([1])),
            "CBitcoinMutableTxInWitness(CScriptWitness([x('01')]))")

    def test_clone(self) -> None:
        txinwit = CMutableTxInWitness(CScriptWitness([1]))
        self.assertEqual(txinwit.serialize(), txinwit.clone().serialize())


class Test_CTransaction(unittest.TestCase):
    def test_is_coinbase(self) -> None:
        tx = CMutableTransaction()
        self.assertFalse(tx.is_coinbase())

        tx.vin.append(CMutableTxIn())

        # IsCoinBase() in reference client doesn't check if vout is empty
        self.assertTrue(tx.is_coinbase())

        tx.vin[0].prevout.n = 0
        self.assertFalse(tx.is_coinbase())

        tx.vin[0] = CTxIn().to_mutable()
        tx.vin.append(CTxIn().to_mutable())
        self.assertFalse(tx.is_coinbase())

    def test_tx_valid(self) -> None:
        for prevouts, tx, tx_data, enforceP2SH in load_test_vectors('tx_valid.json'):
            self.assertEqual(tx_data, tx.serialize())
            self.assertEqual(tx_data, CTransaction.deserialize(tx.serialize()).serialize())
            try:
                CheckTransaction(tx)
            except CheckTransactionError:
                self.fail('tx failed CheckTransaction(): '
                          + str((prevouts, b2x(tx.serialize()), enforceP2SH)))
                continue

            for i in range(len(tx.vin)):
                flags = set()
                if enforceP2SH:
                    flags.add(SCRIPT_VERIFY_P2SH)

                VerifyScript(tx.vin[i].scriptSig, prevouts[tx.vin[i].prevout], tx, i, flags=flags)

    def test_tx_invalid(self) -> None:
        for prevouts, tx, _, enforceP2SH in load_test_vectors('tx_invalid.json'):
            try:
                CheckTransaction(tx)
            except CheckTransactionError:
                continue

            with self.assertRaises(ValidationError):
                for i in range(len(tx.vin)):
                    flags = set()
                    if enforceP2SH:
                        flags.add(SCRIPT_VERIFY_P2SH)

                    VerifyScript(tx.vin[i].scriptSig, prevouts[tx.vin[i].prevout], tx, i, flags=flags)

    def test_immutable(self) -> None:
        tx = CTransaction()
        self.assertFalse(tx.is_coinbase())

        with self.assertRaises(AttributeError):
            tx.nVersion = 2  # type: ignore
        with self.assertRaises(AttributeError):
            tx.vin.append(CTxIn())  # type: ignore

        mtx = tx.to_mutable()
        mtx.nVersion = 2
        mtx.vin.append(CTxIn().to_mutable())

        itx = tx.to_immutable()

        with self.assertRaises(AttributeError):
            itx.nVersion = 2  # type: ignore
        with self.assertRaises(AttributeError):
            itx.vin.append(CTxIn())  # type: ignore

    def test_mutable_tx_creation_with_immutable_parts_specified(self) -> None:
        tx = CMutableTransaction(
            vin=[CTxIn(prevout=COutPoint(hash=b'a'*32, n=0))],
            vout=[CTxOut(nValue=1)],
            witness=CTxWitness([CTxInWitness()]))

        def check_mutable_parts(tx: CMutableTransaction) -> None:
            self.assertTrue(tx.vin[0].is_mutable())
            self.assertTrue(tx.vin[0].prevout.is_mutable())
            self.assertTrue(tx.vout[0].is_mutable())
            self.assertTrue(tx.wit.is_mutable())
            self.assertTrue(tx.wit.vtxinwit[0].is_mutable())

        check_mutable_parts(tx)

        # Test that if we deserialize with CMutableTransaction,
        # all the parts are mutable
        tx = CMutableTransaction.deserialize(tx.serialize())
        check_mutable_parts(tx)

        # Test some parts separately, because when created via
        # CMutableTransaction instantiation, they are created with from_*
        # methods, and not directly

        txin = CMutableTxIn(prevout=COutPoint(hash=b'a'*32, n=0))
        self.assertTrue(txin.prevout.is_mutable())

        wit = CMutableTxWitness((CTxInWitness(),))
        self.assertTrue(wit.vtxinwit[0].is_mutable())

    def test_immutable_tx_creation_with_mutable_parts_specified(self) -> None:
        tx = CTransaction(
            vin=[CMutableTxIn(prevout=COutPoint(hash=b'a'*32, n=0))],
            vout=[CMutableTxOut(nValue=1)],
            witness=CMutableTxWitness(
                [CMutableTxInWitness(CScriptWitness([CScript([0])]))]))

        def check_immutable_parts(tx: CTransaction) -> None:
            self.assertTrue(tx.vin[0].is_immutable())
            self.assertTrue(tx.vin[0].is_immutable())
            self.assertTrue(tx.vout[0].is_immutable())
            self.assertTrue(tx.wit.is_immutable())
            self.assertTrue(tx.wit.vtxinwit[0].is_immutable())

        check_immutable_parts(tx)

        # Test that if we deserialize with CTransaction,
        # all the parts are immutable
        tx = CTransaction.deserialize(tx.serialize())
        check_immutable_parts(tx)

        # Test some parts separately, because when created via
        # CMutableTransaction instantiation, they are created with from_*
        # methods, and not directly

        txin = CTxIn(prevout=CMutableOutPoint(hash=b'a'*32, n=0))
        self.assertTrue(txin.prevout.is_immutable())

        wit = CTxWitness((CMutableTxInWitness(),))
        self.assertTrue(wit.vtxinwit[0].is_immutable())

    def test_clone(self) -> None:
        tx = CTransaction.deserialize(x('020000000001025fdeae88276b595be42d440d638a52d3ea0e1e1c820ab305ce438452468d7a2201000000171600149f2ca9bcbfb16f8a5c4f664aa22a2c833545a2b5fefffffffc25d526160911147b11fefeb6598ae97e093590d642265f27a67e7242a2ac31000000001716001482ad37a540c47bbb740596667f472f9d96f6dfb3feffffff02848a1b000000000017a914dc5d78da1cd6b02e08f0aa7bf608b091094415968700e1f5050000000017a9144b8acc9fc4210a5ce3ff417b00b419fd4fb03f8c8702473044022042c7ca216ace58920d6114ad30798a7a0b2b64faf17803034316dd83c90048a002205e37943bc694622128494fa2d9d3d402a58d91c1661c9a3a28124ff0e457d561012103bb79122851602141d7ec63a7342bc23bc51f050808695c141958cf2c222e38ed02483045022100c6841686570b60540b1c5ef620f3159f1f359a12cf30112650e72c44864b3e7202205c565a6cf05578557232e03d1655b73dcbf4e082c6ff0602707f0c0394c86b7601210292f52933e2105dc7410445be9a9d01589e0b9bc09d7a4e1509dc8e094b9ee9e437040000'))
        self.assertEqual(tx.serialize(), tx.clone().serialize())

    def test_tx_vsize(self) -> None:
        """simple test to check that tx virtual size calculation works.
        transaction sizes taken from Bitcoin Core's decoderawtransaction output"""
        tx_no_witness = CTransaction.deserialize(x('0200000001eab856b5c4de81511cedab916630cf0afa38ea4ed8e0e88c8990eda88773cd47010000006b4830450221008f9ea83b8f4a2d23b07a02f25109aa508a78b85643b0a1f1c8a08c48d32f53e6022053e7028a585c55ba53895e9a8ef8def86b1d109ec057400f4d5f152f5bf302d60121020bcf101930dd54e22344d4ef060561fe68f42426fe01f92c694bd119f308d44effffffff027ef91e82100000001976a914f1ef6b3f14c69cafd75b3a5cd2101114bb411d5088ac12533c72040000002200201f828f01c988a992ef9efb4c77a8e3607df0f97edbc3029fe95d62f6b1c436bb00000000'))
        tx_no_witness_vsize = 235
        self.assertEqual(tx_no_witness.get_virtual_size(), tx_no_witness_vsize)
        tx_with_witness = CTransaction.deserialize(x('020000000001025fdeae88276b595be42d440d638a52d3ea0e1e1c820ab305ce438452468d7a2201000000171600149f2ca9bcbfb16f8a5c4f664aa22a2c833545a2b5fefffffffc25d526160911147b11fefeb6598ae97e093590d642265f27a67e7242a2ac31000000001716001482ad37a540c47bbb740596667f472f9d96f6dfb3feffffff02848a1b000000000017a914dc5d78da1cd6b02e08f0aa7bf608b091094415968700e1f5050000000017a9144b8acc9fc4210a5ce3ff417b00b419fd4fb03f8c8702473044022042c7ca216ace58920d6114ad30798a7a0b2b64faf17803034316dd83c90048a002205e37943bc694622128494fa2d9d3d402a58d91c1661c9a3a28124ff0e457d561012103bb79122851602141d7ec63a7342bc23bc51f050808695c141958cf2c222e38ed02483045022100c6841686570b60540b1c5ef620f3159f1f359a12cf30112650e72c44864b3e7202205c565a6cf05578557232e03d1655b73dcbf4e082c6ff0602707f0c0394c86b7601210292f52933e2105dc7410445be9a9d01589e0b9bc09d7a4e1509dc8e094b9ee9e437040000'))
        tx_with_witness_vsize = 257
        self.assertEqual(tx_with_witness.get_virtual_size(), tx_with_witness_vsize)

        tx = tx_no_witness.to_mutable()
        for i in range(260):
            tx.vout.append(tx.vout[0])
        self.assertEqual(tx.get_virtual_size(), 9077)

        tx = tx_with_witness.to_mutable()
        for i in range(260):
            tx.vout.append(tx.vout[0])

        self.assertEqual(tx.get_virtual_size(), 8579)
