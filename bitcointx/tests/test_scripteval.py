# Copyright (C) 2013-2017 The python-bitcoinlib developers
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

import json
import os
import unittest
import warnings
import ctypes
import random

from typing import List, Iterator, Tuple, Set, Optional, Sequence, Dict, Union

from binascii import unhexlify

from bitcointx.core import (
    coins_to_satoshi, x, ValidationError,
    CTxOut, CTxIn, CTransaction, COutPoint, CTxWitness, CTxInWitness
)
from bitcointx.core.key import CKey, tap_tweak_pubkey
from bitcointx.core.script import (
    OPCODES_BY_NAME, CScript, CScriptWitness,
    OP_0, SIGHASH_ALL, SIGVERSION_BASE, SIGVERSION_WITNESS_V0, OP_CHECKSIG,
    standard_multisig_redeem_script, standard_multisig_witness_stack,
    TaprootScriptTree, TaprootScriptTreeLeaf_Type, SignatureHashSchnorr
)
from bitcointx.core.scripteval import (
    VerifyScript, SCRIPT_VERIFY_FLAGS_BY_NAME, SCRIPT_VERIFY_P2SH,
    SCRIPT_VERIFY_WITNESS, ScriptVerifyFlag_Type
)
from bitcointx.core.bitcoinconsensus import (
    ConsensusVerifyScript, BITCOINCONSENSUS_ACCEPTED_FLAGS,
    load_bitcoinconsensus_library
)
from bitcointx.wallet import P2TRCoinAddress, CCoinKey

TestDataIterator = Iterator[
    Tuple[CScript, CScript, CScript, CScriptWitness, int,
          Optional[Sequence[CTxOut]], Set[ScriptVerifyFlag_Type],
          str, str, str]
]


def parse_script(s: str) -> CScript:
    def ishex(s: str) -> bool:
        return set(s).issubset(set('0123456789abcdefABCDEF'))

    r: List[bytes] = []

    # Create an opcodes_by_name table with both OP_ prefixed names and
    # shortened ones with the OP_ dropped.
    opcodes_by_name = {}
    for name, code in OPCODES_BY_NAME.items():
        opcodes_by_name[name] = code
        opcodes_by_name[name[3:]] = code

    for word in s.split():
        if word.isdigit() or (word[0] == '-' and word[1:].isdigit()):
            r.append(CScript([int(word)]))
        elif word.startswith('0x') and ishex(word[2:]):
            # Raw ex data, inserted NOT pushed onto stack:
            r.append(unhexlify(word[2:].encode('utf8')))
        elif len(word) >= 2 and word[0] == "'" and word[-1] == "'":
            r.append(CScript([bytes(word[1:-1].encode('utf8'))]))
        elif word in opcodes_by_name:
            r.append(CScript([opcodes_by_name[word]]))
        else:
            raise ValueError("Error parsing script: %r" % s)

    return CScript(b''.join(r))


def load_test_vectors(name: str, skip_fixme: bool = True) -> TestDataIterator:
    with open(os.path.dirname(__file__) + '/data/' + name, 'r') as fd:
        fixme_comment = None
        num_skipped = 0
        for test_case in json.load(fd):
            if len(test_case) == 1:
                continue  # comment

            if len(test_case) == 2:
                if not skip_fixme:
                    assert test_case[0].startswith('FIXME'), \
                        "we do not expect anything other than FIXME* here"
                    continue
                if test_case[0] == 'FIXME':
                    fixme_comment = test_case[1]
                    continue
                if test_case[0] == 'FIXME_END':
                    warnings.warn("SKIPPED {} tests: {}"
                                  .format(num_skipped, fixme_comment))
                    fixme_comment = None
                    num_skipped = 0
                    continue

            if fixme_comment:
                num_skipped += 1
                continue

            to_unpack = test_case.copy()

            witness = CScriptWitness()
            nValue = 0
            if isinstance(to_unpack[0], list):
                wdata = to_unpack.pop(0)
                stack = [CScript(x(d)) for d in wdata[:-1]]
                witness = CScriptWitness(stack)
                nValue = int(round(wdata[-1] * 1e8))

            if len(to_unpack) == 4:
                to_unpack.append('')  # add missing comment

            assert len(to_unpack) == 5, "unexpected test data format: {}".format(to_unpack)

            scriptSig_str, scriptPubKey_str, flags, expected_result, comment = to_unpack

            scriptSig = parse_script(scriptSig_str)
            scriptPubKey = parse_script(scriptPubKey_str)

            flag_set = set()
            for flag in flags.split(','):
                if flag == '' or flag == 'NONE':
                    pass

                else:
                    try:
                        flag = SCRIPT_VERIFY_FLAGS_BY_NAME[flag]
                    except IndexError:
                        raise Exception('Unknown script verify flag %r' % flag)

                    flag_set.add(flag)

            yield (scriptSig, scriptPubKey, CScript(), witness, nValue, None,
                   flag_set, expected_result, comment, test_case)

        if fixme_comment is not None:
            raise Exception('Unbalanced FIXME blocks in test data')


class Test_EvalScript(unittest.TestCase):

    def setUp(self) -> None:
        try:
            handle = load_bitcoinconsensus_library()
        except ImportError:
            warnings.warn(
                "libbitcoinconsensus library is not avaliable, "
                "not testing bitcoinconsensus module and taproot scripts")
            handle = None

        self._bitcoinconsensus_handle = handle

    # IMPORANT: The code inside this function (TaprootScriptTree functionality)
    # is what actually being tested here, not the libbitcoinconsensus
    # interface, so this should not be changed into something that just
    # loads data from a json file.
    def generate_taproot_test_scripts(self) -> TestDataIterator:
        k = CCoinKey.from_secret_bytes(os.urandom(32))

        xopub = k.xonly_pub

        spk = P2TRCoinAddress.from_xonly_pubkey(xopub).to_scriptPubKey()
        nValue = 100
        (txCredit, txSpend) = self.create_test_txs(
            CScript(), spk, spk, CScriptWitness(), nValue)
        sh = SignatureHashSchnorr(txSpend, 0, txCredit.vout)
        sig = k.sign_schnorr_tweaked(sh)
        yield (CScript(), spk, spk, CScriptWitness([sig]), nValue,
               txCredit.vout, BITCOINCONSENSUS_ACCEPTED_FLAGS,
               'OK', '', 'simple taproot spend')

        random_tweak = os.urandom(32)

        tt_res = tap_tweak_pubkey(xopub, merkle_root=random_tweak)
        assert tt_res is not None
        rnd_twpub, _ = tt_res

        t = TaprootScriptTree(
            [CScript([rnd_twpub, OP_CHECKSIG], name='simplespend')])
        t.set_internal_pubkey(xopub)

        swcb = t.get_script_with_control_block('simplespend')
        assert swcb is not None
        s, cb = swcb
        spk = P2TRCoinAddress.from_script_tree(t).to_scriptPubKey()
        (txCredit, txSpend) = self.create_test_txs(
            CScript(), spk, spk, CScriptWitness(), nValue)
        sh = s.sighash_schnorr(txSpend, 0, txCredit.vout)
        sig = k.sign_schnorr_tweaked(sh, merkle_root=random_tweak)

        yield (CScript(), spk, spk, CScriptWitness([sig, s, cb]), nValue,
               txCredit.vout, BITCOINCONSENSUS_ACCEPTED_FLAGS,
               'OK', '', 'simple taproot script spend')

        def gen_leaves(num_leaves: int, prefix: str = ''
                       ) -> Tuple[List[TaprootScriptTreeLeaf_Type],
                                  Dict[str, bytes]]:
            leaves: List[TaprootScriptTreeLeaf_Type] = []
            tweaks = {}
            for leaf_idx in range(num_leaves):
                tw = os.urandom(32)
                tt_res = tap_tweak_pubkey(xopub, merkle_root=tw)
                assert tt_res is not None
                twpub, _ = tt_res
                sname = f'{prefix}leaf_{leaf_idx}'
                tweaks[sname] = tw
                leaves.append(CScript([twpub, OP_CHECKSIG], name=sname))

            return leaves, tweaks

        def yield_leaves(leaves: Sequence[Union[CScript, TaprootScriptTree]],
                         tweaks: Dict[str, bytes]) -> TestDataIterator:
            t = TaprootScriptTree(leaves, internal_pubkey=xopub)

            spk = P2TRCoinAddress.from_script_tree(t).to_scriptPubKey()

            for sname, tweak in tweaks.items():
                nValue = random.randint(1, coins_to_satoshi(21000000))
                swcb = t.get_script_with_control_block(sname)
                assert swcb is not None
                s, cb = swcb
                (txCredit, txSpend) = self.create_test_txs(
                    CScript(), spk, spk, CScriptWitness(), nValue)
                sh = s.sighash_schnorr(txSpend, 0, txCredit.vout)
                sig = k.sign_schnorr_tweaked(sh, merkle_root=tweak)

                yield (CScript(), spk, spk, CScriptWitness([sig, s, cb]), nValue,
                       txCredit.vout, BITCOINCONSENSUS_ACCEPTED_FLAGS,
                       'OK', '', f'taproot script spend leaf {sname}')

        # Test simple balanced tree
        for num_leaves in range(1, 12):
            leaves, tweaks = gen_leaves(num_leaves)
            for data in yield_leaves(leaves, tweaks):
                yield data

        leaves, tweaks = gen_leaves(7)
        for data in yield_leaves(leaves, tweaks):
            yield data

        # Test un-balanced geterogenous tree
        lvdict: Dict[str, List[TaprootScriptTreeLeaf_Type]] = {}
        scripts = {}
        for num_scripts, pfx in ((5, 'level1'), (7, 'level2a'), (6, 'level2b'),
                                 (8, 'level3a'), (11, 'level3b'),
                                 (3, 'level3c')):

            lvdict[pfx], new_scripts = gen_leaves(num_scripts, pfx + '/')
            scripts.update(new_scripts)

        l2a = (lvdict['level2a'][:3] +
               [TaprootScriptTree(lvdict['level3a'][:4])] +
               [lvdict['level2a'][3]] +
               [TaprootScriptTree(lvdict['level3a'][4:])] +
               lvdict['level2a'][4:] +
               [TaprootScriptTree(lvdict['level3b'][:10])] +
               [TaprootScriptTree([lvdict['level3b'][10]])])

        l2b: List[TaprootScriptTreeLeaf_Type]
        l2b = [TaprootScriptTree(lvdict['level3c'])]
        l2b.extend(lvdict['level2b'])

        TaprootScriptTree(l2b)

        l1 = (lvdict['level1'][:1] + [TaprootScriptTree(l2a)]
              + lvdict['level1'][1:2] + [TaprootScriptTree(l2b)]
              + lvdict['level1'][2:])

        for data in yield_leaves(l1, scripts):
            yield data

    def create_test_txs(
        self, scriptSig: CScript, scriptPubKey: CScript,
        dst_scriptPubKey: CScript, witness: CScriptWitness, nValue: int
    ) -> Tuple[CTransaction, CTransaction]:
        txCredit = CTransaction([CTxIn(COutPoint(), CScript([OP_0, OP_0]), nSequence=0xFFFFFFFF)],
                                [CTxOut(nValue, scriptPubKey)],
                                witness=CTxWitness(),
                                nLockTime=0, nVersion=1)

        txSpend = CTransaction([CTxIn(COutPoint(txCredit.GetTxid(), 0), scriptSig, nSequence=0xFFFFFFFF)],
                               [CTxOut(nValue, dst_scriptPubKey)],
                               nLockTime=0, nVersion=1,
                               witness=CTxWitness([CTxInWitness(witness)]))
        return (txCredit, txSpend)

    def test_script(self) -> None:
        for t in load_test_vectors('script_tests.json'):
            (scriptSig, scriptPubKey, dst_scriptPubKey, witness, nValue,
             spent_outputs, flags, expected_result, comment, test_case) = t
            (txCredit, txSpend) = self.create_test_txs(
                scriptSig, scriptPubKey, dst_scriptPubKey, witness, nValue)

            try:
                VerifyScript(scriptSig, scriptPubKey, txSpend, 0, flags, amount=nValue, witness=witness)
            except ValidationError as err:
                if expected_result == 'OK':
                    self.fail('Script FAILED: %r %r %r with exception %r\n\nTest data: %r' % (scriptSig, scriptPubKey, comment, err, test_case))
                continue

            if expected_result != 'OK':
                self.fail('Expected %r to fail (%s)' % (test_case, expected_result))

    def _do_test_bicoinconsensus(
        self, handle: Optional[ctypes.CDLL],
        test_data_iterator: TestDataIterator
    ) -> None:
        for t in test_data_iterator:
            (scriptSig, scriptPubKey, dst_scriptPubKey, witness, nValue, spent_outputs,
                flags, expected_result, comment, test_case) = t

            (txCredit, txSpend) = self.create_test_txs(
                scriptSig, scriptPubKey, dst_scriptPubKey, witness, nValue)

            libconsensus_flags = (flags & BITCOINCONSENSUS_ACCEPTED_FLAGS)
            if flags != libconsensus_flags:
                continue

            try:
                ConsensusVerifyScript(scriptSig, scriptPubKey, txSpend, 0,
                                      libconsensus_flags, amount=nValue,
                                      witness=witness,
                                      spent_outputs=spent_outputs,
                                      consensus_library_hanlde=handle)
            except ValidationError as err:
                if expected_result == 'OK':
                    self.fail('Script FAILED: %r %r %r with exception %r\n\nTest data: %r' % (scriptSig, scriptPubKey, comment, err, test_case))
                continue

            if expected_result != 'OK':
                self.fail('Expected %r to fail (%s)' % (test_case, expected_result))

    def test_script_bitcoinconsensus(self) -> None:
        if not self._bitcoinconsensus_handle:
            self.skipTest("bitcoinconsensus library is not available")

        test_data_iterator = load_test_vectors('script_tests.json',
                                               skip_fixme=False)
        # test with supplied handle
        self._do_test_bicoinconsensus(self._bitcoinconsensus_handle,
                                      test_data_iterator)
        # test with default-loaded handle
        self._do_test_bicoinconsensus(None, test_data_iterator)

    def test_script_bitcoinconsensus_taproot_scripts(self) -> None:
        if not self._bitcoinconsensus_handle:
            self.skipTest("bitcoinconsensus library is not available")
        # disabled until libbitcoinconsensus can handle taproot scripts
        # self._do_test_bicoinconsensus(self._bitcoinconsensus_handle, self.generate_taproot_test_scripts())

    def test_p2sh_redeemscript(self) -> None:
        def T(required: int, total: int, alt_total: Optional[int] = None) -> None:
            amount = 10000
            keys = [CKey.from_secret_bytes(os.urandom(32))
                    for _ in range(total)]
            pubkeys = [k.pub for k in keys]

            if alt_total is not None:
                total = alt_total  # for assertRaises checks

            redeem_script = standard_multisig_redeem_script(
                total=total, required=required, pubkeys=pubkeys)

            # Test with P2SH

            scriptPubKey = redeem_script.to_p2sh_scriptPubKey()

            (_, tx) = self.create_test_txs(CScript(), scriptPubKey, CScript(),
                                           CScriptWitness([]), amount)

            tx = tx.to_mutable()

            sighash = redeem_script.sighash(tx, 0, SIGHASH_ALL,
                                            amount=amount,
                                            sigversion=SIGVERSION_BASE)

            sigs = [k.sign(sighash) + bytes([SIGHASH_ALL])
                    for k in keys[:required]]

            tx.vin[0].scriptSig = CScript(
                standard_multisig_witness_stack(sigs, redeem_script))

            VerifyScript(tx.vin[0].scriptSig, scriptPubKey, tx, 0,
                         (SCRIPT_VERIFY_P2SH,))

            # Test with P2WSH

            scriptPubKey = redeem_script.to_p2wsh_scriptPubKey()

            (_, tx) = self.create_test_txs(CScript(), scriptPubKey, CScript(),
                                           CScriptWitness([]), amount)

            tx = tx.to_mutable()

            sighash = redeem_script.sighash(tx, 0, SIGHASH_ALL,
                                            amount=amount,
                                            sigversion=SIGVERSION_WITNESS_V0)

            sigs = [k.sign(sighash) + bytes([SIGHASH_ALL])
                    for k in keys[:required]]

            witness_stack = standard_multisig_witness_stack(sigs, redeem_script)
            tx.vin[0].scriptSig = CScript([])
            tx.wit.vtxinwit[0] = CTxInWitness(CScriptWitness(witness_stack)).to_mutable()

            VerifyScript(tx.vin[0].scriptSig, scriptPubKey, tx, 0,
                         flags=(SCRIPT_VERIFY_WITNESS, SCRIPT_VERIFY_P2SH),
                         amount=amount,
                         witness=tx.wit.vtxinwit[0].scriptWitness)

            # Test with P2SH_P2WSH

            scriptPubKey = redeem_script.to_p2wsh_scriptPubKey()

            (_, tx) = self.create_test_txs(CScript(), scriptPubKey, CScript(),
                                           CScriptWitness([]), amount)

            tx = tx.to_mutable()

            sighash = redeem_script.sighash(tx, 0, SIGHASH_ALL,
                                            amount=amount,
                                            sigversion=SIGVERSION_WITNESS_V0)

            sigs = [k.sign(sighash) + bytes([SIGHASH_ALL])
                    for k in keys[:required]]

            witness_stack = standard_multisig_witness_stack(sigs, redeem_script)
            tx.vin[0].scriptSig = CScript([scriptPubKey])
            tx.wit.vtxinwit[0] = CTxInWitness(CScriptWitness(witness_stack)).to_mutable()

            VerifyScript(tx.vin[0].scriptSig,
                         scriptPubKey.to_p2sh_scriptPubKey(), tx, 0,
                         flags=(SCRIPT_VERIFY_WITNESS, SCRIPT_VERIFY_P2SH),
                         amount=amount,
                         witness=tx.wit.vtxinwit[0].scriptWitness)

        T(1, 3)
        T(2, 12)
        T(10, 13)
        T(11, 15)
        T(15, 15)

        with self.assertRaises(ValueError):
            T(1, 1)
            T(2, 1)
            T(1, 16)
            T(11, 11, alt_total=12)
            T(1, 3, alt_total=2)
