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

# pylama:ignore=C901,E221

from typing import (
    TypeVar, Tuple, List, Dict, Set, Union, Type, Any, Optional, Generator,
    NamedTuple, Callable, Collection
)

import base64
import struct
from enum import Enum
from collections import OrderedDict
from abc import abstractmethod

from .serialize import (
    BytesSerializer, VarIntSerializer, ByteStream_Type, SerializationError,
    SerializationTruncationError, ser_read, Serializable, ImmutableSerializable
)

import bitcointx.core

from . import (
    CTransaction, CTxIn, CTxOut, CTxInWitness, CTxWitness, b2x,
    CMutableTxIn, CMutableTxOut, CheckTransaction, MoneyRange,
    CheckTransactionError, CoreCoinParams
)
from .key import CPubKey, BIP32Path, KeyDerivationInfo, KeyStore
from .script import (
    CScript, CScriptWitness, SIGHASH_ALL, SIGHASH_Type,
    SIGVERSION_BASE, SIGVERSION_WITNESS_V0,
    ComplexScriptSignatureHelper, StandardMultisigSignatureHelper,
    standard_keyhash_scriptpubkey
)
from ..wallet import CCoinExtPubKey

from ..util import (
    ensure_isinstance, no_bool_use_as_property, assert_never,
    ClassMappingDispatcher, activate_class_dispatcher
)


class PSBT_CoinClassDispatcher(
    ClassMappingDispatcher, identity='psbt',
    depends=[bitcointx.core.CoreCoinClassDispatcher]
):
    ...


class PSBT_CoinClass(Serializable, metaclass=PSBT_CoinClassDispatcher):
    ...


class PSBT_BitcoinClassDispatcher(
    PSBT_CoinClassDispatcher,
    depends=[bitcointx.core.CoreBitcoinClassDispatcher]
):
    ...


class PSBT_BitcoinClass(PSBT_CoinClass, metaclass=PSBT_BitcoinClassDispatcher):

    @abstractmethod
    def _repr_dict(self) -> 'OrderedDict[str, str]':
        ...

    def __repr__(self) -> str:
        contents = ', '.join(f'{k}={v}' for k, v in self._repr_dict().items())
        return f"{self.__class__.__name__}({contents})"


PSBT_SEPARATOR = b'\x00'

PSBT_PROPRIETARY_TYPE = 0xFC


class PSBT_GlobalKeyType(Enum):
    UNSIGNED_TX = 0x00
    XPUB        = 0x01
    VERSION     = 0xFB


class PSBT_InKeyType(Enum):
    NON_WITNESS_UTXO    = 0x00
    WITNESS_UTXO        = 0x01
    PARTIAL_SIG         = 0x02
    SIGHASH_TYPE        = 0x03
    REDEEM_SCRIPT       = 0x04
    WITNESS_SCRIPT      = 0x05
    BIP32_DERIVATION    = 0x06
    FINAL_SCRIPTSIG     = 0x07
    FINAL_SCRIPTWITNESS = 0x08
    POR_COMMITMENT      = 0x09


class PSBT_OutKeyType(Enum):
    REDEEM_SCRIPT    = 0x00
    WITNESS_SCRIPT   = 0x01
    BIP32_DERIVATION = 0x02


PSBT_InputSignInfo = NamedTuple(
    'PSBT_InputSignInfo', [
        ('num_new_sigs', int),
        ('num_sigs_missing', int),
        ('is_final', bool)
    ])

PSBT_SignResult = NamedTuple(
    'PSBT_SignResult', [
        ('inputs_info', List[Optional[PSBT_InputSignInfo]]),
        ('num_inputs_signed', int),
        ('num_inputs_ready', int),
        ('num_inputs_final', int),
        ('is_ready', bool),
        ('is_final', bool)
    ])

PSBT_ProprietaryTypeData = NamedTuple(
    'PSBT_ProprietaryTypeData', [
        ('subtype', int), ('key_data', bytes), ('value', bytes)
    ])

PSBT_UnknownTypeData = NamedTuple(
    'PSBT_UnknownTypeData', [
        ('key_type', int), ('key_data', bytes), ('value', bytes)
    ])

T_KeyTypeEnum = TypeVar(
    'T_KeyTypeEnum', PSBT_GlobalKeyType, PSBT_OutKeyType, PSBT_InKeyType)


def proprietary_field_repr(
    prop_fields_dict: Dict[bytes, List[PSBT_ProprietaryTypeData]]
) -> str:
    def prop_str(p_list: List[PSBT_ProprietaryTypeData]) -> str:
        return ', '.join(
            f"({v.subtype}, x('{b2x(v.key_data)}'), x('{b2x(v.value)}'))"
            for v in p_list)

    return ', '.join(f"x('{b2x(k)}'): ({prop_str(v)})"
                     for k, v in prop_fields_dict.items())


def unknown_fields_repr(unknown_fields: List[PSBT_UnknownTypeData]) -> str:
    return ', '.join(
        f"({v.key_type}, x('{b2x(v.key_data)}'), x('{b2x(v.value)}'))"
        for v in unknown_fields)


def derivation_map_repr(
    derivation_map: Dict[CPubKey, 'PSBT_KeyDerivationInfo']
) -> str:
    return (', '.join(
        f"x('{b2x(k or b'')}'): (x('{b2x(v.master_fp)}'), "
        f"\"{str(v.path)}\")"
        for k, v in derivation_map.items()))


def merge_input_output_common_fields(
    dst: Union['PSBT_Input', 'PSBT_Output'],
    src: Union['PSBT_Input', 'PSBT_Output'],
    what: str
) -> None:
    if dst.index is None:
        dst.index = src.index
    elif src.index is not None and dst.index != src.index:
        raise ValueError(f'{what} indexes do not match')

    if not dst.redeem_script:
        dst.redeem_script = src.redeem_script
    elif src.redeem_script:
        if dst.redeem_script != src.redeem_script:
            raise ValueError(f'redeem scripts are different for {what}s'
                             f'at index {dst.index}')

    if not dst.witness_script:
        dst.witness_script = src.witness_script
    elif src.witness_script:
        if dst.witness_script != src.witness_script:
            raise ValueError(f'redeem scripts are different for {what}s'
                             f'at index {dst.index}')

    for pub, dinfo in src.derivation_map.items():
        if pub in dst.derivation_map:
            if dst.derivation_map[pub].master_fp != dinfo.master_fp:
                raise ValueError(
                    f'master fingerprint do not match in derivation info '
                    f'for {what}s at index {dst.index}')
            if tuple(dst.derivation_map[pub].path) != tuple(dinfo.path):
                raise ValueError(
                    f'derivation paths do not match in derivation info '
                    f'for {what}s at index {dst.index}')
            assert (dst.derivation_map[pub] == dinfo), \
                "if key_ids match, pubkeys must match"
        else:
            dst.derivation_map[CPubKey(pub)] = dinfo.clone()


def stream_serialize_field(
    key_type: Union[int, T_KeyTypeEnum],
    f: ByteStream_Type,
    key_data: bytes = b'',
    value: bytes = b''
) -> None:
    key_type_value = key_type if isinstance(key_type, int) else key_type.value
    key = VarIntSerializer.serialize(key_type_value) + key_data
    BytesSerializer.stream_serialize(key, f)
    BytesSerializer.stream_serialize(value, f)


def stream_serialize_proprietary_fields(
    proprietary_fields: Dict[bytes, List[PSBT_ProprietaryTypeData]],
    f: ByteStream_Type,
) -> None:
    for prefix in proprietary_fields.keys():
        for prop_data in proprietary_fields[prefix]:
            prop_key = (
                BytesSerializer.serialize(prefix)
                + VarIntSerializer.serialize(prop_data.subtype,
                                             allow_full_range=True)
                + prop_data.key_data
            )
            stream_serialize_field(PSBT_PROPRIETARY_TYPE, f,
                                   key_data=prop_key, value=prop_data.value)


def merge_proprietary_fields(
    proprietary_fields_dst: Dict[bytes, List[PSBT_ProprietaryTypeData]],
    proprietary_fields_src: Dict[bytes, List[PSBT_ProprietaryTypeData]],
    allow_duplicates: bool = False
) -> None:
    for prefix, propdata_list in proprietary_fields_src.items():
        if prefix not in proprietary_fields_dst:
            proprietary_fields_dst[prefix] = []

        dst_set: Set[PSBT_ProprietaryTypeData]

        if allow_duplicates:
            dst_set = set()
        else:
            dst_set = set(proprietary_fields_dst[prefix])

        for pd in propdata_list:
            if pd in dst_set:
                continue
            proprietary_fields_dst[prefix].append(
                PSBT_ProprietaryTypeData(subtype=pd.subtype,
                                         key_data=pd.key_data,
                                         value=pd.value))


def stream_serialize_unknown_fields(
    unknown_fields: List[PSBT_UnknownTypeData],
    f: ByteStream_Type,
) -> None:
    for unk_data in unknown_fields:
        stream_serialize_field(unk_data.key_type, f,
                               key_data=unk_data.key_data,
                               value=unk_data.value)


def merge_unknown_fields(
    unknown_fields_dst: List[PSBT_UnknownTypeData],
    unknown_fields_src: List[PSBT_UnknownTypeData],
    allow_duplicates: bool = False
) -> None:
    dst_set: Set[PSBT_UnknownTypeData]
    if allow_duplicates:
        dst_set = set()
    else:
        dst_set = set(unknown_fields_dst)
    for ud in unknown_fields_src:
        if ud in dst_set:
            continue
        unknown_fields_dst.append(
            PSBT_UnknownTypeData(key_type=ud.key_type,
                                 key_data=ud.key_data,
                                 value=ud.value))


def read_psbt_keymap(
    f: ByteStream_Type,
    keys_seen: Set[bytes],
    keys_enum_class: Type[T_KeyTypeEnum],
    proprietary_fields: Dict[bytes, List[PSBT_ProprietaryTypeData]],
    unknown_fields: List[PSBT_UnknownTypeData]
) -> Generator[Tuple[T_KeyTypeEnum, bytes, bytes], None, None]:
    while True:
        key_data = BytesSerializer.stream_deserialize(f)
        if not key_data:
            return

        if key_data in keys_seen:
            tellf = getattr(f, 'tell', lambda: '<untracked>')
            raise SerializationError(
                f'Duplicate key encountered at position {tellf()}')

        keys_seen.add(key_data)

        key_type, key_data = VarIntSerializer.deserialize_partial(
            key_data, allow_full_range=True)

        value = BytesSerializer.stream_deserialize(f)

        if key_type == PSBT_PROPRIETARY_TYPE:
            prefix, tail = BytesSerializer.deserialize_partial(key_data)
            subtype, key_data = VarIntSerializer.deserialize_partial(
                tail, allow_full_range=True)
            field = PSBT_ProprietaryTypeData(
                subtype=subtype, key_data=key_data, value=value)
            if prefix in proprietary_fields:
                proprietary_fields[prefix].append(field)
            else:
                proprietary_fields[prefix] = [field]

            continue

        try:
            kt = keys_enum_class(key_type)
        except ValueError:
            unknown_fields.append(
                PSBT_UnknownTypeData(key_type=key_type, key_data=key_data,
                                     value=value))
            continue

        yield kt, key_data, value


def ensure_empty_key_data(
    key_type: T_KeyTypeEnum, key_data: bytes, msg_suffix: str = ''
) -> None:
    if key_data:
        raise SerializationError(
            f'Unexpected data after key type {key_type.name}' + msg_suffix)


T_PSBT_KeyDerivationInfo = TypeVar('T_PSBT_KeyDerivationInfo',
                                   bound='PSBT_KeyDerivationInfo')


class PSBT_KeyDerivationInfo(ImmutableSerializable, KeyDerivationInfo):

    @classmethod
    def stream_deserialize(cls: Type[T_PSBT_KeyDerivationInfo],
                           f: ByteStream_Type,
                           _err_msg_suffix: str = '', **kwargs: Any
                           ) -> T_PSBT_KeyDerivationInfo:
        fingerprint = ser_read(f, 4)
        indexlist: List[int] = []
        while True:
            data = f.read(4)
            if len(data) < 4:
                if len(data):
                    raise SerializationTruncationError(
                        'Reached end of data while trying to read next '
                        'derivation index' + _err_msg_suffix)
                # reached end of data and have successfully read all indexes
                break

            indexlist.append(struct.unpack(b"<I", data)[0])

            if len(indexlist) > 255:
                raise ValueError(
                    'Derivation path longer than 255 elements'
                    + _err_msg_suffix)

        return cls(fingerprint, BIP32Path(indexlist, is_partial=False))

    def stream_serialize(self, f: ByteStream_Type, **kwargs: Any) -> None:
        f.write(self.master_fp)
        for index in self.path:
            f.write(struct.pack(b"<I", index))


T_PSBT_Input = TypeVar('T_PSBT_Input', bound='PSBT_Input')


class PSBT_Input(PSBT_CoinClass, next_dispatch_final=True):
    index: Optional[int]
    _utxo: Optional[Union[CTransaction, CTxOut]]
    _witness_utxo: Optional[CTxOut]
    partial_sigs: Dict[CPubKey, bytes]
    sighash_type: Optional[int]
    redeem_script: CScript
    witness_script: CScript
    derivation_map: Dict[CPubKey, PSBT_KeyDerivationInfo]
    final_script_sig: bytes
    final_script_witness: CScriptWitness
    proof_of_reserves_commitment: bytes
    proprietary_fields: Dict[bytes, List[PSBT_ProprietaryTypeData]]
    unknown_fields: List[PSBT_UnknownTypeData]
    # NOTE: if you add a field, don't forget to specify it in merge()

    def __init__(
        self, *,
        unsigned_tx: Optional[CTransaction] = None,
        utxo: Optional[Union[CTransaction, CTxOut]] = None,
        partial_sigs: Optional[Dict[CPubKey, bytes]] = None,
        sighash_type: Optional[int] = None,
        redeem_script: Optional[CScript] = None,
        witness_script: Optional[CScript] = None,
        derivation_map: Optional[Dict[CPubKey, PSBT_KeyDerivationInfo]] = None,
        final_script_sig: bytes = b'',
        final_script_witness: Optional[CScriptWitness] = None,
        proof_of_reserves_commitment: bytes = b'',
        proprietary_fields: Optional[Dict[
            bytes, List[PSBT_ProprietaryTypeData]
        ]] = None,
        unknown_fields: Optional[List[PSBT_UnknownTypeData]] = None,

        allow_unknown_sighash_types: bool = False,
        allow_convert_to_witness_utxo: bool = False,
        force_witness_utxo: bool = False,
        relaxed_sanity_checks: bool = False,
        index: Optional[int] = None,
    ) -> None:
        def descr(msg: str) -> str:
            if index is None:
                return msg
            return f'{msg} for input at index {index}'

        if index is not None:
            ensure_isinstance(index, int, 'index')
            if index < 0:
                raise ValueError('index is invalid or unspecified')

            if unsigned_tx and index >= len(unsigned_tx.vin):
                raise ValueError(
                    'index is beyond length of inputs of unsigned_tx')

        self.index = index

        if utxo is not None:
            ensure_isinstance(utxo, (CTransaction, CTxOut), descr('utxo'))
            if isinstance(utxo, CTxOut) and not utxo.is_valid():
                raise ValueError('Invalid CTxOut provided for utxo')
            if isinstance(utxo, CTransaction) and utxo.is_null():
                raise ValueError('Empty CTransaction provided for utxo')

        if partial_sigs is None:
            partial_sigs = OrderedDict()

        for pub, sig in partial_sigs.items():
            ensure_isinstance(
                pub, CPubKey,
                descr('pubkey for one of the partial signatures'))
            ensure_isinstance(sig, bytes,
                              descr('one of the partial signatures'))
        self.partial_sigs = partial_sigs

        if sighash_type is not None:
            ensure_isinstance(sighash_type, int, descr('sighash type'))
            if not allow_unknown_sighash_types:
                # SIGHASH_Type.__init__() will enforce that the value
                # is a supported type
                sighash_type = SIGHASH_Type(sighash_type)
            elif 2**32 <= sighash_type < 0:
                raise ValueError(descr('Sighash type out of range '))

        self.sighash_type = sighash_type

        if redeem_script is None:
            redeem_script = CScript()
        else:
            ensure_isinstance(redeem_script, CScript, descr('redeem script'))

        self.redeem_script = redeem_script

        if witness_script is None:
            witness_script = CScript()
        else:
            ensure_isinstance(witness_script, CScript, descr('witness script'))

        self.witness_script = witness_script

        if derivation_map is None:
            derivation_map = OrderedDict()

        for pub, derinfo in derivation_map.items():
            ensure_isinstance(pub, CPubKey,
                              descr('one of pubkeys in bip32 derivation map'))
            ensure_isinstance(
                derinfo, PSBT_KeyDerivationInfo,
                descr(f'derivation info for pubkey x(\'{b2x(pub)}\')'))

        self.derivation_map = derivation_map

        ensure_isinstance(final_script_sig, bytes, descr('final script sig'))
        self.final_script_sig = final_script_sig

        if final_script_witness is None:
            final_script_witness = CScriptWitness()
        else:
            ensure_isinstance(final_script_witness, CScriptWitness,
                              descr('final script witness'))

        self.final_script_witness = final_script_witness

        ensure_isinstance(proof_of_reserves_commitment,
                          bytes, descr('proof of reserves commitment'))
        self.proof_of_reserves_commitment = proof_of_reserves_commitment

        if proprietary_fields is None:
            proprietary_fields = OrderedDict()

        for prefix, p_fields in proprietary_fields.items():
            ensure_isinstance(prefix, bytes, descr('proprietary type prefix'))
            for field_index, field in enumerate(p_fields):
                ensure_isinstance(
                    field, PSBT_ProprietaryTypeData,
                    descr(f'one of proprietary field contents for '
                          f'prefix {b2x(prefix)}'))

        self.proprietary_fields = proprietary_fields

        if unknown_fields is None:
            unknown_fields = []

        for u_field in unknown_fields:
            ensure_isinstance(u_field, PSBT_UnknownTypeData,
                              descr('contents of unkown type'))
        self.unknown_fields = unknown_fields

        self._utxo = None
        self.set_utxo(utxo, unsigned_tx, force_witness_utxo=force_witness_utxo,
                      relaxed_sanity_checks=relaxed_sanity_checks)

        if allow_convert_to_witness_utxo and self._witness_utxo:
            self._utxo = self._witness_utxo

    @property
    def utxo(self) -> Optional[Union[CTransaction, CTxOut]]:
        """utxo as supplied at PSBT_Input creation"""
        return self._utxo

    def set_utxo(
        self,
        utxo: Optional[Union[CTransaction, CTxOut]],
        unsigned_tx: Optional[CTransaction],
        force_witness_utxo: bool = False,
        relaxed_sanity_checks: bool = False
    ) -> None:
        if utxo is not None:
            ensure_isinstance(utxo, (CTransaction, CTxOut), 'utxo')
        else:
            self._utxo = None
            self._witness_utxo = None
            return

        if unsigned_tx:
            ensure_isinstance(unsigned_tx, CTransaction, 'unsigned_tx')

        input_descr = ('input' if self.index is None
                       else f'input at index {self.index}')

        must_be_witness_utxo = force_witness_utxo
        wutxo_descr = 'as explicitly stated'

        if self.witness_script:
            must_be_witness_utxo = True
            wutxo_descr = 'because witness script is specified'

        if self.final_script_witness:
            must_be_witness_utxo = True
            wutxo_descr = 'because final script witness is specified'

        # Returns True if utxo should be definitely a witness utxo
        # Returns False otherwise
        # Performs consistency checks
        # (most checks are skipped when relaxed_sanity_checks=True)
        def check_witness_utxo_spk(spk: CScript) -> bool:
            rds = self.redeem_script
            if spk.is_witness_scriptpubkey():
                if self.redeem_script and not relaxed_sanity_checks:
                    raise ValueError(
                        f'redeem script is specified for {input_descr} '
                        f'with non-p2sh segwit prevout')
                return True
            elif rds:
                if spk.is_p2sh():
                    if rds.is_witness_scriptpubkey():
                        if rds.to_p2sh_scriptPubKey() != spk and \
                                not relaxed_sanity_checks:
                            raise ValueError(
                                f'redeem script is specified for p2sh '
                                f'{input_descr}, but it does not match '
                                f'the scriptPubKey')
                        return True
                    elif must_be_witness_utxo and not relaxed_sanity_checks:
                        raise ValueError(
                            f'{input_descr} is expected to be a witness UTXO, '
                            f'{wutxo_descr}, but the redeem script is not '
                            f'a witness scriptPubKey')
                    else:
                        return False
                elif not relaxed_sanity_checks:
                    raise ValueError(
                        f'{input_descr} has redeem script specified, '
                        f'but has non-p2sh scriptPubKey')
                else:
                    return False
            elif spk.is_p2sh():
                return must_be_witness_utxo

            if must_be_witness_utxo and not relaxed_sanity_checks:
                raise ValueError(
                    f'{input_descr} is expected to be a witness UTXO, '
                    f'{wutxo_descr}, but it has the scriptPubKey that is not '
                    f'a witness scriptPubKey nor a P2SH scriptPubKey')

            return False

        if isinstance(utxo, CTxOut):
            must_be_witness_utxo = True  # explicitly witness, by being CTxOut
            check_witness_utxo_spk(utxo.scriptPubKey)
            self._utxo = utxo
            self._witness_utxo = utxo
            return

        assert isinstance(utxo, CTransaction)

        if self.index is None or unsigned_tx is None:
            if must_be_witness_utxo:
                what_is_missing = ('unsigned_tx' if unsigned_tx is None
                                   else 'input index')
                raise ValueError(
                    f'cannot convert non-witness utxo to witness utxo, '
                    f'{what_is_missing} is not present')
            # cannot convert without index or unsigned_tx,
            # even if it was a witness utxo, we cannot know
            self._utxo = utxo
            self._witness_utxo = None
            return

        txin = unsigned_tx.vin[self.index]
        if txin.prevout.n >= len(utxo.vout):
            raise ValueError(
                f'{input_descr} prevout index in unsigned_tx is beyond the '
                f'length of utxo.vout')

        txid = utxo.GetTxid()
        if txid != txin.prevout.hash and not relaxed_sanity_checks:
            raise ValueError(
                f'txid of the transaction provided in utxo field for '
                f'segwit {input_descr} does not match '
                f'prevout hash of the input')

        prev_txout = utxo.vout[txin.prevout.n]

        if check_witness_utxo_spk(prev_txout.scriptPubKey):
            self._witness_utxo = prev_txout
        else:
            self._witness_utxo = None

        self._utxo = utxo

    @property
    def non_witness_utxo(self) -> Optional[CTransaction]:
        if self._witness_utxo:
            return None
        assert self._utxo is None or isinstance(self._utxo, CTransaction)
        return self._utxo

    @property
    def witness_utxo(self) -> Optional[CTxOut]:
        return self._witness_utxo

    @classmethod
    def from_instance(cls: Type[T_PSBT_Input],
                      inst: T_PSBT_Input
                      ) -> T_PSBT_Input:
        new_inst = cls()
        new_inst.merge(inst, allow_blob_duplicates=True)
        return new_inst

    def clone(self: T_PSBT_Input) -> T_PSBT_Input:
        return self.__class__.from_instance(self)

    def _check_sanity(self, unsigned_tx: CTransaction) -> None:
        if not (self.final_script_sig or self.final_script_witness):
            nonfinal_fields = self._get_nonfinal_fields_present()
            if not nonfinal_fields and not self.utxo:
                return

        # try to sign with empty keystore,
        # this would do all the required sanity checks on the components.
        self.sign(unsigned_tx, KeyStore(), finalize=False)

    def merge(self: T_PSBT_Input, other: T_PSBT_Input,
              allow_blob_duplicates: bool = False) -> None:

        # checks index fields, so need to be first
        merge_input_output_common_fields(self, other, 'input')

        if not self.utxo:
            self._utxo = other._utxo
            assert self._witness_utxo is None
            self._witness_utxo = other._witness_utxo
        elif not other.utxo:
            assert other._witness_utxo is None
        elif not self.witness_utxo and not other.witness_utxo:
            assert isinstance(self.utxo, CTransaction)
            assert isinstance(other.utxo, CTransaction)
            if self.utxo.GetTxid() != other.utxo.GetTxid():
                raise ValueError(
                    f'inputs at index {self.index} have non-witness utxos '
                    f'with different txids')
        elif not self.witness_utxo and other.witness_utxo:
            assert isinstance(self.utxo, CTransaction)
            # The witness utxo wins, but we check consistency first
            for vout in self.utxo.vout:
                if vout.serialize() == other.witness_utxo.serialize():
                    break
            else:
                raise ValueError(
                    f'witness utxo (CTxOut) in in merge source at index '
                    f'{other.index} does not exist in outputs of '
                    f'non-witness utxo (CTransaction) of the '
                    f'merge destination')

            # The witness utxo wins
            if self.utxo.is_mutable():
                self._utxo = other.utxo.to_mutable()
                self._witness_utxo = other.witness_utxo.to_mutable()
            else:
                self._utxo = other.utxo.to_immutable()
                self._witness_utxo = other.witness_utxo.to_immutable()
        elif self.witness_utxo and not other.witness_utxo:
            assert isinstance(other.utxo, CTransaction)
            # The witness utxo wins, but we check consistency first
            for vout in other.utxo.vout:
                if vout.serialize() == self.witness_utxo.serialize():
                    break
            else:
                raise ValueError(
                    f'witness utxo (CTxOut) in in merge destination '
                    f'at index {self.index} does not exist in outputs of '
                    f'non-witness utxo (CTransaction) of the merge source')
        elif self.witness_utxo and other.witness_utxo:
            if self.witness_utxo.serialize() != other.witness_utxo.serialize():
                raise ValueError(
                    f'witness utxos are different for inputs '
                    f'at index {self.index}')
            if isinstance(self.utxo, CTxOut) and \
                    isinstance(other.utxo, CTransaction):
                # Other utxo has more information (full tx)
                if self.utxo.is_mutable():
                    self._utxo = other.utxo.to_mutable()
                    self._witness_utxo = other.witness_utxo.to_mutable()
                else:
                    self._utxo = other.utxo.to_immutable()
                    self._witness_utxo = other.witness_utxo.to_immutable()
            else:
                assert isinstance(self.utxo, CTransaction) or \
                    isinstance(other.utxo, CTxOut)
        else:
            raise AssertionError(
                'should not happen, all variants of witness/nonwitness utxo '
                'combinations should have been checked')

        for pub, sig in other.partial_sigs.items():
            if pub not in self.partial_sigs:
                self.partial_sigs[pub] = sig

        if self.sighash_type is None:
            self.sighash_type = other.sighash_type
        elif other.sighash_type is not None:
            if self.sighash_type != other.sighash_type:
                raise ValueError(f'sighash types are different for inputs'
                                 f'at index {self.index}')

        if not self.final_script_sig:
            self.final_script_sig = other.final_script_sig

        if not self.final_script_witness:
            self.final_script_witness = other.final_script_witness

        # should we check if commitments match when present in both instnaces ?
        if not self.proof_of_reserves_commitment:
            self.proof_of_reserves_commitment = \
                other.proof_of_reserves_commitment

        merge_proprietary_fields(self.proprietary_fields,
                                 other.proprietary_fields,
                                 allow_duplicates=allow_blob_duplicates)
        merge_unknown_fields(self.unknown_fields, other.unknown_fields,
                             allow_duplicates=allow_blob_duplicates)

    @no_bool_use_as_property
    def is_null(self) -> bool:
        return (
            self.utxo is None
            and (not self.partial_sigs)
            and (not self.redeem_script)
            and (not self.witness_script)
            and (not self.derivation_map)
            and (not self.final_script_sig)
            and (not self.final_script_witness)
            and (not self.proprietary_fields)
            and (not self.unknown_fields)
        )

    def _get_nonfinal_fields_present(self) -> Optional[List[str]]:
        fields = []

        if self.partial_sigs:
            fields.append('partial_sigs')
        if self.redeem_script:
            fields.append('redeem_script')
        if self.witness_script:
            fields.append('witness_script')
        if self.derivation_map:
            fields.append('derivation_map')

        return fields

    def _check_nonfinal_fields_empty(self) -> None:
        nonfinal_fields = self._get_nonfinal_fields_present()
        if nonfinal_fields:
            raise ValueError(
                f'non-final fields: ({", ".join(nonfinal_fields)}) is present '
                f'in finalized PSBT_Input')

    def _clear_nonfinal_fields(self) -> None:
        self.partial_sigs = OrderedDict()
        self.redeem_script = CScript()
        self.witness_script = CScript()
        self.derivation_map = OrderedDict()

    def _got_single_sig(self, pub: CPubKey, sig: bytes, *,
                        is_witness: bool = True,
                        script_sig_for_witness: Optional[CScript] = None,
                        finalize: bool = True
                        ) -> PSBT_InputSignInfo:
        if self.final_script_sig or self.final_script_witness:
            raise AssertionError(
                f'trying to sign already finalized input '
                f'at index {self.index}')
        if finalize:
            if self.sighash_type is not None and sig[-1] != self.sighash_type:
                raise ValueError(
                    f'sighash_type ({self.sighash_type}) specified for '
                    f'input {self.index} does not match the '
                    f'last byte of the signature')
            if is_witness:
                assert script_sig_for_witness is not None
                self.final_script_sig = script_sig_for_witness
                self.final_script_witness = CScriptWitness([sig, pub])
            else:
                self.final_script_sig = CScript([sig, pub])
            self._clear_nonfinal_fields()
        elif pub not in self.partial_sigs:
            self.partial_sigs[pub] = sig

        return PSBT_InputSignInfo(num_new_sigs=1, num_sigs_missing=0,
                                  is_final=finalize)

    def _maybe_sign_complex_script(
        self,
        msig_helper: ComplexScriptSignatureHelper,
        signer: Callable[[CPubKey], Optional[bytes]],
        *,
        is_witness: bool = True,
        script_sig_for_witness: Optional[CScript] = None,
        finalize: bool = True
    ) -> PSBT_InputSignInfo:

        new_sigs, is_ready = msig_helper.sign(signer, self.partial_sigs)

        if is_ready:
            if finalize:
                if is_witness:
                    assert script_sig_for_witness is not None
                    self.final_script_sig = script_sig_for_witness
                    self.final_script_witness = \
                        CScriptWitness(msig_helper.construct_witness_stack())
                else:
                    self.final_script_sig = \
                        CScript(msig_helper.construct_witness_stack())
                self._clear_nonfinal_fields()
            elif new_sigs:
                self.partial_sigs.update(new_sigs)

            return PSBT_InputSignInfo(num_new_sigs=len(new_sigs),
                                      num_sigs_missing=0,
                                      is_final=finalize)

        assert msig_helper.num_sigs_missing() > 0
        assert set(self.partial_sigs).isdisjoint(set(new_sigs))
        self.partial_sigs.update(new_sigs)

        return PSBT_InputSignInfo(
            num_new_sigs=len(new_sigs),
            num_sigs_missing=msig_helper.num_sigs_missing(),
            is_final=False)

    def _get_derinfo_by_key_id(self, key_id: bytes
                               ) -> Optional['PSBT_KeyDerivationInfo']:
        for pub, derinfo in self.derivation_map.items():
            if pub.key_id == key_id:
                return derinfo
        return None

    @no_bool_use_as_property
    def is_final(self) -> bool:
        utxo = self.witness_utxo or self.utxo

        if self.final_script_witness:
            if not isinstance(utxo, CTxOut):
                inp_descr = ("input without utxo specified" if utxo is None
                             else "non-segwit input")
                raise ValueError(
                    f'final_script_witness is present for {inp_descr}')
            self._check_nonfinal_fields_empty()
            if self.final_script_sig:
                if utxo.scriptPubKey.is_witness_scriptpubkey():
                    raise ValueError(
                        'final_script_sig is present for native segwit input')
            elif utxo.scriptPubKey.is_p2sh():
                raise ValueError(
                    'final_script_sig is not present for p2sh-wrapped '
                    'segwit input')
            return True

        if self.final_script_sig:
            self._check_nonfinal_fields_empty()
            return True

        return False

    def sign(self,
             unsigned_tx: CTransaction,
             key_store: KeyStore, *,
             complex_script_helper_factory: Callable[
                 [CScript], ComplexScriptSignatureHelper
             ] = StandardMultisigSignatureHelper.__call__,
             finalize: bool = True
             ) -> Optional[PSBT_InputSignInfo]:
        """Sign the input using keys available from `key_store`.
        `complex_script_helper_factory`, given the script, should return
        an instance of appropriate `ComplexScriptSignatureHelper` subclass
        that is capable of signing particular complex script,
        or raise `ValueError` if it cannot return such an instance."""

        sighash: Optional[bytes] = None

        assert self.sighash_type != 0, \
            "unspecified sighash_type must be represented by None"

        if self.is_final():
            return PSBT_InputSignInfo(num_new_sigs=0, num_sigs_missing=0,
                                      is_final=True)

        if self.index is None:
            return None  # Not signable, cannot know the prevout

        utxo = self.witness_utxo or self.utxo

        if utxo is None:
            return None  # Not signable, we don't have utxo at all

        def signer(pub: CPubKey) -> Optional[bytes]:
            assert sighash is not None
            derinfo = self.derivation_map.get(pub)
            key = key_store.get_privkey(pub.key_id, derinfo)
            if key:
                return key.sign(sighash) + bytes([sighash_type])
            return None

        # SIGHASH_Type.__init__() will enforce that the value
        # is a supported type
        sighash_type = SIGHASH_Type(self.sighash_type or SIGHASH_ALL)

        rds = self.redeem_script
        ws = self.witness_script

        if isinstance(utxo, CTxOut):  # witness UTXO
            if not MoneyRange(utxo.nValue):
                raise ValueError(
                    f'prevout for input at index {self.index} has value '
                    f'out of valid range')
            spk = utxo.scriptPubKey
            if spk.is_witness_scriptpubkey():
                input_descr = 'segwit native'
                if rds:
                    raise ValueError(
                        f'redeem script is specified for {input_descr} input '
                        f'at index {self.index}')
                script_sig = CScript()
                s = spk
            elif spk.is_p2sh() and rds and rds.is_witness_scriptpubkey():
                input_descr = 'p2sh-wrapped segwit'
                if rds.to_p2sh_scriptPubKey() != spk:
                    raise ValueError(
                        f'redeem script for {input_descr} '
                        f'input at index {self.index} does not match '
                        f'the scriptPubKey')
                script_sig = CScript([rds])
                s = rds
            elif spk.is_p2sh() and not rds:
                return None  # redeem script is not specified, cannot sign.
            else:
                raise ValueError(
                    f'input at index {self.index} specified as '
                    f'witness UTXO, but has non-witness scriptPubKey')

            def calc_sighash(script_for_sighash: CScript) -> bytes:
                assert self.index is not None
                assert isinstance(utxo, CTxOut)
                return script_for_sighash.sighash(
                    unsigned_tx, self.index, SIGHASH_Type(sighash_type),
                    amount=utxo.nValue,
                    sigversion=SIGVERSION_WITNESS_V0)

            derinfo: Optional[PSBT_KeyDerivationInfo]

            if s.is_witness_v0_keyhash():
                if ws:
                    raise ValueError(
                        f'witness script is specified for {input_descr} '
                        f'p2wpkh input at index {self.index}')

                sighash = calc_sighash(
                    standard_keyhash_scriptpubkey(s.pubkey_hash()))

                if self.partial_sigs:
                    if len(self.partial_sigs) > 1:
                        raise ValueError(
                            f'more than one signature in partial_sigs '
                            f'for p2wpkh input at index {self.index}')
                    pub = list(self.partial_sigs)[0]
                    if s.pubkey_hash() != pub.key_id:
                        raise ValueError(
                            f'the pubkey in partial_sigs for p2wpkh input '
                            f'at index {self.index} does not match the '
                            f'keyhash for the input')
                    return self._got_single_sig(
                        pub, self.partial_sigs[pub], is_witness=True,
                        script_sig_for_witness=script_sig, finalize=finalize)

                key_id = s.pubkey_hash()
                derinfo = self._get_derinfo_by_key_id(key_id)
                key = key_store.get_privkey(key_id, derinfo)
                if key:
                    sig = key.sign(sighash) + bytes([sighash_type])
                    return self._got_single_sig(
                        key.pub, sig, is_witness=True,
                        script_sig_for_witness=script_sig, finalize=finalize)
                return PSBT_InputSignInfo(num_new_sigs=0, num_sigs_missing=1,
                                          is_final=False)
            elif s.is_witness_v0_scripthash():
                if not ws:
                    raise ValueError(
                        f'witness script is not specified for {input_descr} '
                        f'p2wsh input at index {self.index}')

                if rds and ws.to_p2wsh_scriptPubKey() != rds:
                    raise ValueError(
                        f'witness script for {input_descr} '
                        f'p2wpkh input at index {self.index} does not match '
                        f'the redeem script')

                sighash = calc_sighash(ws)

                try:
                    msig_helper = complex_script_helper_factory(ws)
                except ValueError:
                    return None

                return self._maybe_sign_complex_script(
                    msig_helper, signer, is_witness=True,
                    script_sig_for_witness=script_sig, finalize=finalize)
            else:
                return None  # unknown scriptpubkey type, cannot sign

        elif isinstance(utxo, CTransaction):  # non-witness UTXO
            if utxo.GetTxid() != unsigned_tx.vin[self.index].prevout.hash:
                raise ValueError(
                    f'txid of the transaction provided in utxo field for '
                    f'non-segwit input at index {self.index} does not match '
                    f'prevout hash of the input')
            if ws:
                raise ValueError(
                    f'witness script is specified for non-segwit input '
                    f'at index {self.index}')

            prevout_index = unsigned_tx.vin[self.index].prevout.n

            if prevout_index >= len(utxo.vout):
                raise ValueError(
                    'prevout index in unsigned_tx is beyond the '
                    'length of utxo.vout')

            prev_txout = utxo.vout[prevout_index]
            if not MoneyRange(prev_txout.nValue):
                raise ValueError(
                    f'prevout for input at index {self.index} has value '
                    f'out of valid range')

            spk = prev_txout.scriptPubKey

            if spk.is_witness_scriptpubkey():
                raise ValueError(
                    f'witness scritpubkey is found for non-witness UTXO '
                    f'at index {self.index}')

            def calc_sighash(script_for_sighash: CScript) -> bytes:
                assert self.index is not None
                return script_for_sighash.sighash(
                    unsigned_tx, self.index, SIGHASH_Type(sighash_type),
                    sigversion=SIGVERSION_BASE)

            if spk.is_p2pkh():
                if rds:
                    raise ValueError(
                        f'redeem script is specified for p2pkh input '
                        f'at index {self.index}')

                sighash = calc_sighash(spk)

                if self.partial_sigs:
                    if len(self.partial_sigs) > 1:
                        raise ValueError(
                            f'more than one signature in partial_sigs '
                            f'for p2pkh input at index {self.index}')
                    pub = list(self.partial_sigs)[0]
                    if spk.pubkey_hash() != pub.key_id:
                        raise ValueError(
                            f'the pubkey in partial_sigs for p2pkh input '
                            f'at index {self.index} does not match the '
                            f'keyhash for the input')
                    return self._got_single_sig(pub, self.partial_sigs[pub],
                                                is_witness=False,
                                                finalize=finalize)

                key_id = spk.pubkey_hash()
                derinfo = self._get_derinfo_by_key_id(key_id)
                key = key_store.get_privkey(key_id, derinfo)
                if key:
                    sig = key.sign(sighash) + bytes([sighash_type])
                    return self._got_single_sig(key.pub, sig,
                                                is_witness=False,
                                                finalize=finalize)
                return PSBT_InputSignInfo(num_new_sigs=0, num_sigs_missing=1,
                                          is_final=False)
            elif spk.is_p2sh():
                if not rds:
                    return None  # redeem script is not specified, cannot sign.

                if rds.to_p2sh_scriptPubKey() != spk:
                    raise ValueError(
                        f'redeem script for input at index {self.index} '
                        f'does not match scriptPubKey in UTXO')

                sighash = calc_sighash(rds)

                try:
                    msig_helper = complex_script_helper_factory(rds)
                except ValueError:
                    return None

                return self._maybe_sign_complex_script(
                    msig_helper, signer, is_witness=False, finalize=finalize)
            else:
                # unknown scriptpubkey type (maybe bare pubkey) cannot sign
                return None
        else:
            raise AssertionError(
                f'type of UTXO in PSBT input at index {self.index} '
                f'is expected to be CTxOut or CTransaction, '
                f'but is actually {utxo.__class__.name}')

        return None

    @classmethod
    def stream_deserialize(cls: Type[T_PSBT_Input], f: ByteStream_Type,
                           unsigned_tx: Optional[CTransaction] = None,
                           index: Optional[int] = None,
                           **kwargs: Any) -> T_PSBT_Input:

        partial_sigs: Dict[CPubKey, bytes] = OrderedDict()
        sighash_type: Optional[int] = None
        redeem_script: CScript = CScript()
        witness_script: CScript = CScript()
        derivation_map: Dict[CPubKey, PSBT_KeyDerivationInfo] = OrderedDict()
        final_script_sig: bytes = b''
        final_script_witness: CScriptWitness = CScriptWitness()
        proof_of_reserves_commitment: bytes = b''
        proprietary_fields: Dict[
            bytes, List[PSBT_ProprietaryTypeData]
        ] = OrderedDict()
        unknown_fields: List[PSBT_UnknownTypeData] = []

        def descr(msg: str) -> str:
            return f'{msg} for input at index {index}'

        def check_witness_and_nonwitness_utxo_in_sync(
            witness_utxo: CTxOut, non_witness_utxo: CTransaction,
        ) -> None:
            if index is None or unsigned_tx is None:
                raise ValueError(descr(
                    'both witness and non-witness UTXO fields '
                    'are present in PSBT input, but index and unsigned_tx '
                    'arguments are not supplied. This makes it impossible '
                    'to check that these fields are in-sync'))

            prevout_index = unsigned_tx.vin[index].prevout.n

            if prevout_index >= len(non_witness_utxo.vout):
                raise SerializationError(descr(
                    'prevout index in unsigned_tx is beyond the '
                    'length of outputs array of non-witness UTXO'))

            txout = non_witness_utxo.vout[prevout_index]
            if witness_utxo.serialize() != txout.serialize():
                raise SerializationError(descr(
                    'both witness and non-witness UTXO fields are supplied, '
                    'but witness utxo is not equal to the corresponding '
                    'output in the transaction given for non-witness utxo'))

        witness_utxo: Optional[CTxOut] = None
        non_witness_utxo: Optional[CTransaction] = None
        keys_seen: Set[bytes] = set()
        for key_type, key_data, value in \
                read_psbt_keymap(f, keys_seen, PSBT_InKeyType,
                                 proprietary_fields, unknown_fields):

            if key_type is PSBT_InKeyType.NON_WITNESS_UTXO:
                ensure_empty_key_data(key_type, key_data, descr(''))
                non_witness_utxo = CTransaction.deserialize(value)
                if witness_utxo is not None:
                    check_witness_and_nonwitness_utxo_in_sync(
                        witness_utxo, non_witness_utxo)
            elif key_type is PSBT_InKeyType.WITNESS_UTXO:
                ensure_empty_key_data(key_type, key_data, descr(''))
                witness_utxo = CTxOut.deserialize(value)
                if non_witness_utxo is not None:
                    check_witness_and_nonwitness_utxo_in_sync(
                        witness_utxo, non_witness_utxo)
            elif key_type is PSBT_InKeyType.PARTIAL_SIG:
                pub = CPubKey(key_data)
                if not pub.is_fullyvalid():
                    raise SerializationError(
                        descr(
                            f'Invalid pubkey encountered in {key_type.name}'))
                assert pub not in partial_sigs, \
                    ("duplicate keys should have been catched "
                     "inside read_psbt_keymap()")
                partial_sigs[pub] = value
            elif key_type is PSBT_InKeyType.SIGHASH_TYPE:
                ensure_empty_key_data(key_type, key_data, descr(''))
                if len(value) != 4:
                    raise SerializationError(
                        descr(f'Incorrect data length for {key_type.name}'))
                sighash_type = struct.unpack(b"<I", value)[0]
            elif key_type is PSBT_InKeyType.REDEEM_SCRIPT:
                ensure_empty_key_data(key_type, key_data, descr(''))
                redeem_script = CScript(value)
            elif key_type is PSBT_InKeyType.WITNESS_SCRIPT:
                ensure_empty_key_data(key_type, key_data, descr(''))
                witness_script = CScript(value)
            elif key_type is PSBT_InKeyType.BIP32_DERIVATION:
                pub = CPubKey(key_data)
                if not pub.is_fullyvalid():
                    raise SerializationError(
                        descr(
                            f'Invalid pubkey encountered in {key_type.name}'))
                assert pub not in derivation_map, \
                    ("duplicate keys should have been catched "
                     "inside read_psbt_keymap()")
                derivation_map[pub] = PSBT_KeyDerivationInfo.deserialize(value)
            elif key_type is PSBT_InKeyType.FINAL_SCRIPTSIG:
                ensure_empty_key_data(key_type, key_data, descr(''))
                final_script_sig = value
            elif key_type is PSBT_InKeyType.FINAL_SCRIPTWITNESS:
                ensure_empty_key_data(key_type, key_data, descr(''))
                final_script_witness = CScriptWitness.deserialize(value)
            elif key_type is PSBT_InKeyType.POR_COMMITMENT:
                ensure_empty_key_data(key_type, key_data, descr(''))
                proof_of_reserves_commitment = value
            else:
                assert_never(key_type)

        # non_witness_utxo is preferred over witness_utxo for `utxo` kwarg
        # because non_witness_utxo is a full transaction,
        # that may contain the witness utxo.
        #
        # If the case when non_witness_utxo contains the witness_utxo,
        # we have checked that the CTxOut presented in WITNESS_UTXO was
        # in fact in-sync with transaction present in NON_WITNESS_UTXO.
        # The logic in set_utxo() will extract the witness utxo and
        # will use it. There are cases when set_utxo() cannot detect
        # 'witness-ness' of the utxo. To handle this cases, we also supply
        # force_witness_utxo boolean kwarg
        return cls(utxo=non_witness_utxo or witness_utxo,
                   partial_sigs=partial_sigs,
                   unsigned_tx=unsigned_tx,
                   sighash_type=sighash_type,
                   redeem_script=redeem_script, witness_script=witness_script,
                   derivation_map=derivation_map,
                   final_script_sig=final_script_sig,
                   final_script_witness=final_script_witness,
                   proof_of_reserves_commitment=proof_of_reserves_commitment,
                   proprietary_fields=proprietary_fields,
                   unknown_fields=unknown_fields,
                   index=index, force_witness_utxo=bool(witness_utxo),
                   **kwargs)

    def stream_serialize(self, f: ByteStream_Type,
                         always_include_witness_utxo: bool = True,
                         **kwargs: Any) -> None:
        if self.utxo is not None:
            if isinstance(self.utxo, CTransaction):
                assert not self.utxo.is_null()
                stream_serialize_field(PSBT_InKeyType.NON_WITNESS_UTXO, f,
                                       value=self.utxo.serialize())
                # This may be non-segwit input, or the segwit input that
                # retains full transaction. Full transaction will be serialized
                # as NON_WITNESS_UTXO, and if this is a segwit input,
                # the CTxOut will be additionally serialized as WITNESS_UTXO
                # (unless always_include_witness_utxo is False)
                include_witness_utxo = always_include_witness_utxo
            else:
                include_witness_utxo = True

            if self.witness_utxo and include_witness_utxo:
                assert self.witness_utxo.is_valid()
                stream_serialize_field(PSBT_InKeyType.WITNESS_UTXO, f,
                                       value=self.witness_utxo.serialize())

        if not self.final_script_sig and not self.final_script_witness:
            for pub, sig in self.partial_sigs.items():
                stream_serialize_field(PSBT_InKeyType.PARTIAL_SIG, f,
                                       key_data=pub, value=sig)

            if self.sighash_type is not None:
                stream_serialize_field(
                    PSBT_InKeyType.SIGHASH_TYPE, f,
                    value=struct.pack(b"<I", self.sighash_type))

            if self.redeem_script:
                stream_serialize_field(PSBT_InKeyType.REDEEM_SCRIPT, f,
                                       value=self.redeem_script)

            if self.witness_script:
                stream_serialize_field(PSBT_InKeyType.WITNESS_SCRIPT, f,
                                       value=self.witness_script)

            for pub, dinfo in self.derivation_map.items():
                assert isinstance(pub, CPubKey) and pub.is_fullyvalid()
                stream_serialize_field(PSBT_InKeyType.BIP32_DERIVATION, f,
                                       key_data=pub, value=dinfo.serialize())

        if self.final_script_sig:
            stream_serialize_field(PSBT_InKeyType.FINAL_SCRIPTSIG, f,
                                   value=self.final_script_sig)

        if self.final_script_witness:
            stream_serialize_field(PSBT_InKeyType.FINAL_SCRIPTWITNESS, f,
                                   value=self.final_script_witness.serialize())

        if self.proof_of_reserves_commitment:
            stream_serialize_field(PSBT_InKeyType.POR_COMMITMENT, f,
                                   value=self.proof_of_reserves_commitment)

        stream_serialize_proprietary_fields(self.proprietary_fields, f)
        stream_serialize_unknown_fields(self.unknown_fields, f)

        f.write(PSBT_SEPARATOR)

    def get_amount(self, unsigned_tx: Optional[CTransaction]) -> int:
        if self.witness_utxo:
            return self.witness_utxo.nValue

        assert isinstance(self.utxo, CTransaction)
        if not unsigned_tx:
            raise ValueError(
                'cannot get input amount without associated unsigned_tx '
                'because we need prevout.n from there')

        if self.index is None:
            raise ValueError('index field is not set on PSBT_Input, '
                             ' cannot know which CTxIn to access')

        prevout_index = unsigned_tx.vin[self.index].prevout.n

        if prevout_index >= len(self.utxo.vout):
            raise ValueError(
                'prevout index in unsigned_tx is beyond the '
                'length of utxo.vout')

        return self.utxo.vout[prevout_index].nValue

    def _repr_dict(self) -> 'OrderedDict[str, str]':
        partial_sigs = (', '.join(f"x('{b2x(k)}'): x('{b2x(v)}')"
                                  for k, v in self.partial_sigs.items()))
        return OrderedDict({
            'utxo': f'{self.utxo}',
            'partial_sigs': f'{{{partial_sigs}}}',
            'sighash_type': f'{self.sighash_type}',
            'redeem_script': repr(self.redeem_script),
            'witness_script': repr(self.witness_script),
            'derivation_map':
                f'{{{derivation_map_repr(self.derivation_map)}}}',
            'final_script_sig': f"x('{b2x(self.final_script_sig)}')",
            'final_script_witness': repr(self.final_script_witness),
            'proof_of_reserves_commitment':
                f"x('{b2x(self.proof_of_reserves_commitment)}')",
            'proprietary_fields':
                f"{{{proprietary_field_repr(self.proprietary_fields)}}}",
            'unknown_fields': f'[{unknown_fields_repr(self.unknown_fields)}]'
        })


class PSBT_BitcoinInput(PSBT_Input, PSBT_BitcoinClass):
    ...


T_PSBT_Output = TypeVar('T_PSBT_Output', bound='PSBT_Output')


class PSBT_Output(PSBT_CoinClass, next_dispatch_final=True):
    index: Optional[int]
    redeem_script: CScript
    witness_script: CScript
    derivation_map: Dict[CPubKey, PSBT_KeyDerivationInfo]
    proprietary_fields: Dict[bytes, List[PSBT_ProprietaryTypeData]]
    unknown_fields: List[PSBT_UnknownTypeData]
    # NOTE: if you add a field, don't forget to specify it in merge()

    def __init__(
        self, *,
        redeem_script: Optional[CScript] = None,
        witness_script: Optional[CScript] = None,
        derivation_map: Optional[Dict[CPubKey, PSBT_KeyDerivationInfo]] = None,
        proprietary_fields: Optional[Dict[
            bytes, List[PSBT_ProprietaryTypeData]
        ]] = None,
        unknown_fields: Optional[List[PSBT_UnknownTypeData]] = None,
        index: Optional[int] = None
    ) -> None:
        def descr(msg: str) -> str:
            if index is None:
                return msg
            return f'{msg} for output at index {index}'

        if index is not None:
            if index < 0:
                raise ValueError('index is invalid or unspecified')

        self.index = index

        if redeem_script is None:
            redeem_script = CScript()
        else:
            ensure_isinstance(redeem_script, CScript, descr('redeem script'))

        self.redeem_script = redeem_script

        if witness_script is None:
            witness_script = CScript()
        else:
            ensure_isinstance(witness_script, CScript, descr('witness script'))

        self.witness_script = witness_script

        if derivation_map is None:
            derivation_map = OrderedDict()

        for pub, derinfo in derivation_map.items():
            ensure_isinstance(pub, CPubKey,
                              descr('one of pubkeys in bip32 derivation map'))
            ensure_isinstance(
                derinfo, PSBT_KeyDerivationInfo,
                descr(f'derivation info for pubkey x(\'{b2x(pub)}\')'))

        self.derivation_map = derivation_map

        if proprietary_fields is None:
            proprietary_fields = OrderedDict()

        for prefix, p_fields in proprietary_fields.items():
            ensure_isinstance(prefix, bytes, descr('proprietary type prefix'))
            for field_index, field in enumerate(p_fields):
                ensure_isinstance(
                    field, PSBT_ProprietaryTypeData,
                    descr(f'one of proprietary field contents for '
                          f'prefix {b2x(prefix)}'))

        self.proprietary_fields = proprietary_fields

        if unknown_fields is None:
            unknown_fields = []

        for u_field in unknown_fields:
            ensure_isinstance(u_field, PSBT_UnknownTypeData,
                              descr('contents of unkown type'))
        self.unknown_fields = unknown_fields

    @no_bool_use_as_property
    def is_null(self) -> bool:
        return (
            (not self.redeem_script)
            and (not self.witness_script)
            and (not self.derivation_map)
            and (not self.proprietary_fields)
            and (not self.unknown_fields)
        )

    def merge(self: T_PSBT_Output, other: T_PSBT_Output,
              allow_blob_duplicates: bool = False) -> None:
        merge_input_output_common_fields(self, other, 'output')
        merge_proprietary_fields(self.proprietary_fields,
                                 other.proprietary_fields,
                                 allow_duplicates=allow_blob_duplicates)
        merge_unknown_fields(self.unknown_fields, other.unknown_fields,
                             allow_duplicates=allow_blob_duplicates)

    @classmethod
    def from_instance(cls: Type[T_PSBT_Output],
                      inst: T_PSBT_Output
                      ) -> T_PSBT_Output:
        new_inst = cls()
        new_inst.merge(inst, allow_blob_duplicates=True)
        return new_inst

    def clone(self: T_PSBT_Output) -> T_PSBT_Output:
        return self.__class__.from_instance(self)

    def _check_sanity(self, unsigned_tx: CTransaction) -> None:
        rds = self.redeem_script
        ws = self.witness_script

        if self.index is None:
            raise ValueError(
                'index is not set for this instance of PSBT_Output')

        vout = unsigned_tx.vout[self.index]

        if not MoneyRange(vout.nValue):
            raise ValueError(
                f'Value of output at index {self.index} is out of valid range')

        if not rds and not ws:
            # No information to check the outputs is supplied, that's OK
            return

        spk = vout.scriptPubKey

        if spk.is_witness_scriptpubkey():
            if rds:
                raise ValueError(
                    f'redeem script is specified for native segwit output '
                    f'at index {self.index}')

            if spk.is_witness_v0_keyhash():
                if ws:
                    raise ValueError(
                        f'witness script is specified for native segwit '
                        f'p2wpkh output at index {self.index}')
            elif spk.is_witness_v0_scripthash():
                if not ws:
                    raise ValueError(
                        f'witness script is not specified for native segwit '
                        f'p2wsh output at index {self.index}')
            else:
                raise ValueError('unsupported scriptPubKey type')
        elif spk.is_p2pkh():
            if rds:
                raise ValueError(
                    f'redeem script is specified for p2pkh output '
                    f'at index {self.index}')
            if ws:
                raise ValueError(
                    f'witness script is specified for p2pkh output '
                    f'at index {self.index}')
        elif spk.is_p2sh():
            if not rds:
                raise ValueError(
                    f'redeem script is not specified for p2sh output '
                    f'at index {self.index}')

            if rds.is_witness_scriptpubkey():
                if rds.is_witness_v0_keyhash():
                    if ws:
                        raise ValueError(
                            f'witness script is specified for p2sh-wrapped '
                            f'p2wpkh segwit output at index {self.index}')
                elif rds.is_witness_v0_scripthash():
                    if not ws:
                        raise ValueError(
                            f'witness script is not specified for '
                            f'p2sh-wrapped p2wsh segwit output '
                            f'at index {self.index}')
                else:
                    raise ValueError(
                        'unsupported scriptPubKey type (that was p2sh-wrapped)'
                    )
            elif ws:
                raise ValueError(
                    f'witness script is specified for '
                    f'non-segwit p2sh output at index {self.index}')
        else:
            raise ValueError('unsupported scriptPubKey type')

    @classmethod
    def stream_deserialize(cls: Type[T_PSBT_Output], f: ByteStream_Type,
                           index: int = -1,
                           **kwargs: Any) -> T_PSBT_Output:

        if index < 0:
            raise ValueError('index is invalid or unspecified')

        redeem_script: CScript = CScript()
        witness_script: CScript = CScript()
        derivation_map: Dict[CPubKey, PSBT_KeyDerivationInfo] = OrderedDict()
        proprietary_fields: Dict[
            bytes, List[PSBT_ProprietaryTypeData]
        ] = OrderedDict()
        unknown_fields: List[PSBT_UnknownTypeData] = []

        def descr(msg: str) -> str:
            return f'{msg} for output at index {index}'

        keys_seen: Set[bytes] = set()
        for key_type, key_data, value in \
                read_psbt_keymap(f, keys_seen, PSBT_OutKeyType,
                                 proprietary_fields, unknown_fields):

            if key_type is PSBT_OutKeyType.REDEEM_SCRIPT:
                ensure_empty_key_data(key_type, key_data, descr(''))
                redeem_script = CScript(value)
            elif key_type is PSBT_OutKeyType.WITNESS_SCRIPT:
                ensure_empty_key_data(key_type, key_data, descr(''))
                witness_script = CScript(value)
            elif key_type is PSBT_OutKeyType.BIP32_DERIVATION:
                pub = CPubKey(key_data)
                if not pub.is_fullyvalid():
                    raise SerializationError(
                        descr(
                            f'Invalid pubkey encountered in {key_type.name}'))
                assert pub not in derivation_map, \
                    ("duplicate keys should have been catched "
                     "inside read_psbt_keymap()")
                derivation_map[pub] = PSBT_KeyDerivationInfo.deserialize(value)
            else:
                assert_never(key_type)

        return cls(redeem_script=redeem_script, witness_script=witness_script,
                   derivation_map=derivation_map,
                   proprietary_fields=proprietary_fields,
                   unknown_fields=unknown_fields,
                   index=index)

    def stream_serialize(self, f: ByteStream_Type, **kwargs: Any) -> None:
        if self.redeem_script:
            stream_serialize_field(PSBT_OutKeyType.REDEEM_SCRIPT, f,
                                   value=self.redeem_script)

        if self.witness_script:
            stream_serialize_field(PSBT_OutKeyType.WITNESS_SCRIPT, f,
                                   value=self.witness_script)

        for pub, dinfo in self.derivation_map.items():
            assert isinstance(pub, CPubKey) and pub.is_fullyvalid()
            stream_serialize_field(PSBT_OutKeyType.BIP32_DERIVATION, f,
                                   key_data=pub, value=dinfo.serialize())

        stream_serialize_proprietary_fields(self.proprietary_fields, f)
        stream_serialize_unknown_fields(self.unknown_fields, f)

        f.write(PSBT_SEPARATOR)

    def _repr_dict(self) -> 'OrderedDict[str, str]':
        return OrderedDict({
            'redeem_script': repr(self.redeem_script),
            'witness_script': repr(self.witness_script),
            'derivation_map':
                f'{{{derivation_map_repr(self.derivation_map)}}}',
            'proprietary_fields':
                f"{{{proprietary_field_repr(self.proprietary_fields)}}}",
            'unknown_fields': f"[{unknown_fields_repr(self.unknown_fields)}]"
        })


class PSBT_BitcoinOutput(PSBT_Output, PSBT_BitcoinClass):
    ...


T_PartiallySignedTransaction = TypeVar('T_PartiallySignedTransaction',
                                       bound='PartiallySignedTransaction')


class PartiallySignedTransaction(PSBT_CoinClass, next_dispatch_final=True):
    version: int
    inputs: List[PSBT_Input]
    outputs: List[PSBT_Output]
    unsigned_tx: CTransaction
    xpubs: Dict[CCoinExtPubKey, PSBT_KeyDerivationInfo]
    proprietary_fields: Dict[bytes, List[PSBT_ProprietaryTypeData]]
    unknown_fields: List[PSBT_UnknownTypeData]
    # NOTE: if you add a field, don't forget to specify it in merge()

    def __init__(self, *,
                 version: int = 0,
                 inputs: Optional[List[PSBT_Input]] = None,
                 outputs: Optional[List[PSBT_Output]] = None,
                 unsigned_tx: Optional[CTransaction] = None,
                 xpubs: Optional[Dict[
                     CCoinExtPubKey, PSBT_KeyDerivationInfo
                 ]] = None,
                 proprietary_fields: Optional[Dict[
                     bytes, List[PSBT_ProprietaryTypeData]
                 ]] = None,
                 unknown_fields: Optional[List[PSBT_UnknownTypeData]] = None,
                 relaxed_sanity_checks: bool = False
                 ) -> None:

        ensure_isinstance(version, int, 'version')
        if version != 0:
            raise ValueError('Unsupported PSBT version')
        self.version = version

        if unsigned_tx is None:
            unsigned_tx = CTransaction()
        else:
            ensure_isinstance(unsigned_tx, CTransaction, 'unsigned_tx')

        if inputs is None:
            num_inputs = len(unsigned_tx.vin)
        else:
            num_inputs = len(inputs)

        if num_inputs != len(unsigned_tx.vin):
            raise ValueError(
                'length of inputs list supplied is not the same as number '
                'of inputs in unsigned_tx')

        if outputs is None:
            num_outputs = len(unsigned_tx.vout)
        else:
            num_outputs = len(outputs)

        if num_outputs != len(unsigned_tx.vout):
            raise ValueError(
                'length of outputs list supplied is not the same as '
                'number of outputs in unsigned_tx')

        if unsigned_tx.has_witness():
            raise ValueError(
                'Unsigned transaction contains witness data')
        if any(inp.scriptSig for inp in unsigned_tx.vin):
            raise ValueError(
                'Unsigned transaction contains non-empty scriptSigs')
        self.unsigned_tx = unsigned_tx

        new_inputs = []
        for i in range(num_inputs):
            if inputs is None:
                inp = PSBT_Input(index=i)
            else:
                ensure_isinstance(inputs[i], PSBT_Input,
                                  f'input at position {i}')
                inp = inputs[i].clone()
                if inp.index is None:
                    inp.index = i
                elif inp.index != i:
                    raise ValueError(
                        f'incorrect index on PSBT_Input at position {i}')
                if inp.non_witness_utxo:
                    # This might actually be a witness utxo. This can only be
                    # checked when unsigned_tx is known, do this check now.
                    inp.set_utxo(inp.non_witness_utxo, unsigned_tx)

            new_inputs.append(inp)

        self.inputs = new_inputs

        new_outputs = []
        for i in range(num_outputs):
            if outputs is None:
                outp = PSBT_Output(index=i)
            else:
                ensure_isinstance(outputs[i], PSBT_Output,
                                  f'output at position {i}')
                outp = outputs[i].clone()
                if outp.index is None:
                    outp.index = i
                elif outp.index != i:
                    raise ValueError(
                        f'incorrect index on PSBT_Output at position {i}')

            new_outputs.append(outp)

        self.outputs = new_outputs

        if xpubs is None:
            xpubs = OrderedDict()

        for xpub, derinfo in xpubs.items():
            ensure_isinstance(xpub, CCoinExtPubKey, 'one of xpubs')
            ensure_isinstance(derinfo, PSBT_KeyDerivationInfo,
                              'derivation info for one of xpubs')
        self.xpubs = xpubs

        if proprietary_fields is None:
            proprietary_fields = OrderedDict()

        for prefix, p_fields in proprietary_fields.items():
            ensure_isinstance(prefix, bytes, 'proprietary type prefix')
            for field_index, field in enumerate(p_fields):
                ensure_isinstance(
                    field, PSBT_ProprietaryTypeData,
                    f'one of proprietary field contents for '
                    f'prefix {b2x(prefix)}')

        self.proprietary_fields = proprietary_fields

        if unknown_fields is None:
            unknown_fields = []

        for u_field in unknown_fields:
            ensure_isinstance(u_field, PSBT_UnknownTypeData,
                              'contents of unkown type')
        self.unknown_fields = unknown_fields

        if not relaxed_sanity_checks:
            self._check_sanity()

    def _check_sanity(self) -> None:

        if self.unsigned_tx.is_null():
            return

        try:
            CheckTransaction(self.unsigned_tx)
        except CheckTransactionError as e:
            raise ValueError(str(e))

        inputs_sum = 0
        for inp in self.inputs:
            inp._check_sanity(self.unsigned_tx)
            if inp.utxo is not None:
                inputs_sum += inp.get_amount(self.unsigned_tx)

        if not MoneyRange(inputs_sum):
            raise ValueError('sum of input amounts is out of valid range')

        for outp in self.outputs:
            outp._check_sanity(self.unsigned_tx)

    @classmethod
    def from_instance(cls: Type[T_PartiallySignedTransaction],
                      inst: T_PartiallySignedTransaction
                      ) -> T_PartiallySignedTransaction:
        new_inst = cls()
        new_inst.merge(inst, allow_blob_duplicates=True)
        return new_inst

    def clone(self: T_PartiallySignedTransaction
              ) -> T_PartiallySignedTransaction:
        return self.__class__.from_instance(self)

    def merge(self: T_PartiallySignedTransaction,
              other: T_PartiallySignedTransaction,
              allow_blob_duplicates: bool = False
              ) -> None:
        if self.version != other.version:
            raise ValueError('PSBT version do not match')

        tx_assigned = False
        if self.unsigned_tx.is_null():
            self.unsigned_tx = other.unsigned_tx
            tx_assigned = True
        elif other.unsigned_tx.is_null():
            pass
        elif self.unsigned_tx.GetTxid() != other.unsigned_tx.GetTxid():
            raise ValueError('unsigned_tx txids do not match')

        if not self.inputs and other.inputs:
            if not tx_assigned:
                raise ValueError('number of inputs do not match')
            self.inputs = [PSBT_Input() for _ in other.inputs]

        for index, inp in enumerate(self.inputs):
            inp.merge(other.inputs[index],
                      allow_blob_duplicates=allow_blob_duplicates)

        if not self.outputs and other.outputs:
            if not tx_assigned:
                raise ValueError('number of outputs do not match')
            self.outputs = [PSBT_Output() for _ in other.outputs]

        for index, outp in enumerate(self.outputs):
            outp.merge(other.outputs[index],
                       allow_blob_duplicates=allow_blob_duplicates)

        for xpub, dinfo in other.xpubs.items():
            if xpub in self.xpubs:
                if self.xpubs[xpub].master_fp != \
                        dinfo.master_fp:
                    raise ValueError(
                        f'master fingerprint do not match in derivation info '
                        f'for xpub {str(xpub)}')
                if tuple(self.xpubs[xpub].path) != tuple(dinfo.path):
                    raise ValueError(
                        f'derivation paths do not match in derivation info '
                        f'for xpub {str(xpub)}')
            else:
                self.xpubs[xpub] = dinfo.clone()

        merge_proprietary_fields(self.proprietary_fields,
                                 other.proprietary_fields,
                                 allow_duplicates=allow_blob_duplicates)
        merge_unknown_fields(self.unknown_fields, other.unknown_fields,
                             allow_duplicates=allow_blob_duplicates)

    def combine(self: T_PartiallySignedTransaction,
                other: T_PartiallySignedTransaction
                ) -> T_PartiallySignedTransaction:
        new_psbt = self.clone()
        new_psbt.merge(other, allow_blob_duplicates=True)
        return new_psbt

    def add_input(self, txin: CTxIn, inp: PSBT_Input) -> None:

        if inp.index is not None and inp.index != len(self.unsigned_tx.vin):
            raise ValueError(
                f'invalid index in supplied PSBT_Input '
                f'(must be None or {len(self.unsigned_tx.vin)}, '
                f'but is {inp.index})')

        self._check_consistency()

        tuple_or_list = list if self.unsigned_tx.is_mutable() else tuple

        if self.unsigned_tx.is_mutable():
            if txin.is_immutable():
                txin = CMutableTxIn.from_instance(txin)
        else:
            if txin.is_mutable():
                txin = CTxIn.from_instance(txin)

        saved_vin = self.unsigned_tx.vin
        vin = list(saved_vin)
        vin.append(txin)

        object.__setattr__(self.unsigned_tx, 'vin', tuple_or_list(vin))

        inp = inp.clone()

        inp.index = len(saved_vin)

        if inp.non_witness_utxo:
            # This might actually be a witness utxo. This can only be
            # checked when unsigned_tx is known, do this check now.
            inp.set_utxo(inp.non_witness_utxo, self.unsigned_tx)

        try:
            inp._check_sanity(self.unsigned_tx)
        except ValueError:
            object.__setattr__(self.unsigned_tx, 'vin', saved_vin)
            raise

        self.inputs.append(inp)

    def add_output(self, txout: CTxOut, outp: PSBT_Output) -> None:
        if outp.index is not None and outp.index != len(self.unsigned_tx.vout):
            raise ValueError(
                f'invalid index in supplied PSBT_Output '
                f'(must be None or {len(self.unsigned_tx.vout)}, '
                f'but is {outp.index})')

        self._check_consistency()

        tuple_or_list = list if self.unsigned_tx.is_mutable() else tuple

        if self.unsigned_tx.is_mutable():
            if txout.is_immutable():
                txout = CMutableTxOut.from_instance(txout)
        else:
            if txout.is_mutable():
                txout = CTxOut.from_instance(txout)

        saved_vout = self.unsigned_tx.vout
        vout = list(saved_vout)
        vout.append(txout)

        object.__setattr__(self.unsigned_tx, 'vout', vout)

        outp.index = len(saved_vout)

        try:
            outp._check_sanity(self.unsigned_tx)
        except ValueError:
            object.__setattr__(self.unsigned_tx, 'vout', saved_vout)
            raise

        object.__setattr__(self.unsigned_tx, 'vout', tuple_or_list(vout))
        self.outputs.append(outp)

    def set_utxo(
        self,
        utxo: Optional[Union[CTransaction, CTxOut]],
        index: int,
        force_witness_utxo: bool = False,
        relaxed_sanity_checks: bool = False
    ) -> None:
        ensure_isinstance(index, int, 'index')
        self.inputs[index].set_utxo(
            utxo, self.unsigned_tx,
            force_witness_utxo=force_witness_utxo,
            relaxed_sanity_checks=relaxed_sanity_checks)

    @classmethod
    def from_base64_or_binary(
        cls: Type[T_PartiallySignedTransaction], data: Union[bytes, str],
        validate: bool = True, **kwargs: Any
    ) -> T_PartiallySignedTransaction:
        if isinstance(data, str):
            if data[:len(CoreCoinParams.PSBT_MAGIC_HEADER_BASE64)] != \
                    CoreCoinParams.PSBT_MAGIC_HEADER_BASE64:
                raise ValueError(
                    'got data of type str, but magic bytes at the start '
                    'do not match base64-encoded PSBT magic bytes')
            data_b = data.encode('ascii')
        elif isinstance(data, bytes):
            data_b = data
        else:
            raise TypeError('type of data is not str or bytes')

        if data_b.startswith(CoreCoinParams.PSBT_MAGIC_HEADER_BYTES):
            return cls.from_binary(bytes(data_b), **kwargs)
        elif data_b.startswith(CoreCoinParams.PSBT_MAGIC_HEADER_BASE64
                               .encode('ascii')):
            return cls.deserialize(base64.b64decode(data_b.decode('ascii'),
                                                    validate=validate),
                                   **kwargs)
        else:
            raise ValueError(
                'magic bytes at the start do not match PSBT magic bytes')

    @classmethod
    def from_binary(cls: Type[T_PartiallySignedTransaction], data: bytes,
                    **kwargs: Any
                    ) -> T_PartiallySignedTransaction:
        return cls.deserialize(data, **kwargs)

    @classmethod
    def from_base64(cls: Type[T_PartiallySignedTransaction], b64_data: str,
                    validate: bool = True, **kwargs: Any
                    ) -> T_PartiallySignedTransaction:
        return cls.deserialize(base64.b64decode(b64_data, validate=validate),
                               **kwargs)

    def to_base64(self) -> str:
        return base64.b64encode(self.serialize()).decode('ascii')

    @no_bool_use_as_property
    def is_null(self) -> bool:
        return (
            self.unsigned_tx.is_null()
            and (not self.inputs)
            and (not self.outputs)
            and (not self.xpubs)
            and (not self.proprietary_fields)
            and (not self.unknown_fields)
        )

    @classmethod
    def stream_deserialize(cls: Type[T_PartiallySignedTransaction],
                           f: ByteStream_Type,
                           relaxed_sanity_checks: bool = False,
                           acceptable_xpub_prefixes: Collection[bytes] = (),
                           **kwargs: Any) -> T_PartiallySignedTransaction:

        magic = ser_read(f, 5)
        if magic != CoreCoinParams.PSBT_MAGIC_HEADER_BYTES:
            raise SerializationError(
                'Invalid partially-signed transaction header')

        proprietary_fields: Dict[bytes, List[PSBT_ProprietaryTypeData]] = \
            OrderedDict()
        unknown_fields: List[PSBT_UnknownTypeData] = []
        xpubs: Dict[CCoinExtPubKey, PSBT_KeyDerivationInfo] = OrderedDict()
        unsigned_tx: Optional[CTransaction] = None
        version: int = 0

        keys_seen: Set[bytes] = set()
        for key_type, key_data, value in \
                read_psbt_keymap(f, keys_seen, PSBT_GlobalKeyType,
                                 proprietary_fields, unknown_fields):

            if key_type is PSBT_GlobalKeyType.UNSIGNED_TX:
                ensure_empty_key_data(key_type, key_data)
                unsigned_tx = CTransaction.deserialize(value)
            elif key_type is PSBT_GlobalKeyType.XPUB:

                acceptable_prefixes = [CCoinExtPubKey.base58_prefix]
                acceptable_prefixes.extend(acceptable_xpub_prefixes)

                if key_data[:4] not in acceptable_prefixes:
                    if len(acceptable_xpub_prefixes) > 1:
                        pfx_msg = 'prefixes (hex) ('
                        pfx_msg += ', '.join([b2x(pfx) for
                                              pfx in acceptable_prefixes])
                        pfx_msg += ')'
                    else:
                        pfx_msg = 'prefix (hex) ' + b2x(acceptable_prefixes[0])

                    raise ValueError(
                        f'One of global xpubs has unknown prefix: expected '
                        f'{pfx_msg}, got {b2x(key_data[:4])}')

                xpub = CCoinExtPubKey.from_bytes(key_data[4:])
                assert xpub not in xpubs, \
                    ("duplicate keys should have been catched "
                     "inside read_psbt_keymap()")
                xpubs[xpub] = PSBT_KeyDerivationInfo.deserialize(value)

            elif key_type is PSBT_GlobalKeyType.VERSION:
                ensure_empty_key_data(key_type, key_data)
                if len(value) != 4:
                    raise SerializationError(
                        f'Incorrect data length for {key_type.name}')
                version = struct.unpack(b'<I', value)[0]
            else:
                assert_never(key_type)

        if unsigned_tx is None:
            raise ValueError(
                'PSBT does not contain unsigned transaction')

        inputs = []
        for input_index in range(len(unsigned_tx.vin)):
            inputs.append(
                PSBT_Input.stream_deserialize(
                    f, index=input_index, unsigned_tx=unsigned_tx,
                    relaxed_sanity_checks=relaxed_sanity_checks,
                    **kwargs))

        outputs = []
        for output_index in range(len(unsigned_tx.vout)):
            outputs.append(
                PSBT_Output.stream_deserialize(
                    f, index=output_index, **kwargs))

        return cls(version=version,
                   inputs=inputs, outputs=outputs,
                   unsigned_tx=unsigned_tx, xpubs=xpubs,
                   proprietary_fields=proprietary_fields,
                   unknown_fields=unknown_fields,
                   relaxed_sanity_checks=relaxed_sanity_checks)

    def _check_consistency(self) -> None:
        if len(self.unsigned_tx.vin) != len(self.inputs):
            raise AssertionError('inputs length must match unsigned_tx.vin')

        if len(self.unsigned_tx.vout) != len(self.outputs):
            raise AssertionError('outputs length must match unsigned_tx.vout')

    def stream_serialize(self, f: ByteStream_Type,
                         relaxed_sanity_checks: bool = False,
                         **kwargs: Any) -> None:

        self._check_consistency()
        if not relaxed_sanity_checks:
            self._check_sanity()

        f.write(CoreCoinParams.PSBT_MAGIC_HEADER_BYTES)

        stream_serialize_field(
            PSBT_GlobalKeyType.UNSIGNED_TX, f,
            value=self.unsigned_tx.serialize(include_witness=False))

        if self.version:
            stream_serialize_field(
                PSBT_GlobalKeyType.VERSION, f,
                value=struct.pack(b"<I", self.version))

        for xpub, derinfo in self.xpubs.items():
            assert isinstance(xpub, CCoinExtPubKey)
            stream_serialize_field(
                PSBT_GlobalKeyType.XPUB, f,
                key_data=xpub.base58_prefix + xpub,
                value=PSBT_KeyDerivationInfo.serialize(derinfo))

        stream_serialize_proprietary_fields(self.proprietary_fields, f)
        stream_serialize_unknown_fields(self.unknown_fields, f)

        f.write(PSBT_SEPARATOR)

        always_include_witness_utxo = kwargs.pop(
            'always_include_witness_utxo', True)

        for inp in self.inputs:
            inp.stream_serialize(
                f, always_include_witness_utxo=always_include_witness_utxo,
                **kwargs)

        for outp in self.outputs:
            outp.stream_serialize(f, **kwargs)

    @no_bool_use_as_property
    def is_final(self) -> bool:
        if len(self.unsigned_tx.vin) != len(self.inputs):
            raise ValueError('len(inputs) != len(unsigned_tx.vin)')
        return all(inp.is_final() for inp in self.inputs)

    def sign(self, key_store: KeyStore,
             complex_script_helper_factory: Callable[
                 [CScript], ComplexScriptSignatureHelper
             ] = StandardMultisigSignatureHelper.__call__,
             finalize: bool = True,
             ) -> PSBT_SignResult:
        self._check_consistency()

        inputs_sign_info: List[Optional[PSBT_InputSignInfo]] = []
        num_inputs_signed = 0
        num_inputs_ready = 0
        num_inputs_final = 0
        for txin_index, _ in enumerate(self.unsigned_tx.vin):
            info = self.inputs[txin_index].sign(
                self.unsigned_tx, key_store,
                complex_script_helper_factory=complex_script_helper_factory,
                finalize=finalize)
            inputs_sign_info.append(info)
            if info:
                if info.num_new_sigs:
                    num_inputs_signed += 1
                if info.is_final:
                    num_inputs_final += 1
                elif info.num_sigs_missing == 0:
                    num_inputs_ready += 1

        is_final = len(self.unsigned_tx.vin) == num_inputs_final
        is_ready = len(self.unsigned_tx.vin) == \
            num_inputs_final + num_inputs_ready
        return PSBT_SignResult(inputs_info=inputs_sign_info,
                               num_inputs_signed=num_inputs_signed,
                               num_inputs_ready=num_inputs_ready,
                               num_inputs_final=num_inputs_final,
                               is_ready=is_ready,
                               is_final=is_final)

    def extract_transaction(self) -> CTransaction:
        sign_result = self.sign(KeyStore())
        if not sign_result.is_final:
            raise ValueError(
                'not all inputs have required signatures')

        tx = self.unsigned_tx.to_mutable()

        txin_witnesses = []
        for index, inp in enumerate(self.inputs):
            tx.vin[index].scriptSig = inp.final_script_sig
            txin_witnesses.append(CTxInWitness(inp.final_script_witness))

        tx.wit = CTxWitness(txin_witnesses)

        tx_immutable = tx.to_immutable()

        CheckTransaction(tx_immutable)

        return tx_immutable

    def get_input_amounts(self) -> Tuple[int, ...]:
        return tuple(inp.get_amount(self.unsigned_tx) for inp in self.inputs)

    def get_output_amounts(self) -> Tuple[int, ...]:
        return tuple(outp.nValue for outp in self.unsigned_tx.vout)

    def get_fee(self, allow_negative: bool = False) -> int:
        inputs_sum = sum(self.get_input_amounts())
        outputs_sum = sum(self.get_output_amounts())
        fee = inputs_sum - outputs_sum
        if fee < 0 and not allow_negative:
            raise ValueError(f'Calculated fee is negative: '
                             f'sum of input amounts {inputs_sum}, '
                             f'sum of output amounts {outputs_sum}')
        return fee

    def _repr_dict(self) -> 'OrderedDict[str, str]':
        xpubs = (
            ', '.join(
                f"'{str(k)}': (x('{b2x(v.master_fp)}'), \"{str(v.path)}\")"
                for k, v in self.xpubs.items()))

        return OrderedDict({
            'version': f'{self.version}',
            'inputs': repr(self.inputs),
            'outputs': repr(self.outputs),
            'unsigned_tx': repr(self.unsigned_tx),
            'xpubs': f'{{{xpubs}}}',
            'proprietary_fields':
                f"{{{proprietary_field_repr(self.proprietary_fields)}}}",
            'unknown_fields': f"[{unknown_fields_repr(self.unknown_fields)}]"
        })


class PartiallySignedBitcoinTransaction(PartiallySignedTransaction,
                                        PSBT_BitcoinClass):
    ...


# default dispatcher for the module
activate_class_dispatcher(PSBT_BitcoinClassDispatcher)

__all__ = (
    'PartiallySignedTransaction',
    'PSBT_Input',
    'PSBT_Output',
    'PSBT_KeyDerivationInfo',
    'PSBT_ProprietaryTypeData',
    'PSBT_UnknownTypeData',
)
