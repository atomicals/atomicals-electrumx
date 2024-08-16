# Copyright (C) 2012-2014 The python-bitcoinlib developers
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

"""Wallet-related functionality

Includes things like representing addresses and converting them to/from
scriptPubKeys; currently there is no actual wallet support implemented.
"""

# pylama:ignore=E501,E221

from io import BytesIO
from typing import (
    Type, TypeVar, Union, Optional, List, Callable, ClassVar, cast
)

import bitcointx
import bitcointx.base58
import bitcointx.bech32
import bitcointx.core

from bitcointx.util import (
    ClassMappingDispatcher, activate_class_dispatcher, dispatcher_mapped_list,
    ensure_isinstance
)
from bitcointx.core.key import (
    CPubKey, CKeyBase, CExtKeyBase, CExtPubKeyBase, XOnlyPubKey,
    tap_tweak_pubkey
)
from bitcointx.core.script import (
    CScript, standard_keyhash_scriptpubkey, standard_scripthash_scriptpubkey,
    TaprootScriptTree
)


class WalletCoinClassDispatcher(ClassMappingDispatcher, identity='wallet',
                                depends=[bitcointx.core.CoreCoinClassDispatcher]):
    ...


class WalletBitcoinClassDispatcher(
    WalletCoinClassDispatcher,
    depends=[bitcointx.core.CoreBitcoinClassDispatcher]
):
    ...


class WalletBitcoinTestnetClassDispatcher(WalletBitcoinClassDispatcher):
    ...


class WalletBitcoinRegtestClassDispatcher(WalletBitcoinClassDispatcher):
    ...


class WalletBitcoinSignetClassDispatcher(WalletBitcoinClassDispatcher):
    ...


class WalletCoinClass(metaclass=WalletCoinClassDispatcher):
    ...


class WalletBitcoinClass(WalletCoinClass,
                         metaclass=WalletBitcoinClassDispatcher):
    ...


class WalletBitcoinTestnetClass(WalletBitcoinClass,
                                metaclass=WalletBitcoinTestnetClassDispatcher):
    ...


class WalletBitcoinRegtestClass(WalletBitcoinClass,
                                metaclass=WalletBitcoinRegtestClassDispatcher):
    ...


class WalletBitcoinSignetClass(WalletBitcoinClass,
                               metaclass=WalletBitcoinSignetClassDispatcher):
    ...


T_CCoinAddress = TypeVar('T_CCoinAddress', bound='CCoinAddress')


class CCoinAddress(WalletCoinClass):

    _data_length: int
    _scriptpubkey_type: str

    def __new__(cls: Type[T_CCoinAddress], s: str) -> T_CCoinAddress:
        ensure_isinstance(s, str, 'address string')

        recognized_encoding = []
        target_cls_set = dispatcher_mapped_list(cls)
        for target_cls in target_cls_set:
            try:
                inst = target_cls(s)

                # CCoinClass shall be used as mixin along with
                # bytes-derived base class
                assert isinstance(inst, bytes), \
                    '{inst.__class__.__name__} must be bytes subclass'

                return inst

            except CCoinAddressError:
                recognized_encoding.append(target_cls.__name__)
            except bitcointx.core.AddressDataEncodingError:
                pass

        if recognized_encoding:
            raise CCoinAddressError(
                'Correct encoding for any of {}, but not correct format'
                .format(recognized_encoding))

        raise CCoinAddressError(
            'Unrecognized encoding for any of {}'
            .format([tcls.__name__ for tcls in target_cls_set]))

    @classmethod
    def from_scriptPubKey(cls: Type[T_CCoinAddress],
                          scriptPubKey: CScript) -> T_CCoinAddress:
        """Convert a scriptPubKey to a subclass of CCoinAddress"""
        for candidate in dispatcher_mapped_list(cls):
            try:
                return candidate.from_scriptPubKey(scriptPubKey)
            except CCoinAddressError:
                pass

        raise CCoinAddressError(
            'scriptPubKey is not in a recognized address format')

    @classmethod
    def get_output_size(cls: Type[T_CCoinAddress]) -> int:
        data_length = getattr(cls, '_data_length', None)
        if not data_length:
            raise TypeError('output size is not available for {}'
                            .format(cls.__name__))
        inst = cls.from_bytes(b'\x00'*data_length)
        txo = bitcointx.core.CTxOut(scriptPubKey=inst.to_scriptPubKey())
        f = BytesIO()
        txo.stream_serialize(f)
        return len(f.getbuffer())

    # 'scriptPubKey' is used thoughout API (as this is how pubkey script is
    # referred to in C++ code in Bitcoin Core). Using snake-case
    # would be more pythonic, but sticking to the established convention
    # is better, because users of API will just need to know that scriptPubKey
    # is always camel-cased.
    @classmethod
    def get_scriptPubKey_type(cls) -> str:
        """return scriptPubKey type for a given concrete class.
        For example, when called on P2SHCoinAddress, will return 'scripthash'.

        calling this method on generic address class is an error."""
        spk_type = getattr(cls, '_scriptpubkey_type', None)
        if not spk_type:
            raise TypeError('scriptPubKey type is not available for {}'
                            .format(cls.__name__))
        return cls._scriptpubkey_type

    @classmethod
    def match_scriptPubKey_type(cls, spk_type_string: str
                                ) -> Optional[Type['CCoinAddress']]:
        """match the concrete address class by scriptPubKey type.
        For example, given the string 'scripthash', it will return
        P2SHCoinAddress. If no matching scriptPubKey type is found,
        will return None."""
        for target_cls in dispatcher_mapped_list(cls):
            assert issubclass(target_cls, CCoinAddress)
            spk_type = getattr(target_cls, '_scriptpubkey_type', None)
            if not spk_type:
                matched = target_cls.match_scriptPubKey_type(spk_type_string)
                if matched is not None:
                    return matched
            elif spk_type_string == spk_type:
                return target_cls
        return None

    def __bytes__(self) -> bytes:
        # we checked at __new__ that self is a bytes instance
        assert isinstance(self, bytes)
        return self[:]

    def to_scriptPubKey(self) -> CScript:
        raise NotImplementedError('method must be overriden in a subclass')

    def to_redeemScript(self) -> CScript:
        raise NotImplementedError('method must be overriden in a subclass')


class CCoinAddressError(Exception):
    """Raised when an invalid coin address is encountered"""


class CBase58AddressError(CCoinAddressError):
    """Raised when an invalid base58-encoded address is encountered"""


class CBech32AddressError(CCoinAddressError):
    """Raised when an invalid bech32-encoded address is encountered"""


class P2SHCoinAddressError(CBase58AddressError):
    """Raised when an invalid P2SH address is encountered"""


class P2PKHCoinAddressError(CBase58AddressError):
    """Raised when an invalid P2PKH address is encountered"""


class P2WSHCoinAddressError(CBech32AddressError):
    """Raised when an invalid PW2SH address is encountered"""


class P2TRCoinAddressError(CBech32AddressError):
    """Raised when an invalid PW2SH address is encountered"""


class P2WPKHCoinAddressError(CBech32AddressError):
    """Raised when an invalid PW2PKH address is encountered"""


T_CBase58DataDispatched = TypeVar('T_CBase58DataDispatched',
                                  bound='CBase58DataDispatched')


class CBase58DataDispatched(bitcointx.base58.CBase58Data):

    def __init__(self, _s: str) -> None:
        if not self.base58_prefix:
            raise TypeError(
                f'{self.__class__.__name__} must not be instantiated directly')
        if len(self) != self.__class__._data_length:
            raise TypeError(
                f'lengh of the data is not {self.__class__._data_length}')

    @classmethod
    def base58_get_match_candidates(cls: Type[T_CBase58DataDispatched]
                                    ) -> List[Type[T_CBase58DataDispatched]]:
        assert isinstance(cls, ClassMappingDispatcher)
        candidates = dispatcher_mapped_list(cls)
        if not candidates:
            if not cls.base58_prefix:
                raise TypeError(
                    "if class has no dispatched descendants, it must have "
                    "base58_prefix set")
            candidates = [cls]
        return candidates


T_CBech32DataDispatched = TypeVar('T_CBech32DataDispatched',
                                  bound='CBech32DataDispatched')


class CBech32DataDispatched(bitcointx.bech32.CBech32Data):

    def __init__(self, _s: str) -> None:
        if self.__class__.bech32_witness_version < 0:
            raise TypeError(
                f'{self.__class__.__name__} must not be instantiated directly')
        if len(self) != self.__class__._data_length:
            raise TypeError(
                f'lengh of the data is not {self.__class__._data_length}')

    @classmethod
    def bech32_get_match_candidates(cls: Type[T_CBech32DataDispatched]
                                    ) -> List[Type[T_CBech32DataDispatched]]:
        assert isinstance(cls, ClassMappingDispatcher)
        candidates = dispatcher_mapped_list(cls)
        if not candidates:
            if cls.bech32_witness_version < 0:
                raise TypeError(
                    "if class has no dispatched descendants, it must have "
                    "bech32_witness_version set to non-negative value")
            candidates = [cls]
        return candidates


class CBech32CoinAddress(CBech32DataDispatched, CCoinAddress):
    """A Bech32-encoded coin address"""


class CBase58CoinAddress(CBase58DataDispatched, CCoinAddress):
    """A Base58-encoded coin address"""


T_P2SHCoinAddress = TypeVar('T_P2SHCoinAddress', bound='P2SHCoinAddress')


class P2SHCoinAddress(CBase58CoinAddress, next_dispatch_final=True):
    _data_length = 20
    _scriptpubkey_type = 'scripthash'

    @classmethod
    def from_redeemScript(cls: Type[T_P2SHCoinAddress],
                          redeemScript: CScript) -> T_P2SHCoinAddress:
        """Convert a redeemScript to a P2SH address

        Convenience function: equivalent to P2SHBitcoinAddress.from_scriptPubKey(redeemScript.to_p2sh_scriptPubKey())
        """
        return cls.from_scriptPubKey(redeemScript.to_p2sh_scriptPubKey())

    @classmethod
    def from_scriptPubKey(cls: Type[T_P2SHCoinAddress],
                          scriptPubKey: CScript) -> T_P2SHCoinAddress:
        """Convert a scriptPubKey to a P2SH address

        Raises CCoinAddressError if the scriptPubKey isn't of the correct
        form.
        """
        if scriptPubKey.is_p2sh():
            return cls.from_bytes(scriptPubKey[2:22])

        else:
            raise P2SHCoinAddressError('not a P2SH scriptPubKey')

    def to_scriptPubKey(self) -> CScript:
        """Convert an address to a scriptPubKey"""
        return standard_scripthash_scriptpubkey(self)

    # Return type deliberately incompatible with CCoinAddress,
    # because this operation is not defined for p2sh address
    def to_redeemScript(self) -> None:  # type: ignore
        raise NotImplementedError("not enough data in p2sh address to reconstruct redeem script")


T_P2PKHCoinAddress = TypeVar('T_P2PKHCoinAddress', bound='P2PKHCoinAddress')


class P2PKHCoinAddress(CBase58CoinAddress, next_dispatch_final=True):
    _data_length = 20
    _scriptpubkey_type = 'pubkeyhash'

    @classmethod
    def from_pubkey(cls: Type[T_P2PKHCoinAddress],
                    pubkey: Union[CPubKey, bytes, bytearray],
                    *,
                    accept_invalid: bool = False,
                    accept_uncompressed: bool = False) -> T_P2PKHCoinAddress:
        """Create a P2PKH address from a pubkey

        Raises CCoinAddressError if pubkey is invalid, unless accept_invalid
        is True.

        The pubkey must be a bytes instance;
        """
        ensure_isinstance(pubkey, (CPubKey, bytes, bytearray), 'pubkey')

        if not accept_invalid:
            if not isinstance(pubkey, CPubKey):
                pubkey = CPubKey(pubkey)
            if not pubkey.is_fullyvalid():
                raise P2PKHCoinAddressError('invalid pubkey')
            if (not pubkey.is_compressed()) and (not accept_uncompressed):
                raise P2PKHCoinAddressError(
                    'Uncompressed pubkeys are not allowed '
                    '(specify accept_uncompressed=True to allow)')

        pubkey_hash = bitcointx.core.Hash160(pubkey)
        return cls.from_bytes(pubkey_hash)

    @classmethod
    def from_scriptPubKey(cls: Type[T_P2PKHCoinAddress],
                          scriptPubKey: CScript) -> T_P2PKHCoinAddress:
        """Convert a scriptPubKey to a P2PKH address
        Raises CCoinAddressError if the scriptPubKey isn't of the correct
        form.
        """
        if scriptPubKey.is_p2pkh():
            return cls.from_bytes(scriptPubKey[3:23])

        raise P2PKHCoinAddressError('not a P2PKH scriptPubKey')

    def to_scriptPubKey(self) -> CScript:
        """Convert an address to a scriptPubKey"""
        return standard_keyhash_scriptpubkey(self)

    def to_redeemScript(self) -> CScript:
        return self.to_scriptPubKey()

    @classmethod
    def from_redeemScript(cls: Type[T_P2PKHCoinAddress],
                          redeemScript: CScript) -> T_P2PKHCoinAddress:
        return cls.from_scriptPubKey(redeemScript)


T_P2WSHCoinAddress = TypeVar('T_P2WSHCoinAddress', bound='P2WSHCoinAddress')


class P2WSHCoinAddress(CBech32CoinAddress, next_dispatch_final=True):
    _data_length = 32
    bech32_witness_version = 0
    _scriptpubkey_type = 'witness_v0_scripthash'

    @classmethod
    def from_scriptPubKey(cls: Type[T_P2WSHCoinAddress],
                          scriptPubKey: CScript) -> T_P2WSHCoinAddress:
        """Convert a scriptPubKey to a P2WSH address

        Raises CCoinAddressError if the scriptPubKey isn't of the correct
        form.
        """
        if scriptPubKey.is_witness_v0_scripthash():
            return cls.from_bytes(scriptPubKey[2:34])
        else:
            raise P2WSHCoinAddressError('not a P2WSH scriptPubKey')

    @classmethod
    def from_redeemScript(cls: Type[T_P2WSHCoinAddress],
                          redeemScript: CScript) -> T_P2WSHCoinAddress:
        """Convert a redeemScript to a P2WSH address

        Convenience function: equivalent to
        P2WSHBitcoinAddress.from_scriptPubKey(redeemScript.to_p2wsh_scriptPubKey())
        """
        return cls.from_scriptPubKey(redeemScript.to_p2wsh_scriptPubKey())

    def to_scriptPubKey(self) -> CScript:
        """Convert an address to a scriptPubKey"""
        return CScript([0, self])

    # Return type deliberately incompatible with CCoinAddress,
    # because this operation is not defined for p2wsh address
    def to_redeemScript(self) -> None:  # type: ignore
        raise NotImplementedError(
            "not enough data in p2wsh address to reconstruct redeem script")


T_P2WPKHCoinAddress = TypeVar('T_P2WPKHCoinAddress', bound='P2WPKHCoinAddress')


class P2WPKHCoinAddress(CBech32CoinAddress, next_dispatch_final=True):
    _data_length = 20
    bech32_witness_version = 0
    _scriptpubkey_type = 'witness_v0_keyhash'

    @classmethod
    def from_pubkey(cls: Type[T_P2WPKHCoinAddress],
                    pubkey: Union[CPubKey, bytes, bytearray],
                    *,
                    accept_invalid: bool = False) -> T_P2WPKHCoinAddress:
        """Create a P2WPKH address from a pubkey

        Raises CCoinAddressError if pubkey is invalid, unless accept_invalid
        is True.

        The pubkey must be a bytes instance;
        """
        ensure_isinstance(pubkey, (CPubKey, bytes, bytearray), 'pubkey')

        if not accept_invalid:
            if not isinstance(pubkey, CPubKey):
                pubkey = CPubKey(pubkey)
            if not pubkey.is_fullyvalid():
                raise P2PKHCoinAddressError('invalid pubkey')
            if not pubkey.is_compressed():
                raise P2PKHCoinAddressError(
                    'Uncompressed pubkeys are not allowed')

        pubkey_hash = bitcointx.core.Hash160(pubkey)
        return cls.from_bytes(pubkey_hash)

    @classmethod
    def from_scriptPubKey(cls: Type[T_P2WPKHCoinAddress],
                          scriptPubKey: CScript) -> T_P2WPKHCoinAddress:
        """Convert a scriptPubKey to a P2WPKH address

        Raises CCoinAddressError if the scriptPubKey isn't of the correct
        form.
        """
        if scriptPubKey.is_witness_v0_keyhash():
            return cls.from_bytes(scriptPubKey[2:22])
        else:
            raise P2WPKHCoinAddressError('not a P2WPKH scriptPubKey')

    def to_scriptPubKey(self) -> CScript:
        """Convert an address to a scriptPubKey"""
        return CScript([0, self])

    def to_redeemScript(self) -> CScript:
        return standard_keyhash_scriptpubkey(self)

    @classmethod
    def from_redeemScript(cls: Type[T_P2WPKHCoinAddress],
                          redeemScript: CScript) -> T_P2WPKHCoinAddress:
        raise NotImplementedError


T_P2TRCoinAddress = TypeVar('T_P2TRCoinAddress', bound='P2TRCoinAddress')


class P2TRCoinAddress(CBech32CoinAddress, next_dispatch_final=True):
    _data_length = 32
    bech32_witness_version = 1
    _scriptpubkey_type = 'witness_v1_taproot'

    @classmethod
    def from_xonly_output_pubkey(
        cls: Type[T_P2TRCoinAddress],
        pubkey: Union[XOnlyPubKey, bytes, bytearray],
        *,
        accept_invalid: bool = False
    ) -> T_P2TRCoinAddress:
        """Create a P2TR address from x-only pubkey that is already tweaked,
        the "output pubkey" in the terms of BIP341

        Raises CCoinAddressError if pubkey is invalid, unless accept_invalid
        is True.
        """
        ensure_isinstance(pubkey, (XOnlyPubKey, bytes, bytearray), 'pubkey')

        if not accept_invalid:
            if not isinstance(pubkey, XOnlyPubKey):
                try:
                    pubkey = XOnlyPubKey(pubkey)
                except ValueError as e:
                    raise P2TRCoinAddressError(f'problem with pubkey: {e}')
            if not pubkey.is_fullyvalid():
                raise P2TRCoinAddressError('invalid x-only pubkey')

        return cls.from_bytes(pubkey)

    @classmethod
    def from_xonly_pubkey(
        cls: Type[T_P2TRCoinAddress],
        pubkey: Union[XOnlyPubKey, bytes, bytearray]
    ) -> T_P2TRCoinAddress:
        """Create a P2TR address from x-only "internal" pubkey (in BIP341 terms).
        The pubkey will be tweaked with the tagged hash of itself, to make
        the output pubkey commit to an unspendable script path, as recommended
        by BIP341 (see note 22 in BIP341).

        Raises CCoinAddressError if pubkey is invalid
        """
        ensure_isinstance(pubkey, (XOnlyPubKey, bytes, bytearray), 'pubkey')

        if not isinstance(pubkey, XOnlyPubKey):
            pubkey = XOnlyPubKey(pubkey)

        if not pubkey.is_fullyvalid():
            raise P2TRCoinAddressError('invalid pubkey')

        tt_res = tap_tweak_pubkey(pubkey)

        if not tt_res:
            raise P2TRCoinAddressError('cannot create tap tweak from supplied pubkey')

        out_pub, _ = tt_res

        return cls.from_xonly_output_pubkey(out_pub)

    @classmethod
    def from_output_pubkey(cls: Type[T_P2TRCoinAddress],
                           pubkey: Union[CPubKey, bytes, bytearray],
                           *,
                           accept_invalid: bool = False) -> T_P2TRCoinAddress:
        """Create a P2TR address from a pubkey that is already tweaked,
        the "output pubkey" in the terms of BIP341

        Raises CCoinAddressError if pubkey is invalid, unless accept_invalid
        is True.
        """
        ensure_isinstance(pubkey, (XOnlyPubKey, CPubKey, bytes, bytearray),
                          'pubkey')

        if len(pubkey) == 32:
            if not isinstance(pubkey, CPubKey):  # might be invalid CPubKey
                return cls.from_xonly_output_pubkey(
                    pubkey, accept_invalid=accept_invalid)

        if not accept_invalid:
            if not isinstance(pubkey, CPubKey):
                pubkey = CPubKey(pubkey)
            if not pubkey.is_fullyvalid():
                raise P2TRCoinAddressError('invalid pubkey')
            if not pubkey.is_compressed():
                raise P2TRCoinAddressError(
                    'Uncompressed pubkeys are not allowed')
        elif isinstance(pubkey, CPubKey):
            # XOnlyPubKey() will check validity of supplied pubkey before
            # stripping its first byte. We strip it here without
            # checking validity, becasue accept_invalid is True
            pubkey = pubkey[1:33]

        return cls.from_xonly_output_pubkey(XOnlyPubKey(pubkey),
                                            accept_invalid=accept_invalid)

    @classmethod
    def from_pubkey(cls: Type[T_P2TRCoinAddress],
                    pubkey: Union[XOnlyPubKey, CPubKey, bytes, bytearray],
                    ) -> T_P2TRCoinAddress:
        """Create a P2TR address from "internal" pubkey (in BIP341 terms)

        Raises CCoinAddressError if pubkey is invalid
        """
        ensure_isinstance(pubkey, (XOnlyPubKey, CPubKey, bytes, bytearray),
                          'pubkey')

        if not isinstance(pubkey, CPubKey):

            if len(pubkey) == 32:
                return cls.from_xonly_pubkey(pubkey)

            pubkey = CPubKey(pubkey)

        if not pubkey.is_fullyvalid():
            raise P2TRCoinAddressError('invalid pubkey')

        if not pubkey.is_compressed():
            raise P2TRCoinAddressError(
                'Uncompressed pubkeys are not allowed')

        return cls.from_xonly_pubkey(XOnlyPubKey(pubkey))

    @classmethod
    def from_script_tree(cls: Type[T_P2TRCoinAddress],
                         stree: TaprootScriptTree) -> T_P2TRCoinAddress:
        """Create a P2TR address from TaprootScriptTree instance
        """
        if not stree.internal_pubkey:
            raise P2TRCoinAddressError(
                f'The supplied instance of {stree.__class__.__name__} '
                f'does not have internal_pubkey')
        assert stree.output_pubkey is not None
        return cls.from_xonly_output_pubkey(stree.output_pubkey)

    @classmethod
    def from_scriptPubKey(cls: Type[T_P2TRCoinAddress],
                          scriptPubKey: CScript) -> T_P2TRCoinAddress:
        """Convert a scriptPubKey to a P2TR address

        Raises CCoinAddressError if the scriptPubKey isn't of the correct
        form.

        Note that there is no check if the x-only pubkey included in the
        scriptPubKey is a valid pubkey
        """
        if scriptPubKey.is_witness_v1_taproot():
            return cls.from_bytes(scriptPubKey[2:34])
        else:
            raise P2TRCoinAddressError('not a P2TR scriptPubKey')

    def to_scriptPubKey(self) -> CScript:
        """Convert an address to a scriptPubKey"""
        return CScript([1, self])

    # Return type deliberately incompatible with CCoinAddress,
    # because this operation is not defined for p2tr address
    def to_redeemScript(self) -> None:  # type: ignore
        raise NotImplementedError(
            "not enough data in p2tr address to reconstruct redeem script")


class CBitcoinAddress(CCoinAddress, WalletBitcoinClass):
    ...


class CBitcoinTestnetAddress(CCoinAddress, WalletBitcoinTestnetClass):
    ...


class CBitcoinRegtestAddress(CCoinAddress, WalletBitcoinRegtestClass):
    ...


class CBitcoinSignetAddress(CCoinAddress, WalletBitcoinSignetClass):
    ...


class CBase58BitcoinAddress(CBase58CoinAddress, CBitcoinAddress):
    ...


class CBase58BitcoinTestnetAddress(CBase58CoinAddress, CBitcoinTestnetAddress):
    ...


class CBase58BitcoinRegtestAddress(CBase58CoinAddress, CBitcoinRegtestAddress):
    ...


class CBase58BitcoinSignetAddress(CBase58CoinAddress, CBitcoinSignetAddress):
    ...


class CBech32BitcoinAddress(CBech32CoinAddress, CBitcoinAddress):
    bech32_hrp = 'bc'


class CBech32BitcoinTestnetAddress(CBech32CoinAddress,
                                   CBitcoinTestnetAddress):
    bech32_hrp = 'tb'


class CBech32BitcoinSignetAddress(CBech32CoinAddress,
                                  CBitcoinSignetAddress):
    bech32_hrp = 'tb'


class CBech32BitcoinRegtestAddress(CBech32CoinAddress,
                                   CBitcoinRegtestAddress):
    bech32_hrp = 'bcrt'


class P2SHBitcoinAddress(P2SHCoinAddress, CBase58BitcoinAddress):
    base58_prefix = bytes([5])


class P2PKHBitcoinAddress(P2PKHCoinAddress, CBase58BitcoinAddress):
    base58_prefix = bytes([0])


class P2PKHBitcoinTestnetAddress(P2PKHCoinAddress,
                                 CBase58BitcoinTestnetAddress):
    base58_prefix = bytes([111])


class P2SHBitcoinTestnetAddress(P2SHCoinAddress,
                                CBase58BitcoinTestnetAddress):
    base58_prefix = bytes([196])


class P2PKHBitcoinRegtestAddress(P2PKHCoinAddress,
                                 CBase58BitcoinRegtestAddress):
    base58_prefix = bytes([111])


class P2PKHBitcoinSignetAddress(P2PKHCoinAddress,
                                CBase58BitcoinSignetAddress):
    base58_prefix = bytes([111])


class P2SHBitcoinRegtestAddress(P2SHCoinAddress,
                                CBase58BitcoinRegtestAddress):
    base58_prefix = bytes([196])


class P2SHBitcoinSignetAddress(P2SHCoinAddress,
                               CBase58BitcoinSignetAddress):
    base58_prefix = bytes([196])


class P2WSHBitcoinAddress(P2WSHCoinAddress, CBech32BitcoinAddress):
    ...


class P2WPKHBitcoinAddress(P2WPKHCoinAddress, CBech32BitcoinAddress):
    ...


class P2TRBitcoinAddress(P2TRCoinAddress, CBech32BitcoinAddress):
    ...


class P2WSHBitcoinTestnetAddress(P2WSHCoinAddress,
                                 CBech32BitcoinTestnetAddress):
    ...


class P2WPKHBitcoinTestnetAddress(P2WPKHCoinAddress,
                                  CBech32BitcoinTestnetAddress):
    ...


class P2TRBitcoinTestnetAddress(P2TRCoinAddress,
                                CBech32BitcoinTestnetAddress):
    ...


class P2WSHBitcoinRegtestAddress(P2WSHCoinAddress,
                                 CBech32BitcoinRegtestAddress):
    ...


class P2WPKHBitcoinRegtestAddress(P2WPKHCoinAddress,
                                  CBech32BitcoinRegtestAddress):
    ...


class P2TRBitcoinRegtestAddress(P2TRCoinAddress,
                                CBech32BitcoinRegtestAddress):
    ...


class P2WSHBitcoinSignetAddress(P2WSHCoinAddress,
                                CBech32BitcoinSignetAddress):
    ...


class P2WPKHBitcoinSignetAddress(P2WPKHCoinAddress,
                                 CBech32BitcoinSignetAddress):
    ...


class P2TRBitcoinSignetAddress(P2TRCoinAddress,
                               CBech32BitcoinSignetAddress):
    ...


T_CCoinKey = TypeVar('T_CCoinKey', bound='CCoinKey')


class CCoinKey(CBase58DataDispatched, CKeyBase,
               WalletCoinClass, next_dispatch_final=True):
    """A base58-encoded secret key

    Attributes: (inherited from CKeyBase):

    pub           - The corresponding CPubKey for this private key
    secret_bytes  - Secret data, 32 bytes

    is_compressed() - True if compressed

    Note that CBase58CoinKeyBase instance is 33 bytes long if compressed,
    32 bytes otherwise (due to WIF format that states b'\x01' should be
    appended for compressed keys).
    secret_bytes property is 32 bytes long in both cases.
    """

    def __init__(self, _s: str) -> None:
        data = self
        if len(data) > 33:
            raise ValueError('data size must not exceed 33 bytes')
        compressed = (len(data) > 32 and data[32] == 1)
        CKeyBase.__init__(self, None, compressed=compressed)

    @classmethod
    def from_secret_bytes(cls: Type[T_CCoinKey],
                          secret: bytes, compressed: bool = True
                          ) -> T_CCoinKey:
        """Create a secret key from a 32-byte secret"""
        if len(secret) != 32:
            raise ValueError('secret size must be exactly 32 bytes')
        return cls.from_bytes(secret + (b'\x01' if compressed else b''))

    def to_compressed(self: T_CCoinKey) -> T_CCoinKey:
        if self.is_compressed():
            return self
        return self.__class__.from_secret_bytes(self[:32], True)

    def to_uncompressed(self: T_CCoinKey) -> T_CCoinKey:
        if not self.is_compressed():
            return self
        return self.__class__.from_secret_bytes(self[:32], False)

    def sign_schnorr_tweaked(
        self, hash: Union[bytes, bytearray],
        *,
        merkle_root: bytes = b'',
        aux: Optional[bytes] = None
    ) -> bytes:
        """Schnorr-sign with the key that is tweaked before signing.

        When merkle_root is empty bytes, the tweak will be generated
        as a tagged hash of the x-only pubkey that corresponds to this
        private key. Supplying empty-bytes merkle_root (the default) is
        mostly useful when signing keypath spends when there is no script path.

        When merkle_root is 32 bytes, it will be directly used as a tweak.
        This is mostly useful when signing keypath spends when there is also
        a script path present
        """
        return self._sign_schnorr_internal(
            hash, merkle_root=merkle_root, aux=aux)


class CBitcoinKey(CCoinKey, WalletBitcoinClass):
    base58_prefix = bytes([128])


class CBitcoinSecret(CBitcoinKey, variant_of=CBitcoinKey):
    """a backwards-compatibility class for CBitcoinKey"""
    ...


class CBitcoinTestnetKey(CCoinKey, WalletBitcoinTestnetClass):
    base58_prefix = bytes([239])


class CBitcoinRegtestKey(CCoinKey, WalletBitcoinRegtestClass):
    base58_prefix = bytes([239])


class CBitcoinSignetKey(CCoinKey, WalletBitcoinSignetClass):
    base58_prefix = bytes([239])


class CCoinExtPubKey(CBase58DataDispatched, CExtPubKeyBase,
                     WalletCoinClass, next_dispatch_final=True):

    def __init__(self, _s: str) -> None:
        assert isinstance(self, CExtPubKeyBase)
        CExtPubKeyBase.__init__(self, None)


class CCoinExtKey(CBase58DataDispatched, CExtKeyBase,
                  WalletCoinClass, next_dispatch_final=True):

    neuter: ClassVar[Callable[['CCoinExtKey'], CCoinExtPubKey]]

    def __init__(self, _s: str) -> None:
        assert isinstance(self, CExtKeyBase)
        CExtKeyBase.__init__(self, None)

    @property
    def _xpub_class(self) -> Type[CCoinExtPubKey]:
        return cast(Type[CCoinExtPubKey],
                    dispatcher_mapped_list(CCoinExtPubKey)[0])

    @property
    def _key_class(self) -> Type[CCoinKey]:
        return cast(Type[CCoinKey],
                    dispatcher_mapped_list(CCoinKey)[0])


class CBitcoinExtPubKey(CCoinExtPubKey, WalletBitcoinClass):
    """A base58-encoded extended public key

    Attributes (inherited from CExtPubKeyBase):

    pub           - The corresponding CPubKey for extended pubkey
    """

    base58_prefix = b'\x04\x88\xB2\x1E'


class CBitcoinExtKey(CCoinExtKey, WalletBitcoinClass):
    """A base58-encoded extended key

    Attributes (inherited from key mixin class):

    pub           - The corresponding CPubKey for extended pubkey
    priv          - The corresponding CBitcoinKey for extended privkey
    """

    base58_prefix = b'\x04\x88\xAD\xE4'


class CBitcoinTestnetExtPubKey(CCoinExtPubKey, WalletBitcoinTestnetClass):
    base58_prefix = b'\x04\x35\x87\xCF'


class CBitcoinTestnetExtKey(CCoinExtKey, WalletBitcoinTestnetClass):
    base58_prefix = b'\x04\x35\x83\x94'


class CBitcoinRegtestExtPubKey(CCoinExtPubKey, WalletBitcoinRegtestClass):
    base58_prefix = b'\x04\x35\x87\xCF'


class CBitcoinRegtestExtKey(CCoinExtKey, WalletBitcoinRegtestClass):
    base58_prefix = b'\x04\x35\x83\x94'


class CBitcoinSignetExtPubKey(CCoinExtPubKey, WalletBitcoinSignetClass):
    base58_prefix = b'\x04\x35\x87\xCF'


class CBitcoinSignetExtKey(CCoinExtKey, WalletBitcoinSignetClass):
    base58_prefix = b'\x04\x35\x83\x94'


# default dispatcher for the module
activate_class_dispatcher(WalletBitcoinClassDispatcher)

__all__ = (
    'CCoinAddressError',
    'P2SHCoinAddressError',
    'P2PKHCoinAddressError',
    'P2WSHCoinAddressError',
    'P2WPKHCoinAddressError',
    'P2TRCoinAddressError',
    'CCoinAddress',
    'CBitcoinAddress',
    'CBitcoinTestnetAddress',
    'CBase58BitcoinAddress',
    'CBech32BitcoinAddress',
    'P2SHCoinAddress',
    'P2PKHCoinAddress',
    'P2WSHCoinAddress',
    'P2WPKHCoinAddress',
    'P2TRCoinAddress',
    'P2SHBitcoinAddress',
    'P2PKHBitcoinAddress',
    'P2WSHBitcoinAddress',
    'P2WPKHBitcoinAddress',
    'P2TRBitcoinAddress',
    'CBase58BitcoinTestnetAddress',
    'CBech32BitcoinTestnetAddress',
    'P2SHBitcoinTestnetAddress',
    'P2PKHBitcoinTestnetAddress',
    'P2WSHBitcoinTestnetAddress',
    'P2WPKHBitcoinTestnetAddress',
    'P2TRBitcoinTestnetAddress',
    'P2SHBitcoinRegtestAddress',
    'P2PKHBitcoinRegtestAddress',
    'P2WSHBitcoinRegtestAddress',
    'P2WPKHBitcoinRegtestAddress',
    'P2TRBitcoinRegtestAddress',
    'P2SHBitcoinSignetAddress',
    'P2PKHBitcoinSignetAddress',
    'P2WSHBitcoinSignetAddress',
    'P2WPKHBitcoinSignetAddress',
    'P2TRBitcoinSignetAddress',
    'CCoinKey',
    'CCoinExtKey',
    'CCoinExtPubKey',
    'CBitcoinKey',
    'CBitcoinSecret',  # backwards-compatible naming for CBitcoinKey
    'CBitcoinExtKey',
    'CBitcoinExtPubKey',
    'CBitcoinTestnetKey',
    'CBitcoinTestnetExtKey',
    'CBitcoinTestnetExtPubKey',
    'CBitcoinRegtestKey',
    'CBitcoinRegtestExtKey',
    'CBitcoinRegtestExtPubKey',
    'WalletCoinClassDispatcher',
    'WalletCoinClass',
    'WalletBitcoinClassDispatcher',
    'WalletBitcoinClass',
)
