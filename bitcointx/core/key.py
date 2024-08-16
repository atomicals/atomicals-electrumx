# Copyright (C) 2011 Sam Rushing
# Copyright (C) 2012-2015 The python-bitcoinlib developers
# Copyright (C) 2018-2021 The python-bitcointx developers
#
# This file is part of python-bitcointx.
#
# It is subject to the license terms in the LICENSE-PYTHON-BITCOINTX file found in the top-level
# directory of this distribution.
#
# No part of python-bitcointx, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

# pylama:ignore=E501,E261,E221

"""ECC secp256k1 crypto routines

WARNING: This module does not mlock() secrets; your private keys may end up on
disk in swap! Use with caution!
"""

import hmac
import struct
import ctypes
import ctypes.util
import hashlib
import warnings
from abc import abstractmethod
from typing import (
    TypeVar, Type, Union, Tuple, List, Sequence, Optional, Iterator, cast,
    Dict, Any, Iterable, Callable, Generic, ClassVar
)

import bitcointx.core
from bitcointx.util import no_bool_use_as_property, ensure_isinstance
from bitcointx.core.secp256k1 import (
    get_secp256k1,
    SIGNATURE_SIZE, COMPACT_SIGNATURE_SIZE,
    PUBLIC_KEY_SIZE, COMPRESSED_PUBLIC_KEY_SIZE,
    SECP256K1_EC_COMPRESSED, SECP256K1_EC_UNCOMPRESSED,
)
from bitcointx.core.ecdasig_parse_der_lax import ecdsa_signature_parse_der_lax

BIP32_HARDENED_KEY_OFFSET = 0x80000000

T_CKeyBase = TypeVar('T_CKeyBase', bound='CKeyBase')
T_CExtKeyCommonBase = TypeVar('T_CExtKeyCommonBase', bound='CExtKeyCommonBase')
T_CExtKeyBase = TypeVar('T_CExtKeyBase', bound='CExtKeyBase')
T_CExtPubKeyBase = TypeVar('T_CExtPubKeyBase', bound='CExtPubKeyBase')
T_unbounded = TypeVar('T_unbounded')


class KeyDerivationFailException(RuntimeError):
    pass


def _module_unavailable_error(msg: str, module_name: str) -> str:
    return (
        f'{msg} handling functions from libsecp256k1 is not available. '
        f'configure it libsecp256k1 with --enable-module-{module_name}'
    )


def _raw_sig_has_low_r(raw_sig: bytes) -> bool:
    compact_sig = ctypes.create_string_buffer(64)
    secp256k1 = get_secp256k1()
    result = secp256k1.lib.secp256k1_ecdsa_signature_serialize_compact(
        secp256k1.ctx.sign, compact_sig, raw_sig)
    assert result == 1

    # In DER serialization, all values are interpreted as big-endian,
    # signed integers. The highest bit in the integer indicates
    # its signed-ness; 0 is positive, 1 is negative.
    # When the value is interpreted as a negative integer,
    # it must be converted to a positive value by prepending a 0x00 byte
    # so that the highest bit is 0. We can avoid this prepending by ensuring
    # that our highest bit is always 0, and thus we must check that the
    # first byte is less than 0x80.
    return compact_sig.raw[0] < 0x80


class CKeyBase:
    """An encapsulated private key

    Attributes:

    pub           - The corresponding CPubKey for this private key
    secret_bytes  - Secret data, 32 bytes (needed because subclasses may have trailing data)

    is_compressed() - True if compressed

    """

    __pub: 'CPubKey'

    def __init__(self, b: Optional[bytes], compressed: bool = True) -> None:
        raw_pubkey = ctypes.create_string_buffer(64)

        if len(self.secret_bytes) != 32:
            raise ValueError('secret data length too short')

        secp256k1 = get_secp256k1()

        result = secp256k1.lib.secp256k1_ec_seckey_verify(
            secp256k1.ctx.sign, self.secret_bytes)

        if result != 1:
            assert result == 0
            raise ValueError('Invalid private key data')

        result = secp256k1.lib.secp256k1_ec_pubkey_create(
            secp256k1.ctx.sign, raw_pubkey, self.secret_bytes)

        if result != 1:
            assert result == 0
            raise ValueError('Cannot construct public key from private key')

        self.__pub = CPubKey._from_ctypes_char_array(
            raw_pubkey, compressed=compressed)

    @no_bool_use_as_property
    def is_compressed(self) -> bool:
        return self.pub.is_compressed()

    @property
    def secret_bytes(self) -> bytes:
        assert isinstance(self, bytes)
        return self[:32]

    @property
    def pub(self) -> 'CPubKey':
        return self.__pub

    @property
    def xonly_pub(self) -> 'XOnlyPubKey':
        return XOnlyPubKey(self.__pub)

    def sign(self, hash: Union[bytes, bytearray], *,
             _ecdsa_sig_grind_low_r: bool = True,
             _ecdsa_sig_extra_entropy: int = 0
             ) -> bytes:

        ensure_isinstance(hash, (bytes, bytearray), 'hash')
        if len(hash) != 32:
            raise ValueError('Hash must be exactly 32 bytes long')

        raw_sig = ctypes.create_string_buffer(64)

        if _ecdsa_sig_grind_low_r:
            counter = 0
        else:
            counter = _ecdsa_sig_extra_entropy

        def maybe_extra_entropy() -> Optional[bytes]:
            if counter == 0:
                return None

            # mimic Bitcoin Core that uses 32-bit counter for the entropy
            assert counter < 2**32
            return counter.to_bytes(4, byteorder="little") + b'\x00'*28

        secp256k1 = get_secp256k1()

        while True:
            result = secp256k1.lib.secp256k1_ecdsa_sign(
                secp256k1.ctx.sign, raw_sig, hash, self.secret_bytes, None,
                maybe_extra_entropy())
            if 1 != result:
                assert result == 0
                raise RuntimeError('secp256k1_ecdsa_sign returned failure')

            if not _ecdsa_sig_grind_low_r or _raw_sig_has_low_r(raw_sig.raw):
                break

            counter += 1

        sig_size0 = ctypes.c_size_t()
        sig_size0.value = SIGNATURE_SIZE
        mb_sig = ctypes.create_string_buffer(SIGNATURE_SIZE)

        result = secp256k1.lib.secp256k1_ecdsa_signature_serialize_der(
            secp256k1.ctx.sign, mb_sig, ctypes.byref(sig_size0), raw_sig)
        if 1 != result:
            assert result == 0
            raise RuntimeError('secp256k1_ecdsa_signature_parse_der returned failure')

        # secp256k1 creates signatures already in lower-S form, no further
        # conversion needed.
        return mb_sig.raw[:sig_size0.value]

    def sign_compact(self, hash: Union[bytes, bytearray]) -> Tuple[bytes, int]:  # pylint: disable=redefined-builtin
        ensure_isinstance(hash, (bytes, bytearray), 'hash')
        if len(hash) != 32:
            raise ValueError('Hash must be exactly 32 bytes long')

        secp256k1 = get_secp256k1()

        if not secp256k1.cap.has_pubkey_recovery:
            raise RuntimeError('secp256k1 compiled without pubkey recovery functions. '
                               'sign_compact is not functional.')

        secp256k1 = get_secp256k1()

        recoverable_sig = ctypes.create_string_buffer(COMPACT_SIGNATURE_SIZE)

        result = secp256k1.lib.secp256k1_ecdsa_sign_recoverable(
            secp256k1.ctx.sign, recoverable_sig, hash, self.secret_bytes, None, None)

        if 1 != result:
            assert result == 0
            raise RuntimeError('secp256k1_ecdsa_sign_recoverable returned failure')

        recid = ctypes.c_int()
        recid.value = 0
        output = ctypes.create_string_buffer(64)
        result = secp256k1.lib.secp256k1_ecdsa_recoverable_signature_serialize_compact(
            secp256k1.ctx.sign, output, ctypes.byref(recid), recoverable_sig)

        if 1 != result:
            assert result == 0
            raise RuntimeError('secp256k1_ecdsa_recoverable_signature_serialize_compact returned failure')

        return output.raw, recid.value

    def sign_schnorr_no_tweak(
        self, hash: Union[bytes, bytearray],
        *,
        aux: Optional[bytes] = None
    ) -> bytes:
        """
        Produce Schnorr signature of the supplied `hash` with this key.
        No tweak is applied to the key before signing.
        This is mostly useful when the signature is going to be checked
        within the script by CHECKSIG-related opcodes, or for other generic
        Schnorr signing needs
        """
        return self._sign_schnorr_internal(hash, aux=aux)

    def _sign_schnorr_internal(  # noqa
        self, hash: Union[bytes, bytearray],
        *,
        merkle_root: Optional[bytes] = None,
        aux: Optional[bytes] = None
    ) -> bytes:
        """
        Internal function to produce Schnorr signature.
        It is not supposed to be called by the external code.

        Note on merkle_root argument: values of None, b'' and <32 bytes>
        all have different meaning.
           - None means no tweak is applied to the key before signing.
             This is mostly useful when the signature is going to be checked
             within the script by CHECKSIG-related opcodes, or for other
             generic Schnorr signing needs
           - b'' means that the tweak will be applied, with merkle_root
             being generated as the tagged hash of the x-only pubkey
             corresponding to this private key. This is mostly useful
             when signing keypath spends when there is no script path
           - <32 bytes> are used directly as a tweak. This is mostly useful
             when signing keypath spends when there is also a script path
             present
        """

        ensure_isinstance(hash, (bytes, bytearray), 'hash')
        if len(hash) != 32:
            raise ValueError('Hash must be exactly 32 bytes long')

        secp256k1 = get_secp256k1()
        if not secp256k1.cap.has_schnorrsig:
            raise RuntimeError(
                _module_unavailable_error('schnorr signature', 'schnorrsig'))

        if aux is not None:
            ensure_isinstance(aux, (bytes, bytearray), 'aux')
            if len(aux) != 32:
                raise ValueError('aux must be exactly 32 bytes long')

        sizeof_keypair = 96
        keypair_buf = ctypes.create_string_buffer(sizeof_keypair)

        secp256k1 = get_secp256k1()

        result = secp256k1.lib.secp256k1_keypair_create(
            secp256k1.ctx.sign, keypair_buf, self)

        if 1 != result:
            assert result == 0
            raise RuntimeError('secp256k1_keypair_create returned failure')

        pubkey_buf = ctypes.create_string_buffer(64)

        if merkle_root is not None:
            ensure_isinstance(merkle_root, (bytes, bytearray), 'merkle_root')

            result = secp256k1.lib.secp256k1_keypair_xonly_pub(
                secp256k1.ctx.sign, pubkey_buf, None, keypair_buf)

            if 1 != result:
                assert result == 0
                raise RuntimeError('secp256k1_keypair_xonly_pub returned failure')

            # It should take one less secp256k1 call if we just take self.pub
            # here, because XOnlyPubKey(self.pub) will just drop the first
            # byte of self.pub data and will make x-only pubkey from that.
            # But the code is translated from CKey::SignSchnorr in Bitcon Core,
            # so one extra secp256k1 call here to be close to original source

            serialized_pubkey_buf = ctypes.create_string_buffer(32)
            result = secp256k1.lib.secp256k1_xonly_pubkey_serialize(
                secp256k1.ctx.verify, serialized_pubkey_buf, pubkey_buf)

            if 1 != result:
                assert result == 0
                raise RuntimeError('secp256k1_xonly_pubkey_serialize returned failure')

            tweak = compute_tap_tweak_hash(
                XOnlyPubKey(serialized_pubkey_buf.raw),
                merkle_root=merkle_root)

            result = secp256k1.lib.secp256k1_keypair_xonly_tweak_add(
                secp256k1.ctx.sign, keypair_buf, tweak)

            if 1 != result:
                assert result == 0
                raise RuntimeError('secp256k1_keypair_xonly_tweak_add returned failure')

        sig_buf = ctypes.create_string_buffer(64)
        result = secp256k1.lib.secp256k1_schnorrsig_sign(
            secp256k1.ctx.sign, sig_buf, hash, keypair_buf, aux)

        if 1 != result:
            assert result == 0
            raise RuntimeError('secp256k1_schnorrsig_sign returned failure')

        # The pubkey may be tweaked, so extract it from keypair
        # to do verification after signing
        result = secp256k1.lib.secp256k1_keypair_xonly_pub(
            secp256k1.ctx.sign, pubkey_buf, None, keypair_buf)

        if 1 != result:
            assert result == 0
            raise RuntimeError('secp256k1_keypair_xonly_pub returned failure')

        # This check is not in Bitcoin Core's `CKey::SignSchnorr`, but
        # is recommended in BIP340 if the computation cost is not a concern
        result = secp256k1.lib.secp256k1_schnorrsig_verify(
            secp256k1.ctx.verify, sig_buf.raw, hash, 32, pubkey_buf)

        if result != 1:
            assert result == 0
            raise RuntimeError(
                'secp256k1_schnorrsig_verify failed after signing')

        # There's no C compiler that can optimize out the 'superfluous' memset,
        # so we don't need special memory_cleanse() function.
        # Not that it matters much in python where we don't have control over
        # memory and the keydata is probably spread all over the place anyway,
        # but still, do this to be close to the original source
        ctypes.memset(keypair_buf, 0, sizeof_keypair)

        return sig_buf.raw

    def verify(self, hash: bytes, sig: bytes) -> bool:
        return self.pub.verify(hash, sig)

    def verify_nonstrict(self, hash: bytes, sig: bytes) -> bool:
        return self.pub.verify_nonstrict(hash, sig)

    def verify_schnorr(self, msg: bytes, sig: bytes) -> bool:
        return XOnlyPubKey(self.pub).verify_schnorr(msg, sig)

    def ECDH(self, pub: Optional['CPubKey'] = None) -> bytes:
        secp256k1 = get_secp256k1()
        if not secp256k1.cap.has_ecdh:
            raise RuntimeError(
                'secp256k1 compiled without ECDH shared secret computation functions. '
                'ECDH is not functional.')

        if pub is None:
            pub = self.pub

        if not pub.is_fullyvalid():
            raise ValueError('supplied pubkey is not valid')

        secp256k1 = get_secp256k1()

        result_data = ctypes.create_string_buffer(32)
        ret = secp256k1.lib.secp256k1_ecdh(secp256k1.ctx.sign, result_data,
                                           pub._to_ctypes_char_array(), self,
                                           None, None)
        if 1 != ret:
            assert ret == 0
            raise RuntimeError('secp256k1_ecdh returned failure')

        return result_data.raw

    @classmethod
    def combine(cls: Type[T_CKeyBase], *privkeys: T_CKeyBase,
                compressed: bool = True) -> T_CKeyBase:
        if len(privkeys) <= 1:
            raise ValueError(
                'number of privkeys to combine must be more than one')
        if not all(isinstance(k, CKeyBase) for k in privkeys):
            raise ValueError(
                'each supplied privkey must be an instance of CKeyBase')

        secp256k1 = get_secp256k1()

        result_data = ctypes.create_string_buffer((privkeys[0]).secret_bytes)
        for p in privkeys[1:]:
            ret = secp256k1.lib.secp256k1_ec_privkey_tweak_add(
                secp256k1.ctx.sign, result_data, p.secret_bytes)
            if ret != 1:
                assert ret == 0
                raise ValueError('Combining the keys failed')

        return cls.from_secret_bytes(result_data.raw[:32], compressed=compressed)

    @classmethod
    def add(cls: Type[T_CKeyBase], a: T_CKeyBase, b: T_CKeyBase) -> T_CKeyBase:
        if a.is_compressed() != b.is_compressed():
            raise ValueError("compressed attributes must match on "
                             "privkey addition/substraction")
        return cls.combine(a, b, compressed=a.is_compressed())

    @classmethod
    def sub(cls: Type[T_CKeyBase], a: T_CKeyBase, b: T_CKeyBase) -> T_CKeyBase:
        if a == b:
            raise ValueError('Values are equal, result would be zero, and '
                             'thus an invalid key.')
        return cls.add(a, b.negated())

    def negated(self: T_CKeyBase) -> T_CKeyBase:
        secp256k1 = get_secp256k1()
        if not secp256k1.cap.has_privkey_negate:
            raise RuntimeError(
                'secp256k1 does not export privkey negation function. '
                'You should use newer version of secp256k1 library')
        key_buf = ctypes.create_string_buffer(self.secret_bytes)
        ret = secp256k1.lib.secp256k1_ec_privkey_negate(secp256k1.ctx.sign, key_buf)
        if 1 != ret:
            assert ret == 0
            raise RuntimeError('secp256k1_ec_privkey_negate returned failure')
        return self.__class__.from_secret_bytes(key_buf.raw[:32], compressed=self.is_compressed())

    @classmethod
    def from_secret_bytes(cls: Type[T_CKeyBase],
                          secret: bytes, compressed: bool = True) -> T_CKeyBase:
        return cls(secret, compressed=compressed)

    @classmethod
    def from_bytes(cls: Type[T_unbounded], data: bytes) -> T_unbounded:
        raise NotImplementedError('subclasses must override from_bytes()')


class CKey(bytes, CKeyBase):
    "Standalone privkey class"

    def __new__(cls: Type['CKey'], secret: bytes, compressed: bool = True
                ) -> 'CKey':
        if len(secret) != 32:
            raise ValueError('secret size must be exactly 32 bytes')
        return super().__new__(cls, secret)


T_CPubKey = TypeVar('T_CPubKey', bound='CPubKey')


class CPubKey(bytes):
    """An encapsulated public key

    Attributes:

    key_id        - Hash160(pubkey)
    """

    __key_id: bytes
    __fullyvalid: bool

    def __new__(cls: Type[T_CPubKey], buf: bytes = b'') -> T_CPubKey:
        self = super().__new__(cls, buf)

        self.__fullyvalid = False
        if self.is_nonempty():
            tmp_pub = ctypes.create_string_buffer(64)
            secp256k1 = get_secp256k1()
            result = secp256k1.lib.secp256k1_ec_pubkey_parse(
                secp256k1.ctx.verify, tmp_pub, self, len(self))
            assert result in (1, 0)
            self.__fullyvalid = (result == 1)

        self.__key_id = bitcointx.core.Hash160(self)
        return self

    @classmethod
    def _from_ctypes_char_array(cls: Type[T_CPubKey],
                                raw_pubkey: 'ctypes.Array[ctypes.c_char]',
                                compressed: bool = True) -> T_CPubKey:
        if len(raw_pubkey) != 64:
            raise ValueError('raw pubkey must be 64 bytes')

        pub_size0 = ctypes.c_size_t()
        pub_size0.value = PUBLIC_KEY_SIZE
        pub = ctypes.create_string_buffer(pub_size0.value)

        secp256k1 = get_secp256k1()

        secp256k1.lib.secp256k1_ec_pubkey_serialize(
            secp256k1.ctx.verify, pub, ctypes.byref(pub_size0), raw_pubkey,
            SECP256K1_EC_COMPRESSED if compressed else SECP256K1_EC_UNCOMPRESSED)

        return cls(pub.raw[:pub_size0.value])

    def _to_ctypes_char_array(self) -> 'ctypes.Array[ctypes.c_char]':
        assert self.is_fullyvalid()
        raw_pub = ctypes.create_string_buffer(64)
        secp256k1 = get_secp256k1()
        result = secp256k1.lib.secp256k1_ec_pubkey_parse(
            secp256k1.ctx.verify, raw_pub, self, len(self))

        if 1 != result:
            assert result == 0
            raise RuntimeError('secp256k1_ec_pubkey_parse returned failure')

        return raw_pub

    @classmethod
    def recover_compact(cls: Type[T_CPubKey],
                        hash: bytes, sig: bytes) -> Optional[T_CPubKey]:
        """Recover a public key from a compact signature."""
        if len(sig) != COMPACT_SIGNATURE_SIZE:
            raise ValueError("Signature should be %d characters, not [%d]" % (COMPACT_SIGNATURE_SIZE, len(sig)))

        secp256k1 = get_secp256k1()
        if not secp256k1.cap.has_pubkey_recovery:
            raise RuntimeError('secp256k1 compiled without pubkey recovery functions. '
                               'recover_compact is not functional.')

        recid = (sig[0] - 27) & 3
        compressed = ((sig[0] - 27) & 4) != 0

        rec_sig = ctypes.create_string_buffer(COMPACT_SIGNATURE_SIZE)

        result = secp256k1.lib.secp256k1_ecdsa_recoverable_signature_parse_compact(
            secp256k1.ctx.verify, rec_sig, sig[1:], recid)

        if result != 1:
            assert result == 0
            return None

        raw_pubkey = ctypes.create_string_buffer(64)

        result = secp256k1.lib.secp256k1_ecdsa_recover(
            secp256k1.ctx.verify, raw_pubkey, rec_sig, hash)

        if result != 1:
            assert result == 0
            return None

        return cls._from_ctypes_char_array(raw_pubkey, compressed=compressed)

    @property
    def key_id(self) -> bytes:
        return self.__key_id

    @no_bool_use_as_property
    def is_valid(self) -> bool:
        """Bitcoin Core has IsValid() and IsFullyValid() for CPubKey,
        but there is a danger that a developer would use is_valid() where
        they really meant is_fullyvalid(), and thus could pass invalid pubkeys
        potentially breaking some important checks. Better be safe and do not
        use confusing names - thus is_valid is deprecated and will be removed
        in the future."""
        warnings.warn(
            "CPubKey.is_valid() is deprecated due to possibility of confusion "
            "with CPubKey.is_fullyvalid(). CPubKey.is_valid() will be removed "
            "in the future. Please use CPubKey.is_nonempty() instead.",
            DeprecationWarning
        )
        return self.is_nonempty()

    @no_bool_use_as_property
    def is_nonempty(self) -> bool:
        return not self.is_null()

    @no_bool_use_as_property
    def is_null(self) -> bool:
        return len(self) == 0

    @no_bool_use_as_property
    def is_fullyvalid(self) -> bool:
        return self.__fullyvalid

    @no_bool_use_as_property
    def is_compressed(self) -> bool:
        return len(self) == COMPRESSED_PUBLIC_KEY_SIZE

    def __str__(self) -> str:
        return repr(self)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(x('{bitcointx.core.b2x(self)}'))"

    def verify(self, hash: bytes, sig: bytes) -> bool:
        """Verify a DER signature"""

        ensure_isinstance(sig, (bytes, bytearray), 'signature')
        ensure_isinstance(hash, (bytes, bytearray), 'hash')

        if len(hash) != 32:
            raise ValueError('Hash must be exactly 32 bytes long')

        if not sig:
            return False

        if not self.is_fullyvalid():
            return False

        secp256k1 = get_secp256k1()

        raw_sig = ctypes.create_string_buffer(64)
        result = secp256k1.lib.secp256k1_ecdsa_signature_parse_der(
            secp256k1.ctx.verify, raw_sig, sig, len(sig))

        if result != 1:
            assert result == 0
            return False

        secp256k1.lib.secp256k1_ecdsa_signature_normalize(
            secp256k1.ctx.verify, raw_sig, raw_sig)

        raw_pub = self._to_ctypes_char_array()
        result = secp256k1.lib.secp256k1_ecdsa_verify(
            secp256k1.ctx.verify, raw_sig, hash, raw_pub)

        if result != 1:
            assert result == 0
            return False

        return True

    def verify_nonstrict(self, hash: bytes, sig: bytes) -> bool:
        """Verify a non-strict DER signature"""

        ensure_isinstance(sig, (bytes, bytearray), 'signature')
        ensure_isinstance(hash, (bytes, bytearray), 'hash')

        if len(hash) != 32:
            raise ValueError('Hash must be exactly 32 bytes long')

        if not sig:
            return False

        raw_sig = ecdsa_signature_parse_der_lax(sig)
        if raw_sig is None:
            return False

        sig_size0 = ctypes.c_size_t()
        sig_size0.value = SIGNATURE_SIZE
        mb_sig = ctypes.create_string_buffer(SIGNATURE_SIZE)

        secp256k1 = get_secp256k1()

        result = secp256k1.lib.secp256k1_ecdsa_signature_serialize_der(
            secp256k1.ctx.verify, mb_sig, ctypes.byref(sig_size0), raw_sig)
        if 1 != result:
            assert result == 0
            raise RuntimeError('secp256k1_ecdsa_signature_parse_der returned failure')

        # secp256k1 creates signatures already in lower-S form, no further
        # conversion needed.
        norm_der = mb_sig.raw[:sig_size0.value]

        return self.verify(hash, norm_der)

    def verify_schnorr(self, msg: bytes, sig: bytes) -> bool:
        return XOnlyPubKey(self).verify_schnorr(msg, sig)

    @classmethod
    def combine(cls: Type[T_CPubKey], *pubkeys: T_CPubKey,
                compressed: bool = True) -> T_CPubKey:
        if len(pubkeys) <= 1:
            raise ValueError(
                'number of pubkeys to combine must be more than one')
        for p in pubkeys:
            if not isinstance(p, CPubKey):
                raise ValueError(
                    'each supplied pubkey must be an instance of CPubKey')
            if not p.is_fullyvalid():
                raise ValueError('each supplied pubkey must be valid')

        pubkey_arr = (ctypes.c_char_p*len(pubkeys))()
        for i, p in enumerate(pubkeys):
            pubkey_arr[i] = bytes(p._to_ctypes_char_array())

        secp256k1 = get_secp256k1()

        result_data = ctypes.create_string_buffer(64)
        ret = secp256k1.lib.secp256k1_ec_pubkey_combine(
            secp256k1.ctx.verify, result_data, pubkey_arr, len(pubkeys))

        if ret != 1:
            assert ret == 0
            raise ValueError('Combining the public keys failed')

        return cls._from_ctypes_char_array(result_data, compressed=compressed)

    def negated(self: T_CPubKey) -> T_CPubKey:
        secp256k1 = get_secp256k1()
        if not secp256k1.cap.has_pubkey_negate:
            raise RuntimeError(
                'secp256k1 does not export pubkey negation function. '
                'You should use newer version of secp256k1 library')

        if not self.is_fullyvalid():
            raise ValueError('cannot negate an invalid pubkey')

        pubkey_buf = self._to_ctypes_char_array()
        ret = secp256k1.lib.secp256k1_ec_pubkey_negate(secp256k1.ctx.verify, pubkey_buf)

        if 1 != ret:
            assert ret == 0
            raise RuntimeError('secp256k1_ec_pubkey_negate returned failure')

        return self.__class__._from_ctypes_char_array(
            pubkey_buf, compressed=self.is_compressed())

    @classmethod
    def add(cls: Type[T_CPubKey], a: T_CPubKey, b: T_CPubKey) -> T_CPubKey:
        if a.is_compressed() != b.is_compressed():
            raise ValueError(
                "compressed attributes must match on pubkey "
                "addition/substraction")
        return cls.combine(a, b, compressed=a.is_compressed())

    @classmethod
    def sub(cls: Type[T_CPubKey], a: T_CPubKey, b: T_CPubKey) -> T_CPubKey:
        if a == b:
            raise ValueError('Values are equal, result would be zero, and '
                             'thus an invalid public key.')
        return cls.add(a, b.negated())


class CExtKeyCommonBase:

    __derivation_info: Optional['KeyDerivationInfo']

    def _check_length(self) -> None:
        assert isinstance(self, bytes)
        if len(self) != 74:
            raise ValueError('Invalid length for extended key')

    def _check_depth(self) -> None:
        if self.depth == 0:
            if self.parent_fp != b'\x00\x00\x00\x00':
                raise ValueError(
                    'Derivation depth of the key is 0, the fingerprint '
                    'must be 0x00000000, but it is not')
            if self.child_number != 0:
                raise ValueError(
                    'Derivation depth of the key is 0, the child_number '
                    'must be 0, but it is not')

    @property
    @abstractmethod
    def pub(self) -> 'CPubKey':
        ...

    @property
    def depth(self) -> int:
        assert isinstance(self, bytes)
        return self[0]

    @property
    def parent_fp(self) -> bytes:
        assert isinstance(self, bytes)
        return self[1:5]

    @property
    def child_number(self) -> int:
        return int(struct.unpack(">L", self.child_number_bytes)[0])

    @property
    def child_number_bytes(self) -> bytes:
        assert isinstance(self, bytes)
        return self[5:9]

    @property
    def chaincode(self) -> bytes:
        assert isinstance(self, bytes)
        return self[9:41]

    @property
    def key_bytes(self) -> bytes:
        assert isinstance(self, bytes)
        return self[41:74]

    def derive_path(self: T_CExtKeyCommonBase,
                    path: Union[str, 'BIP32Path', Sequence[int]]
                    ) -> T_CExtKeyCommonBase:
        """Derive the key using the bip32 derivation path."""

        if not isinstance(path, BIP32Path):
            path = BIP32Path(path)

        # NOTE: empty path would mean we need to return master key
        # - there's no need for any derivation - you already have your key.
        # But if someone calls the derivation method, and there is no
        # actual derivation, that might mean that there is some error in
        # the code, and the path should be non-empty.
        # We choose to err on the safe side, and
        # raise ValueError on empty path
        if len(path) == 0:
            raise ValueError('derivation path is empty')

        if not path.is_partial() and self.depth != 0:
            raise ValueError(
                'full derivation path was supplied, but this '
                'extended (pub)key has depth != 0')

        xkey = self
        for n in path:
            xkey = xkey.derive(n)

        return xkey

    @property
    def fingerprint(self) -> bytes:
        return self.pub.key_id[:4]

    def derive(self: T_CExtKeyCommonBase, child_number: int) -> T_CExtKeyCommonBase:
        raise NotImplementedError('subclasses must override derive()')

    @classmethod
    def from_bytes(cls: Type[T_unbounded], data: bytes) -> T_unbounded:
        raise NotImplementedError('subclasses must override from_bytes()')

    def assign_derivation_info(
        self, derivation_info: Optional['KeyDerivationInfo']
    ) -> None:
        try:
            if self.__derivation_info:
                raise AttributeError(
                    'derivation info already present for this instance')
        except AttributeError:
            pass

        if derivation_info:
            if len(derivation_info.path) != self.depth:
                raise ValueError(
                    f'the length of derivation path specified in '
                    f'derivation_info ({len(derivation_info.path)}) '
                    f'is not the same as the depth specified in this '
                    f'extended key ({self.depth})')

            if self.depth == 1 and \
                    self.parent_fp != derivation_info.master_fp:
                raise ValueError(
                    'master fingerprint in derivation info is not '
                    'the same as extended key parent fingerprint while '
                    'this key has depth 1')
            elif self.depth == 0 and \
                    self.fingerprint != derivation_info.master_fp:
                raise ValueError(
                    'master fingerprint in derivation info is not '
                    'the same as extended key fingerprint while '
                    'this key has depth 0')
        else:
            if self.depth == 0:
                derivation_info = KeyDerivationInfo(
                    self.fingerprint, BIP32Path([], is_partial=False))
            elif self.depth == 1:
                derivation_info = KeyDerivationInfo(
                    self.parent_fp,
                    BIP32Path([self.child_number], is_partial=False))

        self.__derivation_info = derivation_info

    @property
    def derivation_info(self) -> Optional['KeyDerivationInfo']:
        return self.__derivation_info


class CExtKeyBase(CExtKeyCommonBase):
    """An encapsulated extended private key

    Attributes:

    priv            - The corresponding CKey for extended privkey
    pub             - shortcut property for priv.pub
    derivation_info - The information about derivation of this extended privkey
                      from the master (Optional, has to be set explicitly)
    """

    @property
    def _key_class(self) -> Type['CKeyBase']:
        raise NotImplementedError

    @property
    def _xpub_class(self) -> Type['CExtPubKeyBase']:
        raise NotImplementedError

    def __init__(self, _b: Optional[bytes]) -> None:

        self._check_length()
        self._check_depth()

        # NOTE: for xpubkey, first byte is pubkey prefix byte.
        # For xprivkey, this byte is supposed to be zero.
        if self.key_bytes[0] != 0:
            raise ValueError('The byte before private key data should be 0')
        raw_priv = self.key_bytes[1:]

        # NOTE: no need to make self.priv a @property method
        # because we need to pre-check if the privkey is valid now, anyway
        # CKey() will do this for us, and we can just set the priv attribute.
        self.__priv = self._key_class.from_secret_bytes(raw_priv)

        # may actually assign something if the depth is 0 or 1
        self.assign_derivation_info(None)

    @property
    def pub(self) -> CPubKey:
        return self.__priv.pub

    @property
    def priv(self) -> CKeyBase:
        return self.__priv

    @classmethod
    def from_seed(cls: Type[T_CExtKeyBase], seed: bytes) -> T_CExtKeyBase:
        if len(seed) not in (128//8, 256//8, 512//8):
            raise ValueError('Unexpected seed length')

        hmac_hash = hmac.new(b'Bitcoin seed', seed, hashlib.sha512).digest()
        depth = 0
        parent_fp = child_number_packed = b'\x00\x00\x00\x00'
        privkey = hmac_hash[:32]
        chaincode = hmac_hash[32:]
        return cls.from_bytes(bytes([depth]) + parent_fp + child_number_packed + chaincode + bytes([0]) + privkey)

    def derive(self: T_CExtKeyBase, child_number: int) -> T_CExtKeyBase:
        if self.depth >= 255:
            raise ValueError('Maximum derivation path length is reached')

        if (child_number >> 32) != 0:
            raise ValueError('Child number is too big')

        depth = self.depth + 1

        child_number_packed = struct.pack(">L", child_number)

        if (child_number >> 31) == 0:
            bip32_hash = hmac.new(self.chaincode, self.pub + child_number_packed,
                                  hashlib.sha512).digest()
        else:
            bip32_hash = hmac.new(self.chaincode,
                                  bytes([0]) + self.priv.secret_bytes + child_number_packed,
                                  hashlib.sha512).digest()

        chaincode = bip32_hash[32:]

        child_privkey = ctypes.create_string_buffer(self.priv.secret_bytes, size=32)

        secp256k1 = get_secp256k1()

        result = secp256k1.lib.secp256k1_ec_privkey_tweak_add(
            secp256k1.ctx.sign, child_privkey, bip32_hash[:32])

        if result != 1:
            assert result == 0
            raise KeyDerivationFailException('extended privkey derivation failed')

        cls = self.__class__
        instance = cls.from_bytes(bytes([depth]) + self.fingerprint
                                  + child_number_packed + chaincode
                                  + bytes([0]) + child_privkey.raw)
        if self.derivation_info:
            instance.assign_derivation_info(
                KeyDerivationInfo(
                    self.derivation_info.master_fp,
                    self.derivation_info.path + [child_number]))

        return instance

    def neuter(self) -> 'CExtPubKeyBase':
        inst = self._xpub_class.from_bytes(
            bytes([self.depth]) + self.parent_fp + self.child_number_bytes + self.chaincode + self.pub)
        if self.derivation_info:
            inst.assign_derivation_info(self.derivation_info.clone())
        return inst


class CExtPubKeyBase(CExtKeyCommonBase):
    """An encapsulated extended public key

    Attributes:

    pub             - The corresponding CPubKey for extended pubkey
    derivation_info - The information about derivation of this extended pubkey
                      from the master (Optional, has to be set explicitly)
    """

    def __init__(self, _b: Optional[bytes]) -> None:

        self._check_length()

        self._pub = CPubKey(self.key_bytes)
        if not self.pub.is_fullyvalid():
            raise ValueError('pubkey part of xpubkey is not valid')

        # may actually assign something if the depth is 0 or 1
        self.assign_derivation_info(None)

    @property
    def pub(self) -> CPubKey:
        return self._pub

    def derive(self: T_CExtPubKeyBase, child_number: int) -> T_CExtPubKeyBase:
        if (child_number >> 31) != 0:
            if (child_number >> 32) != 0:
                raise ValueError('Child number is too big')
            else:
                raise ValueError('Hardened derivation not possible')
        if self.depth >= 255:
            raise ValueError('Maximum derivation path length is reached')

        assert self.pub.is_fullyvalid()
        assert self.pub.is_compressed()

        child_number_packed = struct.pack(">L", child_number)

        depth = self.depth + 1
        bip32_hash = hmac.new(self.chaincode, self.pub + child_number_packed,
                              hashlib.sha512).digest()
        chaincode = bip32_hash[32:]

        raw_pub = self.pub._to_ctypes_char_array()

        secp256k1 = get_secp256k1()

        result = secp256k1.lib.secp256k1_ec_pubkey_tweak_add(
            secp256k1.ctx.verify, raw_pub, bip32_hash[:32])

        if result != 1:
            assert result == 0
            raise KeyDerivationFailException('extended pubkey derivation failed')

        child_pubkey_size0 = ctypes.c_size_t()
        child_pubkey_size0.value = COMPRESSED_PUBLIC_KEY_SIZE
        child_pubkey = ctypes.create_string_buffer(child_pubkey_size0.value)

        result = secp256k1.lib.secp256k1_ec_pubkey_serialize(
            secp256k1.ctx.verify, child_pubkey, ctypes.byref(child_pubkey_size0), raw_pub,
            SECP256K1_EC_COMPRESSED)

        if 1 != result:
            assert result == 0
            raise RuntimeError('secp256k1_ec_pubkey_serialize returned failure')

        cls = self.__class__
        instance = cls.from_bytes(bytes([depth]) + self.fingerprint
                                  + child_number_packed + chaincode
                                  + child_pubkey.raw)
        if self.derivation_info:
            instance.assign_derivation_info(
                KeyDerivationInfo(
                    self.derivation_info.master_fp,
                    self.derivation_info.path + [child_number]))

        return instance


T_CExtPubKey = TypeVar('T_CExtPubKey', bound='CExtPubKey')


class CExtPubKey(bytes, CExtPubKeyBase):
    "Standalone extended pubkey class"

    @classmethod
    def from_bytes(cls: Type[T_unbounded], data: bytes) -> T_unbounded:
        # We cannot annotate cls with a bounded type here, because
        # there would be conflicts with CBase58Data, etc.
        # But with unbounded type, mypy cannot know if the classs
        # creation can have arguments.
        return cls(data)  # type: ignore


T_CExtKey = TypeVar('T_CExtKey', bound='CExtKey')


class CExtKey(bytes, CExtKeyBase):
    "Standalone extended key class"

    neuter: ClassVar[Callable[['CExtKey'], CExtPubKey]]

    @classmethod
    def from_bytes(cls: Type[T_unbounded], data: bytes) -> T_unbounded:
        # We cannot annotate cls with a bounded type here, because
        # there would be conflicts with CBase58Data, etc.
        # But with unbounded type, mypy cannot know if the classs
        # creation can have arguments.
        return cls(data)  # type: ignore

    @property
    def _key_class(self) -> Type[CKey]:
        return CKey

    @property
    def _xpub_class(self) -> Type[CExtPubKey]:
        return CExtPubKey


T_BIP32PathIndex = TypeVar('T_BIP32PathIndex')


class BIP32PathGeneric(Generic[T_BIP32PathIndex]):

    HARDENED_MARKERS = ("'", "h")

    __slots__ = ['_indexes', '_hardened_marker', '_is_partial_path']

    _indexes: Tuple[T_BIP32PathIndex, ...]
    _hardened_marker: str
    _is_partial_path: bool  # True if path does not start from master (no 'm/')

    def __init__(  # noqa
        self, path: Union[
            str, 'BIP32PathGeneric[T_BIP32PathIndex]',  # noqa
            Sequence[T_BIP32PathIndex],
            # See comment for BIP32PathTemplateIndex for the
            # reason to include this here (python 3.6 typechecking quirks)
            Sequence[Sequence[Tuple[int, int]]]
        ],
        is_partial: Optional[bool] = None,
        hardened_marker: Optional[str] = None
    ) -> None:
        if hardened_marker is not None:
            if hardened_marker not in self.__class__.HARDENED_MARKERS:
                raise ValueError('unsupported hardened_marker')

        indexes: Union[
            Sequence[T_BIP32PathIndex],
            # See comment for BIP32PathTemplateIndex for the
            # reason to include this here (python 3.6 typechecking quirks)
            Sequence[Sequence[Tuple[int, int]]]
        ]

        if isinstance(path, str):
            indexes, hardened_marker, partial = self._parse_string(
                path, hardened_marker=hardened_marker)
            if is_partial is None:
                is_partial = partial
            else:
                if is_partial != partial:
                    raise ValueError(
                        'is_partial argument is specified, but does not '
                        'match the actual path string (which specifies '
                        '{} path)'.format('partial' if partial else 'full'))
        elif isinstance(path, BIP32PathGeneric):
            if hardened_marker is None:
                hardened_marker = path._hardened_marker
            if is_partial is None:
                is_partial = path.is_partial()
            else:
                if is_partial != path.is_partial():
                    raise ValueError(
                        'is_partial argument is specified, but does not '
                        'match the is_partial() property of the supplied '
                        'BIP32PathGeneric instance')
            indexes = path._indexes
            # we cannot just use _indexes if it is mutalbe,
            # assert that it is a tuple, so if the _indexes attr will
            # ever become mutable, this would be cathed by tests
            assert isinstance(indexes, tuple)
        else:
            indexes = path
            if is_partial is None:
                is_partial = True

        if len(indexes) > 255:
            raise ValueError('derivation path longer than 255 elements')

        if hardened_marker is None:
            hardened_marker = self.__class__.HARDENED_MARKERS[0]

        self._indexes = tuple(self.__class__._index_from_argument(n)
                              for n in indexes)
        self._hardened_marker = hardened_marker
        self._is_partial_path = bool(is_partial)

    @no_bool_use_as_property
    def is_partial(self) -> bool:
        return self._is_partial_path

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}("{str(self)}")'

    @abstractmethod
    def _index_to_str(self, n: T_BIP32PathIndex) -> str:
        ...

    @classmethod
    @abstractmethod
    def _index_from_argument(cls, n: Any) -> T_BIP32PathIndex:
        ...

    @classmethod
    @abstractmethod
    def _index_from_str(cls, s: str, *, is_hardened: bool) -> T_BIP32PathIndex:
        ...

    def __str__(self) -> str:
        if len(self._indexes) == 0:
            return '' if self.is_partial() else 'm'

        pfx = '%s' if self.is_partial() else 'm/%s'

        return pfx % '/'.join(self._index_to_str(n) for n in self._indexes)

    def __len__(self) -> int:
        return len(self._indexes)

    def __add__(self,
                other: Union['BIP32PathGeneric[T_BIP32PathIndex]',
                             Iterable[T_BIP32PathIndex]]
                ) -> 'BIP32PathGeneric[T_BIP32PathIndex]':
        if isinstance(other, BIP32PathGeneric):
            if not other.is_partial():
                raise ValueError(
                    'cannot append full path to anything, can only '
                    'append partial path to full path')
        return self.__class__(list(self._indexes) + list(other),
                              is_partial=self.is_partial())

    def __getitem__(self, key: int) -> T_BIP32PathIndex:
        return self._indexes[key]

    def __iter__(self) -> Iterator[T_BIP32PathIndex]:
        return (n for n in self._indexes)

    def _parse_string(self, path: str, hardened_marker: Optional[str] = None  # noqa
                      ) -> Tuple[List[T_BIP32PathIndex], Optional[str], bool]:
        """Parse bip32 derivation path.
        returns a tuple (list_of_indexes, actual_hardened_marker).
        hardened indexes will have BIP32_HARDENED_KEY_OFFSET added to them."""

        assert isinstance(path, str)

        if any(ch.isspace() for ch in path):
            raise ValueError('whitespace found in path')

        if path == '':
            return [], hardened_marker, True
        elif path == 'm':
            return [], hardened_marker, False
        elif path.startswith('m/'):
            is_partial = False
            path = path[2:]
        else:
            if path.startswith('/'):
                raise ValueError(
                    'partial derivation path must not start with "/"')
            is_partial = True

        if path.endswith('/'):
            raise ValueError('derivation path must not end with "/"')

        indexes: List[T_BIP32PathIndex] = []

        expected_marker = hardened_marker

        for pos, elt in enumerate(path.split('/')):
            if elt == '':
                if path == '':
                    raise ValueError(
                        'empty non-partial path must be specified as "m" '
                        '(without slash)')
                # m/// is probably a result of the error, where indexes
                # for some reason was empty strings. Be strict and not allow that.
                raise ValueError('duplicate slashes are not allowed')

            c = elt
            is_hardened = False
            if c[-1] in self.__class__.HARDENED_MARKERS:
                if expected_marker is None:
                    expected_marker = c[-1]
                elif expected_marker != c[-1]:
                    raise ValueError(
                        'Unexpected hardened marker: "{}" {}, but got {}'
                        .format(expected_marker,
                                ('seen in the path previously'
                                 if hardened_marker is None
                                 else 'was specified'),
                                c[-1]))
                is_hardened = True
                c = c[:-1]

            indexes.append(
                self.__class__._index_from_str(c, is_hardened=is_hardened))

        return indexes, expected_marker, is_partial


class BIP32Path(BIP32PathGeneric[int]):

    @classmethod
    def _index_from_str(cls, s: str, *, is_hardened: bool) -> int:

        if not s.isdigit():
            if any(ch.isspace() for ch in s):
                raise ValueError('whitespace found in BIP32 index')
            raise ValueError('non-digit character found in BIP32 index')

        if len(s) > 1 and s.startswith('0'):
            raise ValueError('leading zeroes are not allowed in BIP32 index')

        n = int(s)

        if n < 0:
            raise ValueError('derivation index cannot be negative')

        if n >= BIP32_HARDENED_KEY_OFFSET:
            raise ValueError(
                f'derivation index string cannot represent value > '
                f'{BIP32_HARDENED_KEY_OFFSET-1}')

        if is_hardened:
            n += BIP32_HARDENED_KEY_OFFSET

        return n

    def _index_to_str(self, n: int) -> str:
        if n < BIP32_HARDENED_KEY_OFFSET:
            return f'{n}'

        return f'{n - BIP32_HARDENED_KEY_OFFSET}{self._hardened_marker}'

    @classmethod
    def _index_from_argument(cls, n: Any) -> int:
        ensure_isinstance(n, int, 'derivation index')

        if n < 0:
            raise ValueError('derivation index cannot be negative')

        if n > 0xFFFFFFFF:
            raise ValueError(f'derivation index cannot be > {0xFFFFFFFF}')

        assert isinstance(n, int)
        return n

    def __add__(self, other: Union['BIP32Path', Iterable[int]]
                ) -> 'BIP32Path':
        return cast(BIP32Path, super().__add__(other))


# NOTE that mypy complains
#   error: Implicit generic "Any".
#   Use "typing.Tuple" and specify generic parameters
# on directly subclassing tuple. But using
# class BIP32PathTemplateIndex(Tuple[Tuple[int, int]]) here is unacceptable,
# because this causes isinstance(var, BIP32PathTemplateIndex) to return true
# if var is a tuple. This is happens on python3.6, but on not on python 3.7
class BIP32PathTemplateIndex(tuple):  # type: ignore

    def __init__(self, index_tuples: Iterable[Tuple[int, int]]) -> None:
        max_index = -1
        for from_to_tuple in index_tuples:
            ensure_isinstance(from_to_tuple, (tuple, list), 'index_bounds')
            if len(from_to_tuple) != 2:
                raise ValueError(
                    'index tuple must have two values: from and to')
            ensure_isinstance(from_to_tuple[0], int, 'index_from')
            ensure_isinstance(from_to_tuple[1], int, 'index_to')

            left, right = from_to_tuple

            if left < 0 or right < 0:
                raise ValueError('derivation index cannot be negative')

            if left > 0xFFFFFFFF or right > 0xFFFFFFFF:
                raise ValueError(f'derivation index cannot be > {0xFFFFFFFF}')

            left_hardened = left < BIP32_HARDENED_KEY_OFFSET
            right_hardened = right < BIP32_HARDENED_KEY_OFFSET
            if left_hardened != right_hardened:
                raise ValueError(
                    "index bounds must be both hardened or both unhardened")

            if left > right:
                raise ValueError(
                    'index_from cannot be larger than index_to in an '
                    'index tuple')

            if right <= max_index:
                raise ValueError(
                    f'incorrect path template index bound: {right} is '
                    f'less than or equal {max_index}, which is already '
                    f'seen, and index bounds must only increase')

            max_index = right


class BIP32PathTemplate(BIP32PathGeneric[BIP32PathTemplateIndex]):

    @classmethod
    def _index_from_str(cls, index_str: str, *, is_hardened: bool  # noqa
                        ) -> BIP32PathTemplateIndex:

        if any(ch.isspace() for ch in index_str):
            raise ValueError('whitespace found in index template')

        bad_format_error = ValueError(f'index template format is not valid: "{index_str}"')

        def parse_index(s: str, *, is_hardened: bool
                        ) -> Tuple[Optional[int], Optional[ValueError]]:
            try:
                n_int = BIP32Path._index_from_str(s, is_hardened=is_hardened)
            except ValueError as e:
                return None, e

            return n_int, None

        n_int, err = parse_index(index_str, is_hardened=is_hardened)

        if n_int is not None:
            return BIP32PathTemplateIndex([(n_int, n_int)])
        elif index_str.isdigit():
            assert err is not None
            raise err

        offset = BIP32_HARDENED_KEY_OFFSET if is_hardened else 0

        if index_str == '*':
            return BIP32PathTemplateIndex(
                [(offset, BIP32_HARDENED_KEY_OFFSET - 1 + offset)])

        if len(index_str) < 3:
            raise bad_format_error

        if '{' != index_str[0] or '}' != index_str[-1]:
            raise bad_format_error

        index_str = index_str[1:-1]

        index_bounds_list: List[Tuple[int, int]] = []
        for index_substr in index_str.split(','):
            maybe_range = index_substr.split('-', maxsplit=1)
            if len(maybe_range) > 1:
                left, right = maybe_range
                n_left, err = parse_index(left, is_hardened=False)
                if n_left is None:
                    assert err is not None
                    raise err
                n_right, err = parse_index(right, is_hardened=False)
                if n_right is None:
                    assert err is not None
                    raise err

                if n_left == 0 and n_right == BIP32_HARDENED_KEY_OFFSET-1:
                    raise ValueError(
                        "index range equals wildcard range, should be "
                        "specified as \"*\"")

                range_tuple = (n_left + offset, n_right + offset)
            else:
                idx, err = parse_index(index_substr, is_hardened=False)
                if idx is None:
                    assert err is not None
                    raise err
                range_tuple = (idx + offset, idx + offset)

            if index_bounds_list and \
                    index_bounds_list[-1][1] + 1 == range_tuple[0]:
                index_bounds_list[-1] = (index_bounds_list[-1][0],
                                         range_tuple[1])
            else:
                index_bounds_list.append(range_tuple)

        return BIP32PathTemplateIndex(index_bounds_list)

    def _index_to_str(self, ti: BIP32PathTemplateIndex) -> str:
        items = []
        for left, right in ti:
            left_hardened = left >= BIP32_HARDENED_KEY_OFFSET
            right_hardened = right >= BIP32_HARDENED_KEY_OFFSET
            if left_hardened != right_hardened:
                raise AssertionError(
                    "index bounds must be both hardened or both unhardened")

            is_hardened = left_hardened

            marker = self._hardened_marker if is_hardened else ''

            if is_hardened:
                left -= BIP32_HARDENED_KEY_OFFSET
                right -= BIP32_HARDENED_KEY_OFFSET

            if left == right:
                items.append(str(left))
            elif left == 0 and right == BIP32_HARDENED_KEY_OFFSET-1:
                items.append('*')
            else:
                items.append(f'{left}-{right}')

        assert len(items) > 0

        if len(items) == 1 and ('-' not in items[0]):
            return f'{items[0]}{marker}'

        return f"{{{','.join(items)}}}{marker}"

    @classmethod
    def _index_from_argument(cls, n: Any) -> BIP32PathTemplateIndex:
        if isinstance(n, BIP32PathTemplateIndex):
            return n

        return BIP32PathTemplateIndex(n)

    def __add__(self, other: Union['BIP32PathTemplate',
                                   Iterable[BIP32PathTemplateIndex]]
                ) -> 'BIP32PathTemplate':
        return cast(BIP32PathTemplate, super().__add__(other))

    def match_path(self, path: BIP32Path) -> bool:
        if self.is_partial() != path.is_partial():
            return False

        if len(path) != len(self):
            return False

        for pos, bounds_tuples in enumerate(self):
            for first, last in bounds_tuples:
                if first <= path[pos] <= last:
                    break
            else:
                # path[pos] did not match any bounds
                return False

        # all elements of a path matched respective bounds
        return True


class BIP32PathTemplateViolation(Exception):
    """Raised when the key to be returned from `get_privkey()`
    or `get_pubkey()` is derived via path that do no match any path templates
    specified for the extended key."""

    def __init__(self, *,
                 path_templates: List[BIP32PathTemplate],
                 key_id: bytes, master_fp: bytes,
                 full_path: Optional[BIP32Path] = None,
                 partial_path: Optional[BIP32Path] = None
                 ) -> None:
        self.path_templates = path_templates
        self.key_id = key_id
        self.master_fp = master_fp
        self.full_path = full_path
        self.partial_path = partial_path

    def __repr__(self) -> str:
        return (
            f'{self.__class__.__name__}('
            f'path_templates={self.path_templates}, '
            f'key_id=x(\'{bitcointx.core.b2x(self.key_id)}\'), '
            f'master_fp=x(\'{bitcointx.core.b2x(self.master_fp)}\'), '
            f'full_path=BIP32Path("{self.full_path}"), '
            f'partial_path=BIP32Path("{self.partial_path}")'
            f')'
        )

    def __str__(self) -> str:
        return self.__repr__()


T_KeyDerivationInfo = TypeVar('T_KeyDerivationInfo', bound='KeyDerivationInfo')


class KeyDerivationInfo:
    master_fp: bytes
    path: BIP32Path

    def __init__(self,
                 master_fp: bytes,
                 path: BIP32Path
                 ) -> None:
        ensure_isinstance(master_fp, bytes, 'master key fingerprint')
        ensure_isinstance(path, BIP32Path, 'bip32 path')
        if len(master_fp) != 4:
            raise ValueError('Fingerprint should be 4 bytes in length')
        if path.is_partial():
            raise ValueError(
                'only full paths from the master key are accepted, but '
                'a partial BIP32Path was supplied')
        object.__setattr__(self, 'master_fp', master_fp)
        object.__setattr__(self, 'path', path)

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"x('{bitcointx.core.b2x(self.master_fp)}'), "
            f"{repr(self.path)})")

    def clone(self: T_KeyDerivationInfo) -> T_KeyDerivationInfo:
        return self.__class__(
            master_fp=self.master_fp,
            path=BIP32Path(path=self.path))


T_KeyStoreKeyArg = Union[CKeyBase, CPubKey, CExtKeyBase, CExtPubKeyBase,
                         Tuple[CExtKeyBase,
                               Union[BIP32PathTemplate,
                                     Iterable[BIP32PathTemplate],
                                     str, Iterable[str]]],
                         Tuple[CExtPubKeyBase,
                               Union[BIP32PathTemplate,
                                     Iterable[BIP32PathTemplate],
                                     str, Iterable[str]]]]
T_KeyStore = TypeVar('T_KeyStore', bound='KeyStore')


class KeyStore:
    # KeyStore can store pubkeys and xpubkeys. This can be used, for example,
    # for output checks to determine the change output when you do not
    # have the privkeys
    _xprivkeys: Dict[bytes, Dict[Tuple[int, ...], Dict[CExtKeyBase, List[BIP32PathTemplate]]]]
    _xpubkeys: Dict[bytes, Dict[Tuple[int, ...], Dict[CExtPubKeyBase, List[BIP32PathTemplate]]]]
    _privkeys: Dict[bytes, CKeyBase]
    _pubkeys: Dict[bytes, CPubKey]
    _external_privkey_lookup: Optional[
        Callable[[bytes, Optional[KeyDerivationInfo]],
                 Optional[CKeyBase]]
    ]
    _external_pubkey_lookup: Optional[
        Callable[[bytes, Optional[KeyDerivationInfo]],
                 Optional[CPubKey]]
    ]
    _require_path_templates: bool
    _default_path_template: Optional[BIP32PathTemplate]

    def __init__(self, *args: T_KeyStoreKeyArg,
                 external_privkey_lookup: Optional[
                     Callable[[bytes, Optional[KeyDerivationInfo]],
                              Optional[CKeyBase]]
                 ] = None,
                 external_pubkey_lookup: Optional[
                     Callable[[bytes, Optional[KeyDerivationInfo]],
                              Optional[CPubKey]]
                 ] = None,
                 default_path_template: Optional[
                     Union[BIP32PathTemplate, str]
                 ] = None,
                 require_path_templates: bool = True
                 ) -> None:
        """
        external_privkey_lookup: if supplied, this callback will be used
        to lookup privkeys not found in KeyStore. Pubkey lookup will also call
        this callback, and if privkey is found, will use its pubkey.

        external_pubkey_lookup: if supplied, this callback will be used
        to lookup pubkeys not found in KeyStore. Privkey lookup will not use
        this callback.

        default_path_template: if supplied, the will be used as path template
        for any extended key that does not have its path template specified.

        require_path_templates: default True. If False, then extended keys
        without path templates will be allowed to be added to KeyStore, and
        key lookup for these keys will not restrict derivation paths in any way
        """

        self._privkeys = {}
        self._pubkeys = {}
        self._xpubkeys = {}
        self._xprivkeys = {}

        # must be set before add_key() is called
        self._require_path_templates = require_path_templates
        if default_path_template is not None:
            ensure_isinstance(default_path_template, (BIP32PathTemplate, str),
                              'default_path_template')
            if isinstance(default_path_template, str):
                default_path_template = BIP32PathTemplate(default_path_template)

            if default_path_template.is_partial():
                raise ValueError(
                    'default path template must specify full path')

        self._default_path_template = default_path_template

        for k in args:
            self.add_key(k)

        self._external_privkey_lookup = external_privkey_lookup
        self._external_pubkey_lookup = external_pubkey_lookup

    def replace_external_privkey_lookup(
        self,
        callback: Optional[Callable[[bytes, Optional[KeyDerivationInfo]],
                                    Optional[CKeyBase]]] = None
    ) -> Optional[Callable[[bytes, Optional[KeyDerivationInfo]],
                           Optional[CKeyBase]]]:
        prev_cb = self._external_privkey_lookup
        self._external_privkey_lookup = callback
        return prev_cb

    def replace_external_pubkey_lookup(
        self,
        callback: Optional[Callable[[bytes, Optional[KeyDerivationInfo]],
                                    Optional[CPubKey]]] = None
    ) -> Optional[Callable[[bytes, Optional[KeyDerivationInfo]],
                           Optional[CPubKey]]]:
        prev_cb = self._external_pubkey_lookup
        self._external_pubkey_lookup = callback
        return prev_cb

    @classmethod
    def from_iterable(cls: Type[T_KeyStore],
                      iterable: Iterable[T_KeyStoreKeyArg],
                      **kwargs: Any
                      ) -> T_KeyStore:
        kstore = cls(**kwargs)
        for k in iterable:
            kstore.add_key(k)
        return kstore

    def add_key(self, k: T_KeyStoreKeyArg) -> None:  # noqa

        path_templates = []
        if isinstance(k, tuple):
            k, pts = k
            if isinstance(pts, (str, BIP32PathTemplate)):
                # single path template
                path_templates.append(BIP32PathTemplate(pts))
            else:
                # possibly an iterable of templates
                for pt in pts:
                    ensure_isinstance(pt, (str, BIP32PathTemplate),
                                      'path template')
                    path_templates.append(BIP32PathTemplate(pt))

                # Note: cannot do `if not pts` because it might be a generator
                if not path_templates:
                    raise ValueError(
                        'path templates list is empty')

        if isinstance(k, CKeyBase):
            if path_templates:
                raise ValueError(
                    'path_templates only make sense for extended keys')
            if k.pub.key_id in self._privkeys:
                assert self._privkeys[k.pub.key_id] == k
            else:
                self._privkeys[k.pub.key_id] = k
        elif isinstance(k, CPubKey):
            if path_templates:
                raise ValueError(
                    'path_templates only make sense for extended keys')
            if k.key_id in self._pubkeys:
                assert self._pubkeys[k.key_id] == k
            else:
                self._pubkeys[k.key_id] = k
        elif isinstance(k, CExtKeyCommonBase):
            if not path_templates and self._default_path_template:
                path_templates = [self._default_path_template]

            if not path_templates and self._require_path_templates:
                raise ValueError(
                    'path templates must be specified for extended key')

            for pt in path_templates:
                ensure_isinstance(pt, BIP32PathTemplate, 'path template')

            mfp, indexes = self._mfp_and_indexes_from_derivation(
                k.derivation_info)

            # Even if these two block are similar, they had to be separate
            # due to (current?) limitations of mypy typing
            if isinstance(k, CExtKeyBase):
                l0_dict_priv = self._xprivkeys
                if mfp not in l0_dict_priv:
                    l0_dict_priv[mfp] = {}
                l1_dict_priv = l0_dict_priv[mfp]
                if indexes in l1_dict_priv:
                    if k in l1_dict_priv[indexes]:
                        l1_dict_priv[indexes][k].extend(path_templates)
                    else:
                        l1_dict_priv[indexes][k] = path_templates
                else:
                    l1_dict_priv[indexes] = {k: path_templates}
            else:
                l0_dict_pub = self._xpubkeys
                if mfp not in l0_dict_pub:
                    l0_dict_pub[mfp] = {}
                l1_dict_pub = l0_dict_pub[mfp]
                if indexes in l1_dict_pub:
                    if k in l1_dict_pub[indexes]:
                        l1_dict_pub[indexes][k].extend(path_templates)
                    else:
                        l1_dict_pub[indexes][k] = path_templates
                else:
                    l1_dict_pub[indexes] = {k: path_templates}
        else:
            raise ValueError(
                f'object supplied to add_key is of type '
                f'{k.__class__.__name__}, which is not recognized key type')

    def remove_key(self, k: T_KeyStoreKeyArg) -> None:  # noqa: C901
        if isinstance(k, CKeyBase):
            if k.pub.key_id in self._privkeys:
                self._privkeys.pop(k.pub.key_id)
        elif isinstance(k, CPubKey):
            if k.key_id in self._pubkeys:
                self._pubkeys.pop(k.key_id)
        elif isinstance(k, CExtKeyCommonBase):
            mfp, indexes = self._mfp_and_indexes_from_derivation(
                k.derivation_info)

            # Even if these two block are similar, they had to be separate
            # due to (current?) limitations of mypy typing
            if isinstance(k, CExtKeyBase):
                l0_dict_priv = self._xprivkeys
                if mfp not in l0_dict_priv:
                    return
                l1_dict_priv = l0_dict_priv[mfp]
                if indexes in l1_dict_priv:
                    l1_dict_priv[indexes].pop(k)

                if not l1_dict_priv[indexes]:
                    l1_dict_priv.pop(indexes)
                if not l0_dict_priv[mfp]:
                    l0_dict_priv.pop(mfp)
            else:
                l0_dict_pub = self._xpubkeys
                if mfp not in l0_dict_pub:
                    return
                l1_dict_pub = l0_dict_pub[mfp]
                if indexes in l1_dict_pub:
                    l1_dict_pub[indexes].pop(k)

                if not l1_dict_pub[indexes]:
                    l1_dict_pub.pop(indexes)
                if not l0_dict_pub[mfp]:
                    l0_dict_pub.pop(mfp)
        else:
            raise ValueError('unrecognized argument type')

    def _mfp_and_indexes_from_derivation(
        self, derivation: Optional['KeyDerivationInfo']
    ) -> Tuple[bytes, Tuple[int, ...]]:
        if derivation:
            return (derivation.master_fp, derivation.path._indexes)

        return (b'', tuple())

    def _enforce_path_templates(
        self,
        path_templates: List[BIP32PathTemplate],
        key_id: bytes, master_fp: bytes,
        full_path_indexes: Optional[Tuple[int, ...]] = None,
        partial_path_indexes: Optional[Tuple[int, ...]] = None
    ) -> None:

        if not path_templates:
            if self._require_path_templates:
                raise AssertionError(
                    'path_templates cannot be empty '
                    'when require_path_templates is set')
            return

        full_path: Optional[BIP32Path] = None
        partial_path: Optional[BIP32Path] = None

        if full_path_indexes is not None:
            full_path = BIP32Path(full_path_indexes, is_partial=False)

        if partial_path_indexes is not None:
            partial_path = BIP32Path(partial_path_indexes, is_partial=True)

        if full_path is None and partial_path is None:
            raise ValueError(
                'at least one of full_path_indexes or partial_path_indexes '
                'must be specified')

        for pt in path_templates:
            if pt.is_partial():
                if partial_path is not None and pt.match_path(partial_path):
                    return
            else:
                if full_path is not None and pt.match_path(full_path):
                    return

        raise BIP32PathTemplateViolation(
            path_templates=path_templates, key_id=key_id, master_fp=master_fp,
            full_path=full_path, partial_path=partial_path)

    # Even if _find_by_derivation_* functions are similar,
    # they had to be separate due to (current?) limitations of mypy typing
    def _find_by_derivation_pub(  # noqa
        self, key_id: bytes, master_fp: bytes, indexes: Tuple[int, ...]
    ) -> Optional[CPubKey]:
        l0_dict = self._xpubkeys

        if master_fp in l0_dict:
            l1_dict = l0_dict[master_fp]
            for l1_indexes, xpub_dict in l1_dict.items():
                if indexes[:len(l1_indexes)] == l1_indexes:
                    indexes_tail = indexes[len(l1_indexes):]
                    if all(idx < BIP32_HARDENED_KEY_OFFSET
                            for idx in indexes_tail):
                        for xpub, path_templates in xpub_dict.items():
                            if indexes_tail:
                                xpub = xpub.derive_path(indexes_tail)
                            if xpub.pub.key_id == key_id:
                                self._enforce_path_templates(
                                    path_templates, key_id, master_fp,
                                    full_path_indexes=indexes,
                                    partial_path_indexes=indexes_tail)
                                return xpub.pub
                    break

        return None

    def _find_by_derivation_priv(
        self, key_id: bytes, master_fp: bytes, indexes: Tuple[int, ...]
    ) -> Optional[CKeyBase]:
        l0_dict = self._xprivkeys

        if master_fp in l0_dict:
            l1_dict = l0_dict[master_fp]
            for l1_indexes, xkey_dict in l1_dict.items():
                if indexes[:len(l1_indexes)] == l1_indexes:
                    for xpriv, path_templates in xkey_dict.items():
                        indexes_tail = indexes[len(l1_indexes):]
                        if indexes_tail:
                            xpriv = xpriv.derive_path(indexes_tail)
                        if xpriv.pub.key_id == key_id:
                            self._enforce_path_templates(
                                path_templates, key_id, master_fp,
                                full_path_indexes=indexes,
                                partial_path_indexes=indexes_tail)
                            return xpriv.priv
                    break

        return None

    def get_privkey(self, key_id: bytes,
                    derivation: Optional[T_KeyDerivationInfo] = None
                    ) -> Optional[CKeyBase]:
        ensure_isinstance(key_id, bytes, 'key_id')
        if derivation:
            ensure_isinstance(derivation, KeyDerivationInfo, 'derivation')
        if len(key_id) != 20:
            raise ValueError('invalid length for key_id, expected to be 20')

        if key_id in self._privkeys:
            return self._privkeys[key_id]

        mfp, indexes = self._mfp_and_indexes_from_derivation(derivation)

        priv = self._find_by_derivation_priv(key_id, mfp, indexes)
        if priv:
            return priv

        if self._external_privkey_lookup:
            priv = self._external_privkey_lookup(key_id, derivation)
            if priv and priv.pub.key_id != key_id:
                raise AssertionError(
                    'external_privkey_lookup callback returned incorrect '
                    'privkey, key_ids do not match')
            return priv

        return None

    def get_pubkey(self, key_id: bytes,
                   derivation: Optional[T_KeyDerivationInfo] = None
                   ) -> Optional[CPubKey]:
        ensure_isinstance(key_id, bytes, 'key_id')
        if derivation:
            ensure_isinstance(derivation, KeyDerivationInfo, 'derivation')
        if len(key_id) != 20:
            raise ValueError('invalid length for key_id, expected to be 20')

        if key_id in self._pubkeys:
            return self._pubkeys[key_id]

        mfp, indexes = self._mfp_and_indexes_from_derivation(derivation)

        pub = self._find_by_derivation_pub(key_id, mfp, indexes)
        if pub:
            return pub

        priv = self.get_privkey(key_id, derivation)
        if priv:
            return priv.pub

        if self._external_pubkey_lookup:
            pub = self._external_pubkey_lookup(key_id, derivation)
            if pub and pub.key_id != key_id:
                raise AssertionError(
                    'external_pubkey_lookup callback returned incorrect '
                    'pubkey, key_ids do not match')
            return pub

        return None


T_XOnlyPubKey = TypeVar('T_XOnlyPubKey', bound='XOnlyPubKey')


class XOnlyPubKey(bytes):
    """An encapsulated X-Only public key"""

    __fullyvalid: bool

    def __new__(cls: Type[T_XOnlyPubKey],
                keydata: Union[bytes, CPubKey] = b'') -> T_XOnlyPubKey:

        secp256k1 = get_secp256k1()
        if not secp256k1.cap.has_xonly_pubkeys:
            raise RuntimeError(
                _module_unavailable_error('x-only pubkey', 'extrakeys'))

        if len(keydata) in (32, 0):
            ensure_isinstance(keydata, bytes, 'x-only pubkey data')
        elif len(keydata) == 33:
            ensure_isinstance(keydata, CPubKey,
                              'x-only pubkey data of 33 bytes')
            assert isinstance(keydata, CPubKey)
            if not keydata.is_fullyvalid():
                raise ValueError('invalid CPubKey supplied')

            keydata = keydata[1:33]
        else:
            raise ValueError('unrecognized pubkey data length')

        self = super().__new__(cls, keydata)

        self.__fullyvalid = False

        if self.is_nonempty():
            tmpbuf = ctypes.create_string_buffer(64)
            result = secp256k1.lib.secp256k1_xonly_pubkey_parse(
                secp256k1.ctx.verify, tmpbuf, self)
            assert result in (1, 0)
            self.__fullyvalid = (result == 1)

        return self

    @no_bool_use_as_property
    def is_fullyvalid(self) -> bool:
        return self.__fullyvalid

    @no_bool_use_as_property
    def is_nonempty(self) -> bool:
        return not self.is_null()

    @no_bool_use_as_property
    def is_null(self) -> bool:
        return len(self) == 0

    def verify_schnorr(self, hash: bytes, sigbytes: bytes) -> bool:
        secp256k1 = get_secp256k1()
        if not secp256k1.cap.has_schnorrsig:
            raise RuntimeError(
                _module_unavailable_error('schnorr signature', 'schnorrsig'))

        ensure_isinstance(sigbytes, (bytes, bytearray), 'signature')
        ensure_isinstance(hash, (bytes, bytearray), 'hash')

        if len(hash) != 32:
            raise ValueError('Hash must be exactly 32 bytes long')

        if not sigbytes:
            return False

        if not self.is_fullyvalid():
            return False

        if len(sigbytes) != 64:
            raise ValueError('Signature must be exactly 64 bytes long')

        result = secp256k1.lib.secp256k1_schnorrsig_verify(
            secp256k1.ctx.verify,
            sigbytes, hash, 32, self._to_ctypes_char_array()
        )

        if result != 1:
            assert result == 0
            return False

        return True

    def _to_ctypes_char_array(self) -> 'ctypes.Array[ctypes.c_char]':
        assert self.is_fullyvalid()
        secp256k1 = get_secp256k1()
        raw_pub = ctypes.create_string_buffer(64)
        result = secp256k1.lib.secp256k1_xonly_pubkey_parse(
            secp256k1.ctx.verify, raw_pub, self)

        if 1 != result:
            assert result == 0
            raise RuntimeError('secp256k1_xonly_pubkey_parse returned failure')

        return raw_pub

    def __str__(self) -> str:
        return repr(self)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(x('{bitcointx.core.b2x(self)}'))"


def compute_tap_tweak_hash(
    pub: XOnlyPubKey, *, merkle_root: bytes = b''
) -> bytes:
    ensure_isinstance(merkle_root, bytes, 'merkle_root')

    if not merkle_root:
        return bitcointx.core.CoreCoinParams.taptweak_hasher(pub)

    if len(merkle_root) != 32:
        raise ValueError('non-empty merkle_root must be 32 bytes long')

    return bitcointx.core.CoreCoinParams.taptweak_hasher(
        pub + merkle_root)


def check_tap_tweak(tweaked_pub: XOnlyPubKey, internal_pub: XOnlyPubKey,
                    *,
                    merkle_root: bytes = b'',
                    parity: bool) -> bool:

    if not tweaked_pub.is_fullyvalid():
        raise ValueError('supplied tweaked_pub must be valid')

    if not internal_pub.is_fullyvalid():
        raise ValueError('supplied internal_pub must be valid')

    tweak = compute_tap_tweak_hash(internal_pub, merkle_root=merkle_root)

    secp256k1 = get_secp256k1()

    result = secp256k1.lib.secp256k1_xonly_pubkey_tweak_add_check(
        secp256k1.ctx.verify, tweaked_pub, int(bool(parity)),
        internal_pub._to_ctypes_char_array(), tweak)

    if result != 1:
        assert result == 0
        return False

    return True


# in BitcoinCore, the same function is called `CreateTapTweak`. But
# in this case it makes sense to deviate from followin Core's naming
# conventions, because `create_tap_tweak` could be perceived as something
# that creates tweak hash, rather than tweaks the pubkey.
def tap_tweak_pubkey(pub: XOnlyPubKey, *, merkle_root: bytes = b'',
                     ) -> Optional[Tuple[XOnlyPubKey, bool]]:

    if not pub.is_fullyvalid():
        raise ValueError('pubkey must be valid')

    base_point = pub._to_ctypes_char_array()
    tweak = compute_tap_tweak_hash(pub, merkle_root=merkle_root)
    out = ctypes.create_string_buffer(64)

    secp256k1 = get_secp256k1()

    result = secp256k1.lib.secp256k1_xonly_pubkey_tweak_add(
        secp256k1.ctx.verify, out, base_point, tweak)

    if result != 1:
        assert result == 0
        return None

    out_xonly = ctypes.create_string_buffer(64)

    parity_ret = ctypes.c_int()
    parity_ret.value = -1

    result = secp256k1.lib.secp256k1_xonly_pubkey_from_pubkey(
        secp256k1.ctx.verify, out_xonly, ctypes.byref(parity_ret),
        out)

    if result != 1:
        assert result == 0
        return None

    assert parity_ret.value in (0, 1)
    parity = bool(parity_ret.value)

    out_xonly_serialized = ctypes.create_string_buffer(32)

    result = secp256k1.lib.secp256k1_xonly_pubkey_serialize(
        secp256k1.ctx.verify, out_xonly_serialized, out_xonly)
    assert result == 1

    return XOnlyPubKey(out_xonly_serialized.raw), parity


__all__ = (
    'CKey',
    'CPubKey',
    'CExtKey',
    'CExtPubKey',
    'CKeyBase',
    'CExtKeyBase',
    'CExtPubKeyBase',
    'BIP32Path',
    'BIP32PathTemplate',
    'BIP32PathTemplateIndex',
    'KeyDerivationInfo',
    'KeyStore',
    'XOnlyPubKey',
    'compute_tap_tweak_hash',
    'check_tap_tweak',
    'tap_tweak_pubkey',
)
