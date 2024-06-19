# Copyright (C) 2012-2017 The python-bitcoinlib developers
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

import binascii
import struct
import decimal
from abc import abstractmethod
from io import BytesIO
from typing import (
    Union, List, Sequence, Iterable, Optional, Set, TypeVar, Type, Any,
    Dict, Tuple, Callable, ClassVar, cast
)

from . import script

from .serialize import (
    ImmutableSerializable, make_mutable,
    BytesSerializer, VectorSerializer,
    ser_read, uint256_to_bytes, uint256_from_bytes,
    Hash, Hash160, ByteStream_Type
)

from ..util import (
    no_bool_use_as_property, ClassMappingDispatcher, activate_class_dispatcher,
    dispatcher_wrap_methods, classgetter, ensure_isinstance, ContextVarsCompat,
    tagged_hasher
)

# NOTE: due to custom class dispatching and mutable/immmutable
# distinction, a lot of ReadOnlyField/WriteableField usage causes
# the fields of subclasses to be incompatible with fields in base classes.
# It is nevertheless useful to have the fields annotated with exact
# types that they will have at runtime. This is the reason there are
# a lot of 'type: ignore' comments where ReadOnlyField/WriteableField
# are used.
# Each 'type: ignore' related to ReadOnlyField/WriteableField
# thus is not given a rationale.
# This comment gives the rationale for all those type-ignores.
from ..util import ReadOnlyField, WriteableField


T__UintBitVector = TypeVar('T__UintBitVector', bound='_UintBitVector')


T_CoreCoinClass = TypeVar('T_CoreCoinClass', bound='CoreCoinClass')
T_CoreCoinClassDispatcher = TypeVar('T_CoreCoinClassDispatcher',
                                    bound='CoreCoinClassDispatcher')


class MutableContextVar(ContextVarsCompat):
    mutable_context_enabled: bool


_mutable_context = MutableContextVar(mutable_context_enabled=False)


class CoreCoinClassDispatcher(ClassMappingDispatcher, identity='core',
                              depends=[script.ScriptCoinClassDispatcher]):

    def __init_subclass__(mcs: Type[T_CoreCoinClassDispatcher], **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)

    def __new__(mcs: Type[T_CoreCoinClassDispatcher], name: str, bases: Tuple[type, ...],
                namespace: Dict[str, Any],
                mutable_of: Optional['CoreCoinClassDispatcher'] = None,
                **kwargs: Any) -> T_CoreCoinClassDispatcher:
        return super().__new__(mcs, name, bases, namespace, **kwargs)

    def __init__(cls: T_CoreCoinClassDispatcher, name: str,
                 bases: Tuple[type, ...], namespace: Dict[str, Any],
                 mutable_of: Optional[Type['CoreCoinClass']] = None,
                 **kwargs: Any) -> None:
        super().__init__(name, bases, namespace, **kwargs)
        if mutable_of is None:
            if not (cls.__name__ == 'CoreCoinClass' or
                    issubclass(cls, CoreCoinClass)):
                raise TypeError(f'{cls.__name__} must be a subclass of CoreCoinClass')
            cls._immutable_cls = cast(Type['CoreCoinClass'], cls)
            cls._mutable_cls = None
        else:
            if not issubclass(mutable_of, CoreCoinClass):
                raise TypeError('mutable_of must be a subclass of CoreCoinClass')

            if not issubclass(cls, mutable_of):
                raise TypeError(f'{cls.__class__.__name__} must be a subclass '
                                f'of {mutable_of.__class__.__name__}')

            make_mutable(cls)

            cls._immutable_cls = mutable_of
            cls._mutable_cls = cls
            assert mutable_of._immutable_cls == mutable_of
            assert mutable_of._mutable_cls is None
            mutable_of._mutable_cls = cls

            # Wrap methods of a mutable class so that
            # inside the methods, mutable context is enabled.
            # When it is enabled, __call__ and __getattribute__
            # will substitute immutable class for its mutable twin.
            combined_dict = mutable_of.__dict__.copy()
            combined_dict.update(cls.__dict__)

            def wrap(fn: Any, mcs: Any) -> Any:
                def wrapper(*args: Any, **kwargs: Any) -> Any:
                    # We are about to call a method of a mutable class.
                    # enable the mutable context, but save previous state.
                    prev_state = _mutable_context.mutable_context_enabled
                    _mutable_context.mutable_context_enabled = True
                    try:
                        return fn(*args, **kwargs)
                    finally:
                        # After the method call, restore the context
                        _mutable_context.mutable_context_enabled = prev_state

                return wrapper

            dispatcher_wrap_methods(cls, wrap, dct=combined_dict)

    def __call__(cls, *args: Any, **kwargs: Any) -> Any:
        if _mutable_context.mutable_context_enabled:
            # In the mutable context, new instances created should be mutable
            cls = type.__getattribute__(cls, '_mutable_cls') or cls
        return super().__call__(*args, **kwargs)

    def __getattribute__(cls, name: str) -> Any:
        if _mutable_context.mutable_context_enabled \
                and name == '_from_instance':
            # In the mutable context, new instances created should be mutable
            cls = type.__getattribute__(cls, '_mutable_cls') or cls
        return super().__getattribute__(name)


class CoreCoinClass(ImmutableSerializable, metaclass=CoreCoinClassDispatcher):

    _mutable_cls: Type['CoreCoinClass']
    _immutable_cls: Type['CoreCoinClass']

    def to_mutable(self) -> 'CoreCoinClass':
        return self._mutable_cls.from_instance(self)

    def to_immutable(self) -> 'CoreCoinClass':
        return self._immutable_cls.from_instance(self)

    @no_bool_use_as_property
    @classmethod
    def is_immutable(cls) -> bool:
        return not cls.is_mutable()

    @no_bool_use_as_property
    @classmethod
    def is_mutable(cls) -> bool:
        if cls is cls._mutable_cls:
            return True

        assert cls is cls._immutable_cls
        return False

    # Unfortunately we cannot type other_inst with generic type,
    # because for the mutable type the other instance might be the immutable
    # one, and immutable classes are superclases to the mutable.
    @classmethod
    def _from_instance(
        cls: Type[T_CoreCoinClass],
        other_inst: 'CoreCoinClass',
        *args: Any, **kwargs: Any
    ) -> T_CoreCoinClass:
        ensure_isinstance(other_inst, cls._immutable_cls,
                          'the argument')
        assert issubclass(cls, cls._immutable_cls), \
            (f"_immutable_cls ({cls._immutable_cls.__name__} expected to be "
             f"the same as cls ({cls.__name__}, or be a superclass of it")

        if cls.is_immutable() and other_inst.is_immutable():
            return cast(T_CoreCoinClass, other_inst)

        # CoreCoinClass() does not have arguments, but subclasses might have.
        # mypy complains here that there's too many arguments to CoreCoinClass.
        # We can define a dummy __init__(self, *args) with args ignored,
        # but that potentially means we could miss an erroneous arguments at
        # runtime. Better just ignore this typing check.
        return cls(*args, **kwargs)  # type: ignore

    @classmethod
    @abstractmethod
    def from_instance(cls: Type[T_CoreCoinClass], other_inst: Any
                      ) -> T_CoreCoinClass:
        ...

    def clone(self: T_CoreCoinClass) -> T_CoreCoinClass:
        return self.__class__.from_instance(self)


class CoreBitcoinClassDispatcher(
    CoreCoinClassDispatcher, depends=[script.ScriptBitcoinClassDispatcher]
):
    ...


class CoreBitcoinClass(CoreCoinClass, metaclass=CoreBitcoinClassDispatcher):
    ...


class CoreCoinParams(CoreCoinClass, next_dispatch_final=True):
    COIN = 100000000
    MAX_BLOCK_WEIGHT = 4000000
    WITNESS_SCALE_FACTOR = 4

    @classgetter
    def MAX_MONEY(cls) -> int:
        return 21000000 * cls.COIN

    TAPROOT_LEAF_TAPSCRIPT: int
    taptweak_hasher: Callable[[bytes], bytes]
    tapleaf_hasher: Callable[[bytes], bytes]
    tapbranch_hasher: Callable[[bytes], bytes]
    tap_sighash_hasher: Callable[[bytes], bytes]


class CoreBitcoinParams(CoreCoinParams, CoreBitcoinClass):
    PSBT_MAGIC_HEADER_BYTES = b'psbt\xff'
    PSBT_MAGIC_HEADER_BASE64 = 'cHNidP'

    TAPROOT_LEAF_TAPSCRIPT = 0xc0
    taptweak_hasher = tagged_hasher(b'TapTweak')
    tapleaf_hasher = tagged_hasher(b'TapLeaf')
    tapbranch_hasher = tagged_hasher(b'TapBranch')
    tap_sighash_hasher = tagged_hasher(b'TapSighash')


def MoneyRange(nValue: int) -> bool:
    # check is in satoshis, supplying float might indicate that
    # caller supplied the value in coins, not in satoshi
    ensure_isinstance(nValue, int, 'value for MoneyRange check')
    return 0 <= nValue <= CoreCoinParams.MAX_MONEY


def x(h: str) -> bytes:
    """Convert a hex string to bytes"""
    return binascii.unhexlify(h.encode('utf8'))


def b2x(b: Union[bytes, bytearray]) -> str:
    """Convert bytes to a hex string"""
    return binascii.hexlify(b).decode('utf8')


def lx(h: str) -> bytes:
    """Convert a little-endian hex string to bytes

    Lets you write uint256's and uint160's the way the Satoshi codebase shows
    them.
    """
    return binascii.unhexlify(h.encode('utf8'))[::-1]


def b2lx(b: Union[bytes, bytearray]) -> str:
    """Convert bytes to a little-endian hex string

    Lets you show uint256's and uint160's the way the Satoshi codebase shows
    them.
    """
    return binascii.hexlify(b[::-1]).decode('utf8')


def str_money_value(value: int) -> str:
    """Convert an integer money value to a fixed point string"""
    COIN = CoreCoinParams.COIN
    r = '%i.%08i' % (value // COIN, value % COIN)
    r = r.rstrip('0')
    if r[-1] == '.':
        r += '0'
    return r


def str_money_value_for_repr(nValue: int) -> str:
    if nValue >= 0:
        return "%s*COIN" % (str_money_value(nValue), )
    else:
        return "%d" % (nValue,)


def coins_to_satoshi(value: Union[int, float, decimal.Decimal],
                     check_range: bool = True) -> int:
    """Simple utility function to convert from coins amount
    expressed as a possibly fractional value - of type float or Decimal
    (or int, if the value value in coins is not fractional),
    to integer satoshi amount. essentially multiplies the value
    by CoreCoinParams.COIN with rounding, type conversion,
    and bounds checking (or without bounds checking, if check_range=False)"""

    # Sole number of coins can be expressed as int, so we allow int
    # in addition to fractional types
    ensure_isinstance(value, (int, float, decimal.Decimal), 'value in coins')

    result = int(round(decimal.Decimal(value) * CoreCoinParams.COIN))

    if check_range:
        if not MoneyRange(result):
            raise ValueError('resulting value ({}) is outside MoneyRange'
                             .format(result))

    return result


def satoshi_to_coins(value: int, check_range: bool = True) -> decimal.Decimal:
    """Simple utility function to convert from
    integer satoshi amonut to floating-point coins amount.
    does type checks and conversions, as well as bounds checking.
    (if check_range=False, bounds checking is not performed)"""

    # We expect that satoshi would always be expressed as integer
    ensure_isinstance(value, int, 'value in satoshi')

    if check_range:
        if not MoneyRange(value):
            raise ValueError('supplied value ({}) is outside MoneyRange'
                             .format(value))

    return decimal.Decimal(value) / CoreCoinParams.COIN


def get_size_of_compact_size(size: int) -> int:
    # comment from GetSizeOfCompactSize() src/serialize.h in Bitcoin Core:
    #
    # Compact Size
    # size <  253        -- 1 byte
    # size <= USHRT_MAX  -- 3 bytes  (253 + 2 bytes)
    # size <= UINT_MAX   -- 5 bytes  (254 + 4 bytes)
    # size >  UINT_MAX   -- 9 bytes  (255 + 8 bytes)

    if size < 0xFD:
        return 1
    elif size <= 0xFFFF:
        return 3
    elif size <= 0xFFFFFFFF:
        return 5
    else:
        return 9


def calculate_transaction_virtual_size(*,
                                       num_inputs: int,
                                       inputs_serialized_size: int,
                                       num_outputs: int,
                                       outputs_serialized_size: int,
                                       witness_size: int) -> int:

    """Calculate vsize of transaction given the number of inputs and
       outputs, the serialized size of inputs and outputs, and witness size.
       Useful for fee calculation at the time of coin selection, where you
       might not have CTransaction ready, but know all the parameters on
       that vsize depends on.

       Number of witnesses is always equal to number of inputs,
       and empty witnesses are encoded as a single zero byte.
       If there will be witnesses present in a transaction, `witness_size`
       must be larger than or equal to `num_inputs`.
       If the transaction will not include any witnesses, `witness_size`
       can be 0, or it can be equal to `num_inputs` (that is interpreted as
       'all witnesses are empty', and `witness_size` of 0 is used instead).
       Non-zero `witness_size` that is less than `num_inputs` is an error.

       Note that virtual size can also depend on number of sigops for the
       transaction, and this function does not account for this.

       In Bitcoin Core, virtual size is calculated as a maximum value
       between data-based calculated size and sigops-based calculated size.

       But for sigops-based size to be larger than data-based size, number
       of sigops have to be huge, and is unlikely to happen for normal scripts.
       Counting sigops also requires access to the inputs of the transaction,
       and the sigops-based size depends on adjustable parameter
       "-bytespersigop" in Bitcoin Core (default=20 for v0.18.1).

       If you care about sigops-based vsize and calculated your number of
       sigops, you can compare data-based size with your sigops-based size
       yourself, and use the maximum value. Do not forget that sigops-based
       size is also WITNESS_SCALE_FACTOR adjusted:
          (nSigOpCost * bytes_per_sigop
                      + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR

       """

    if witness_size != 0:
        if witness_size < num_inputs:
            raise ValueError(
                "witness_size should be >= num_inputs, "
                "because empty witness are encoded as a single zero byte.")
        if witness_size == num_inputs:
            # this can happen only if each witness is empty (single zero byte)
            # and therefore the transaction witness will be deemed empty,
            # and won't be serialized
            witness_size = 0
        else:
            # (marker byte, flag byte) that signal that the transaction
            # has witness present are included in witness size.
            witness_size += 2

    base_size = (
        4    # version
        + get_size_of_compact_size(num_inputs)
        + inputs_serialized_size
        + get_size_of_compact_size(num_outputs)
        + outputs_serialized_size
        + 4  # sequence
    )

    WITNESS_SCALE_FACTOR = CoreCoinParams.WITNESS_SCALE_FACTOR

    unscaled_size = (base_size * WITNESS_SCALE_FACTOR
                     + witness_size + WITNESS_SCALE_FACTOR-1)
    return unscaled_size // WITNESS_SCALE_FACTOR


def bytes_repr(buf: bytes, hexfun: Callable[[str], bytes] = x) -> str:
    if hexfun is x:
        bfun = b2x
    elif hexfun is lx:
        bfun = b2lx
    else:
        raise ValueError('invalid hexfun ({}) specified'.format(hexfun))
    if len(buf) > 0 and all(b == buf[0] for b in buf):
        return "{}('{}')*{}".format(hexfun.__name__, bfun(buf[:1]), len(buf))
    return "{}('{}')".format(hexfun.__name__, bfun(buf))


class ValidationError(Exception):
    """Base class for all blockchain validation errors

    Everything that is related to validating the blockchain, blocks,
    transactions, scripts, etc. is derived from this class.
    """


class AddressDataEncodingError(Exception):
    """Base class for all errors related to address encoding"""


class ReprOrStrMixin():

    @abstractmethod
    def _repr_or_str(self, strfn: Callable[[Any], str]) -> str:
        ...

    def __str__(self) -> str:
        return self._repr_or_str(str)

    def __repr__(self) -> str:
        return self._repr_or_str(repr)


class _UintBitVectorMeta(type):
    _UINT_WIDTH_BITS: int

    def __init__(self, name: str, bases: Tuple[type, ...], dct: Dict[str, Any]
                 ) -> None:
        if getattr(self, '_UINT_WIDTH_BITS', None) is not None:
            self._UINT_WIDTH_BYTES = self._UINT_WIDTH_BITS // 8
            assert self._UINT_WIDTH_BITS == self._UINT_WIDTH_BYTES * 8
            self.null_instance = bytes([0 for _ in range(self._UINT_WIDTH_BYTES)])


class _UintBitVector(ImmutableSerializable, metaclass=_UintBitVectorMeta):
    # should be specified by subclasses
    _UINT_WIDTH_BITS: int
    # to be set automatically by _UintBitVectorMeta
    _UINT_WIDTH_BYTES: int
    data: bytes

    def __init__(self, data: Optional[Union[bytes, bytearray]] = None):
        if data is None:
            data = b'\x00'*self._UINT_WIDTH_BYTES
        ensure_isinstance(data, (bytes, bytearray), 'data')
        if len(data) != self._UINT_WIDTH_BYTES:
            raise ValueError('invalid data length, should be {}'
                             .format(self._UINT_WIDTH_BYTES))
        object.__setattr__(self, 'data', bytes(data))

    @no_bool_use_as_property
    def is_null(self) -> bool:
        return all(b == 0 for b in self.data)

    @classmethod
    def stream_deserialize(cls: Type[T__UintBitVector], f: ByteStream_Type,
                           **kwargs: Any) -> T__UintBitVector:
        data = ser_read(f, cls._UINT_WIDTH_BYTES)
        return cls(data)

    def stream_serialize(self, f: ByteStream_Type, **kwargs: Any) -> None:
        f.write(self.data)

    def to_hex(self) -> str:
        return b2lx(self.data)

    @classmethod
    def from_hex(cls: Type[T__UintBitVector], hexdata: str) -> T__UintBitVector:
        return cls(lx(hexdata))

    def __repr__(self) -> str:
        return bytes_repr(self.data, hexfun=lx)


class Uint256(_UintBitVector):
    _UINT_WIDTH_BITS = 256

    @classmethod
    def from_int(cls, num: int) -> 'Uint256':
        ensure_isinstance(num, int, 'value')
        if not (num < 2**256):
            raise ValueError('value is too large')
        return cls(uint256_to_bytes(num))

    def to_int(self) -> int:
        return uint256_from_bytes(self.data)


T_COutPoint = TypeVar('T_COutPoint', bound='COutPoint')


class COutPoint(CoreCoinClass, next_dispatch_final=True):
    """The combination of a transaction hash and an index n into its vout"""
    __slots__: List[str] = ['hash', 'n']

    hash: ReadOnlyField[bytes]
    n: ReadOnlyField[int]

    to_mutable: ClassVar[Callable[['COutPoint'], 'CMutableOutPoint']]
    to_immutable: ClassVar[Callable[['COutPoint'], 'COutPoint']]

    def __init__(self, hash: Union[bytes, bytearray] = b'\x00'*32,
                 n: int = 0xffffffff):
        ensure_isinstance(hash, (bytes, bytearray), 'hash')
        ensure_isinstance(n, int, 'n')
        if not len(hash) == 32:
            raise ValueError('%s: hash must be exactly 32 bytes; got %d bytes'
                             % (self.__class__.__name__, len(hash)))
        object.__setattr__(self, 'hash', hash)
        if not (0 <= n <= 0xffffffff):
            raise ValueError('%s: n must be in range 0x0 to 0xffffffff; got %x'
                             % (self.__class__.__name__, n))
        object.__setattr__(self, 'n', n)

    @classmethod
    def stream_deserialize(cls: Type[T_COutPoint], f: ByteStream_Type,
                           **kwargs: Any) -> T_COutPoint:
        hash = ser_read(f, 32)
        n = struct.unpack(b"<I", ser_read(f, 4))[0]
        return cls(hash, n)

    def stream_serialize(self, f: ByteStream_Type, **kwargs: Any) -> None:
        assert len(self.hash) == 32
        f.write(self.hash)
        f.write(struct.pack(b"<I", self.n))

    @no_bool_use_as_property
    def is_null(self) -> bool:
        return ((self.hash == b'\x00'*32) and (self.n == 0xffffffff))

    def __repr__(self) -> str:
        if self.is_null():
            return '%s()' % (
                self.__class__.__name__
            )
        else:
            return '%s(lx(%r), %i)' % (
                self.__class__.__name__,
                b2lx(self.hash), self.n)

    def __str__(self) -> str:
        return '%s:%i' % (b2lx(self.hash), self.n)

    @classmethod
    def from_instance(cls: Type[T_COutPoint], outpoint: 'COutPoint'
                      ) -> T_COutPoint:
        return cls._from_instance(outpoint, outpoint.hash, outpoint.n)

    @classmethod
    def from_outpoint(cls: Type[T_COutPoint], outpoint: 'COutPoint'
                      ) -> T_COutPoint:
        return cls.from_instance(outpoint)


class CMutableOutPoint(COutPoint, mutable_of=COutPoint,
                       next_dispatch_final=True):
    hash: WriteableField[bytes]
    n: WriteableField[int]


class CBitcoinOutPoint(COutPoint, CoreBitcoinClass):
    """Bitcoin COutPoint"""
    __slots_: List[str] = []

    to_mutable: ClassVar[Callable[['CBitcoinOutPoint'],
                                  'CBitcoinMutableOutPoint']]
    to_immutable: ClassVar[Callable[['CBitcoinOutPoint'], 'CBitcoinOutPoint']]


class CBitcoinMutableOutPoint(CBitcoinOutPoint, CMutableOutPoint,
                              mutable_of=CBitcoinOutPoint):
    """A mutable Bitcoin COutPoint"""

    __slots_: List[str] = []


T_CTxIn = TypeVar('T_CTxIn', bound='CTxIn')


class CTxIn(CoreCoinClass, next_dispatch_final=True):
    """A base class for an input of a transaction

    Contains the location of the previous transaction's output that it claims,
    and a signature that matches the output's public key.
    """
    __slots_: List[str] = ['prevout', 'scriptSig', 'nSequence']

    prevout: ReadOnlyField[COutPoint]
    scriptSig: ReadOnlyField[script.CScript]
    nSequence: ReadOnlyField[int]

    to_mutable: ClassVar[Callable[['CTxIn'], 'CMutableTxIn']]
    to_immutable: ClassVar[Callable[['CTxIn'], 'CTxIn']]

    def __init__(self, prevout: Optional[COutPoint] = None,
                 scriptSig: Optional[Union[script.CScript, bytes, bytearray]] = None,
                 nSequence: int = 0xffffffff) -> None:

        ensure_isinstance(nSequence, int, 'nSequence')

        if not (0 <= nSequence <= 0xffffffff):
            raise ValueError('CTxIn: nSequence must be an integer between 0x0 and 0xffffffff; got %x' % nSequence)
        if scriptSig is None:
            scriptSig = script.CScript()
        elif not isinstance(scriptSig, script.CScript):
            ensure_isinstance(scriptSig, (bytes, bytearray),
                              'scriptSig that is not an instance of CScript')
            scriptSig = script.CScript(scriptSig)
        else:
            ensure_isinstance(scriptSig, script.CScript().__class__,
                              'scriptSig that is an instance of CScript')
        if prevout is None:
            prevout = COutPoint()
        elif self.is_mutable() or prevout.is_mutable():
            prevout = COutPoint.from_outpoint(prevout)
        ensure_isinstance(prevout, COutPoint, 'prevout')
        object.__setattr__(self, 'nSequence', nSequence)
        object.__setattr__(self, 'prevout', prevout)
        object.__setattr__(self, 'scriptSig', scriptSig)

    @classmethod
    def stream_deserialize(cls: Type[T_CTxIn], f: ByteStream_Type,
                           **kwargs: Any) -> T_CTxIn:
        prevout = COutPoint.stream_deserialize(f, **kwargs)
        scriptSig = BytesSerializer.stream_deserialize(f, **kwargs)
        nSequence = struct.unpack(b"<I", ser_read(f, 4))[0]
        return cls(prevout, scriptSig, nSequence)

    def stream_serialize(self, f: ByteStream_Type, **kwargs: Any) -> None:
        COutPoint.stream_serialize(self.prevout, f, **kwargs)
        BytesSerializer.stream_serialize(self.scriptSig, f, **kwargs)
        f.write(struct.pack(b"<I", self.nSequence))

    @no_bool_use_as_property
    def is_final(self) -> bool:
        return (self.nSequence == 0xffffffff)

    @classmethod
    def from_instance(cls: Type[T_CTxIn], txin: 'CTxIn') -> T_CTxIn:
        return cls._from_instance(txin,
                                  COutPoint.from_outpoint(txin.prevout),
                                  txin.scriptSig, txin.nSequence)

    @classmethod
    def from_txin(cls: Type[T_CTxIn], txin: 'CTxIn') -> T_CTxIn:
        """Create a mutable or immutable copy of an existing TxIn,
        depending on the class this method is called on.

        If cls and txin are both immutable, txin is returned directly.
        """
        return cls.from_instance(txin)

    def __repr__(self) -> str:
        return "%s(%s, %s, 0x%x)" % (
            self.__class__.__name__,
            repr(self.prevout), repr(self.scriptSig), self.nSequence)


class CMutableTxIn(CTxIn, mutable_of=CTxIn, next_dispatch_final=True):
    prevout: WriteableField[CMutableOutPoint]  # type: ignore
    scriptSig: WriteableField[script.CScript]
    nSequence: WriteableField[int]


class CBitcoinTxIn(CTxIn, CoreBitcoinClass):
    """An immutable Bitcoin TxIn"""
    __slots_: List[str] = []

    prevout: ReadOnlyField[CBitcoinOutPoint]  # type: ignore
    scriptSig: ReadOnlyField[script.CBitcoinScript]  # type: ignore

    to_mutable: ClassVar[Callable[['CBitcoinTxIn'], 'CBitcoinMutableTxIn']]
    to_immutable: ClassVar[Callable[['CBitcoinTxIn'], 'CBitcoinTxIn']]


class CBitcoinMutableTxIn(CBitcoinTxIn,  # type: ignore
                          CMutableTxIn, mutable_of=CBitcoinTxIn):
    """A mutable Bitcoin TxIn"""
    __slots_: List[str] = []

    prevout: WriteableField[CBitcoinMutableOutPoint]  # type: ignore


T_CTxOut = TypeVar('T_CTxOut', bound='CTxOut')


class CTxOut(CoreCoinClass, next_dispatch_final=True):
    """A base class for an output of a transaction

    Contains the public key that the next input must be able to sign with to
    claim it.
    """
    __slots_: List[str] = ['nValue', 'scriptPubKey']

    nValue: ReadOnlyField[int]
    scriptPubKey: ReadOnlyField[script.CScript]

    to_mutable: ClassVar[Callable[['CTxOut'], 'CMutableTxOut']]
    to_immutable: ClassVar[Callable[['CTxOut'], 'CTxOut']]

    def __init__(self, nValue: int = -1,
                 scriptPubKey: Optional[script.CScript] = None):
        ensure_isinstance(nValue, int, 'nValue')

        if scriptPubKey is None:
            scriptPubKey = script.CScript()
        elif not isinstance(scriptPubKey, script.CScript):
            ensure_isinstance(scriptPubKey, (bytes, bytearray),
                              'scriptPubKey that is not an instance of CScript')
            scriptPubKey = script.CScript(scriptPubKey)
        else:
            ensure_isinstance(scriptPubKey, script.CScript().__class__,
                              'scriptPubKey that is an instance of CScript')

        object.__setattr__(self, 'nValue', int(nValue))
        object.__setattr__(self, 'scriptPubKey', scriptPubKey)

    @classmethod
    def stream_deserialize(cls: Type[T_CTxOut], f: ByteStream_Type,
                           **kwargs: Any) -> T_CTxOut:
        nValue = struct.unpack(b"<q", ser_read(f, 8))[0]
        scriptPubKey = BytesSerializer.stream_deserialize(f, **kwargs)
        return cls(nValue, script.CScript(scriptPubKey))

    def stream_serialize(self, f: ByteStream_Type, **kwargs: Any) -> None:
        f.write(struct.pack(b"<q", self.nValue))
        BytesSerializer.stream_serialize(self.scriptPubKey, f, **kwargs)

    @no_bool_use_as_property
    def is_valid(self) -> bool:
        if not MoneyRange(self.nValue):
            return False
        if not self.scriptPubKey.is_valid():
            return False
        return True

    def __repr__(self) -> str:
        return "%s(%s, %r)" % (
            self.__class__.__name__,
            str_money_value_for_repr(self.nValue), self.scriptPubKey)

    @classmethod
    def from_instance(cls: Type[T_CTxOut], txout: 'CTxOut') -> T_CTxOut:
        return cls._from_instance(txout, txout.nValue, txout.scriptPubKey)

    @classmethod
    def from_txout(cls: Type[T_CTxOut], txout: 'CTxOut') -> T_CTxOut:
        return cls.from_instance(txout)


class CMutableTxOut(CTxOut, mutable_of=CTxOut, next_dispatch_final=True):

    nValue: WriteableField[int]
    scriptPubKey: WriteableField[script.CScript]


class CBitcoinTxOut(CTxOut, CoreBitcoinClass):
    """A immutable Bitcoin TxOut"""
    __slots_: List[str] = []

    scriptPubKey: ReadOnlyField[script.CBitcoinScript]  # type: ignore

    to_mutable: ClassVar[Callable[['CBitcoinTxOut'], 'CBitcoinMutableTxOut']]
    to_immutable: ClassVar[Callable[['CBitcoinTxOut'], 'CBitcoinTxOut']]


class CBitcoinMutableTxOut(CBitcoinTxOut, CMutableTxOut,
                           mutable_of=CBitcoinTxOut):
    """A mutable Bitcoin CTxOut"""
    __slots_: List[str] = []

    scriptPubKey: WriteableField[script.CBitcoinScript]  # type: ignore


T_CTxInWitness = TypeVar('T_CTxInWitness', bound='CTxInWitness')


class CTxInWitness(CoreCoinClass, next_dispatch_final=True):
    """A base class for witness data for a single transaction input"""
    __slots_: List[str] = ['scriptWitness']

    scriptWitness: ReadOnlyField[script.CScriptWitness]

    to_mutable: ClassVar[Callable[['CTxInWitness'], 'CMutableTxInWitness']]
    to_immutable: ClassVar[Callable[['CTxInWitness'], 'CTxInWitness']]

    def __init__(self, scriptWitness: Optional[script.CScriptWitness] = None):
        if scriptWitness is None:
            scriptWitness = script.CScriptWitness()
        else:
            ensure_isinstance(scriptWitness, script.CScriptWitness, 'scriptWitness')

        object.__setattr__(self, 'scriptWitness', scriptWitness)

    @no_bool_use_as_property
    def is_null(self) -> bool:
        return self.scriptWitness.is_null()

    @classmethod
    def stream_deserialize(cls: Type[T_CTxInWitness], f: ByteStream_Type,
                           **kwargs: Any) -> T_CTxInWitness:
        scriptWitness = script.CScriptWitness.stream_deserialize(f, **kwargs)
        return cls(scriptWitness)

    def stream_serialize(self, f: ByteStream_Type, **kwargs: Any) -> None:
        self.scriptWitness.stream_serialize(f, **kwargs)

    @classmethod
    def from_instance(cls: Type[T_CTxInWitness],
                      txin_witness: 'CTxInWitness',
                      ) -> T_CTxInWitness:
        return cls._from_instance(txin_witness, txin_witness.scriptWitness)

    @classmethod
    def from_txin_witness(cls: Type[T_CTxInWitness],
                          txin_witness: 'CTxInWitness',
                          ) -> T_CTxInWitness:
        return cls.from_instance(txin_witness)

    def __repr__(self) -> str:
        return "%s(%s)" % (self.__class__.__name__, repr(self.scriptWitness))


class CMutableTxInWitness(CTxInWitness, mutable_of=CTxInWitness,
                          next_dispatch_final=True):

    scriptWitness: WriteableField[script.CScriptWitness]


class CBitcoinTxInWitness(CTxInWitness, CoreBitcoinClass):
    """Immutable Bitcoin witness data for a single transaction input"""
    __slots_: List[str] = []

    to_mutable: ClassVar[Callable[['CBitcoinTxInWitness'],
                                  'CBitcoinMutableTxInWitness']]
    to_immutable: ClassVar[Callable[['CBitcoinTxInWitness'],
                                    'CBitcoinTxInWitness']]


class CBitcoinMutableTxInWitness(CBitcoinTxInWitness, CMutableTxInWitness,
                                 mutable_of=CBitcoinTxInWitness):
    """Mutable Bitcoin witness data for a single transaction input"""
    __slots_: List[str] = []


T_CTxOutWitness = TypeVar('T_CTxOutWitness', bound='CTxOutWitness')


class CTxOutWitness(CoreCoinClass, next_dispatch_final=True):

    to_mutable: ClassVar[Callable[['CTxOutWitness'], 'CMutableTxOutWitness']]
    to_immutable: ClassVar[Callable[['CTxOutWitness'], 'CTxOutWitness']]

    @classmethod
    def from_instance(cls: Type[T_CTxOutWitness], witness: 'CTxOutWitness'
                      ) -> T_CTxOutWitness:
        return cls._from_instance(witness)


class CMutableTxOutWitness(CTxOutWitness, mutable_of=CTxOutWitness,
                           next_dispatch_final=True):
    pass


class _CBitcoinDummyTxOutWitness(CTxOutWitness, CoreBitcoinClass):
    pass


class _CBitcoinDummyMutableTxOutWitness(
    _CBitcoinDummyTxOutWitness, CMutableTxOutWitness,
    mutable_of=_CBitcoinDummyTxOutWitness
):
    pass


T_CTxWitness = TypeVar('T_CTxWitness', bound='CTxWitness')


class CTxWitness(CoreCoinClass, next_dispatch_final=True):
    """Witness data for all inputs to a transaction"""
    __slots_: List[str] = ['vtxinwit']

    vtxinwit: ReadOnlyField[Tuple[CTxInWitness, ...]]

    to_mutable: ClassVar[Callable[['CTxWitness'], 'CMutableTxWitness']]
    to_immutable: ClassVar[Callable[['CTxWitness'], 'CTxWitness']]

    def __init__(self, vtxinwit: Iterable[CTxInWitness] = (),
                 vtxoutwit: Iterable[CTxOutWitness] = ()) -> None:
        # Note: vtxoutwit is ignored, does not exist for bitcon tx witness
        txinwit_list = [CTxInWitness.from_txin_witness(w) for w in vtxinwit]

        txinwit: Sequence[CTxInWitness]
        if self.is_immutable():
            txinwit = tuple(txinwit_list)
        else:
            txinwit = txinwit_list

        # Note: vtxoutwit is ignored, does not exist for bitcon tx witness
        object.__setattr__(self, 'vtxinwit', txinwit)

    @no_bool_use_as_property
    def is_null(self) -> bool:
        for n in range(len(self.vtxinwit)):
            if not self.vtxinwit[n].is_null():
                return False
        return True

    @classmethod
    def stream_deserialize(cls: Type[T_CTxWitness], f: ByteStream_Type,
                           num_inputs: int = -1, **kwargs: Any) -> T_CTxWitness:
        if num_inputs < 0:
            raise ValueError(
                'num_inputs must be specified (and must be non-negative)')
        vtxinwit = tuple(CTxInWitness.stream_deserialize(f, **kwargs)
                         for dummy in range(num_inputs))
        return cls(vtxinwit)

    def stream_serialize(self, f: ByteStream_Type, **kwargs: Any) -> None:
        for i in range(len(self.vtxinwit)):
            self.vtxinwit[i].stream_serialize(f, **kwargs)

    @classmethod
    def from_instance(cls: Type[T_CTxWitness], witness: 'CTxWitness'
                      ) -> T_CTxWitness:
        vtxinwit = (CTxInWitness.from_txin_witness(w)
                    for w in witness.vtxinwit)
        return cls._from_instance(witness, vtxinwit)

    @classmethod
    def from_witness(cls: Type[T_CTxWitness], witness: 'CTxWitness'
                     ) -> T_CTxWitness:
        return cls.from_instance(witness)

    def __repr__(self) -> str:
        return "%s([%s])" % (self.__class__.__name__,
                             ','.join(repr(w) for w in self.vtxinwit))


class CMutableTxWitness(CTxWitness, mutable_of=CTxWitness,
                        next_dispatch_final=True):

    vtxinwit: WriteableField[List[CMutableTxInWitness]]  # type: ignore


class CBitcoinTxWitness(CTxWitness, CoreBitcoinClass):
    """Immutable witness data for all inputs to a transaction"""
    __slots_: List[str] = []

    vtxinwit: ReadOnlyField[Tuple[CBitcoinTxInWitness, ...]]  # type: ignore

    to_mutable: ClassVar[Callable[['CBitcoinTxWitness'],
                                  'CBitcoinMutableTxWitness']]
    to_immutable: ClassVar[Callable[['CBitcoinTxWitness'], 'CBitcoinTxWitness']]


class CBitcoinMutableTxWitness(CBitcoinTxWitness,
                               CMutableTxWitness, mutable_of=CBitcoinTxWitness):
    """Witness data for all inputs to a transaction, mutable version"""
    __slots_: List[str] = []

    vtxinwit: WriteableField[List[CBitcoinMutableTxInWitness]]  # type: ignore


T_CTransaction = TypeVar('T_CTransaction', bound='CTransaction')


class CTransaction(ReprOrStrMixin, CoreCoinClass, next_dispatch_final=True):
    __slots_: List[str] = ['nVersion', 'vin', 'vout', 'nLockTime', 'wit']

    nVersion: ReadOnlyField[int]
    vin: ReadOnlyField[Tuple[CTxIn, ...]]
    vout: ReadOnlyField[Tuple[CTxOut, ...]]
    nLockTime: ReadOnlyField[int]
    wit: ReadOnlyField[CTxWitness]

    CURRENT_VERSION: int = 2

    # Cannot make to_mutable/to_immutable to use generic typing,
    # because the types are determined at runtime depending on
    # what class is storred in _mutable_cls/_immutable_cls.
    # Type of self might be different from return type.
    #
    # We have to specify types for these methods manually,
    # here and in the chain-specific subclasses, too.
    to_mutable: ClassVar[Callable[['CTransaction'], 'CMutableTransaction']]
    to_immutable: ClassVar[Callable[['CTransaction'], 'CTransaction']]

    def __init__(self, vin: Iterable[CTxIn] = (), vout: Iterable[CTxOut] = (),
                 nLockTime: int = 0, nVersion: Optional[int] = None,
                 witness: Optional[CTxWitness] = None):
        """Create a new transaction

        vin and vout are iterables of transaction inputs and outputs
        respectively. If their contents are not already immutable, immutable
        copies will be made.
        """
        ensure_isinstance(nLockTime, int, 'nLockTime')

        if not (0 <= nLockTime <= 0xffffffff):
            raise ValueError('CTransaction: nLockTime must be in range 0x0 to 0xffffffff; got %x' % nLockTime)

        if nVersion is None:
            nVersion = self.CURRENT_VERSION
        else:
            ensure_isinstance(nVersion, int, 'nVersion')

        if witness is None or (witness.is_null() and self.is_mutable()):
            if self.is_mutable():
                new_witness = CTxWitness([CTxInWitness() for dummy in vin],
                                         [CTxOutWitness() for dummy in vout])
                if witness is not None:
                    ensure_isinstance(witness, new_witness._immutable_cls,
                                      'witness')
                witness = new_witness
            else:
                assert witness is None
                witness = CTxWitness()

        else:
            witness = CTxWitness.from_witness(witness)

        tuple_or_list = list if self.is_mutable() else tuple

        object.__setattr__(self, 'nLockTime', nLockTime)
        object.__setattr__(self, 'nVersion', nVersion)
        object.__setattr__(self, 'vin', tuple_or_list(
            CTxIn.from_txin(txin) for txin in vin))
        object.__setattr__(self, 'vout', tuple_or_list(
            CTxOut.from_txout(txout) for txout in vout))
        object.__setattr__(self, 'wit', witness)

    @no_bool_use_as_property
    def is_coinbase(self) -> bool:
        return len(self.vin) == 1 and self.vin[0].prevout.is_null()

    @no_bool_use_as_property
    def is_null(self) -> bool:
        return (not self.vin) and (not self.vout)

    def has_witness(self) -> bool:
        """True if witness"""
        return not self.wit.is_null()

    def _repr_or_str(self, strfn: Callable[[Any], str]) -> str:
        return "%s([%s], [%s], %i, %i, %s)" % (
            self.__class__.__name__,
            ', '.join(strfn(v) for v in self.vin),
            ', '.join(strfn(v) for v in self.vout),
            self.nLockTime, self.nVersion, strfn(self.wit))

    def GetTxid(self) -> bytes:
        """Get the transaction ID.  This differs from the transactions hash as
            given by GetHash.  GetTxid excludes witness data, while GetHash
            includes it. """

        if not self.wit.is_null():
            txid = Hash(CTransaction(
                self.vin, self.vout, self.nLockTime, self.nVersion).serialize())
        else:
            txid = Hash(self.serialize())
        return txid

    @classmethod
    def from_instance(cls: Type[T_CTransaction],
                      tx: 'CTransaction') -> T_CTransaction:
        vin = [CTxIn.from_txin(txin) for txin in tx.vin]
        vout = [CTxOut.from_txout(txout)
                for txout in tx.vout]
        wit = CTxWitness.from_witness(tx.wit)
        return cls._from_instance(tx,
                                  vin, vout, tx.nLockTime, tx.nVersion, wit)

    @classmethod
    def from_tx(cls: Type[T_CTransaction],
                tx: 'CTransaction') -> T_CTransaction:
        return cls.from_instance(tx)

    @classmethod
    def stream_deserialize(cls: Type[T_CTransaction], f: ByteStream_Type,
                           **kwargs: Any) -> T_CTransaction:
        """Deserialize transaction

        This implementation corresponds to Bitcoin's SerializeTransaction() and
        consensus behavior. Note that Bitcoin's DecodeHexTx() also has the
        option to attempt deserializing as a non-witness transaction first,
        falling back to the consensus behavior if it fails. The difference lies
        in transactions which have zero inputs: they are invalid but may be
        (de)serialized anyway for the purpose of signing them and adding
        inputs. If the behavior of DecodeHexTx() is needed it could be added,
        but not here.
        """
        nVersion = struct.unpack(b"<i", ser_read(f, 4))[0]

        # Try to read the vin.
        # In case the dummy is there, this will be read as an empty vector.
        vin = VectorSerializer.stream_deserialize(
            f, element_class=CTxIn, **kwargs)

        flags = 0

        if not vin:
            # We read a dummy or an empty vin
            flags = struct.unpack(b'B', ser_read(f, 1))[0]
            if flags != 0:
                vin = VectorSerializer.stream_deserialize(
                    f, element_class=CTxIn, **kwargs)
                vout = VectorSerializer.stream_deserialize(
                    f, element_class=CTxOut, **kwargs)
        else:
            # We read a non-empty vin. Assume a normal vout follows.
            vout = VectorSerializer.stream_deserialize(
                f, element_class=CTxOut, **kwargs)

        wit = None

        if flags & 1:
            # The witness flag is present,
            # and we unconditionally support witnesses (see docstring)
            flags ^= 1

            wit = CTxWitness.stream_deserialize(f, num_inputs=len(vin),
                                                **kwargs)
            if wit.is_null():
                # It's illegal to encode witnesses
                # when all witness stacks are empty.
                raise ValueError('Superfluous witness record')

        if flags:
            # Unknown flag in the serialization
            raise ValueError('Unknown transaction optional data')

        nLockTime = struct.unpack(b"<I", ser_read(f, 4))[0]

        return cls(vin, vout, nLockTime, nVersion, wit)

    # NOTE: for_sighash is ignored, but may be used in other implementations
    def stream_serialize(self, f: ByteStream_Type,
                         include_witness: bool = True, **kwargs: Any) -> None:
        f.write(struct.pack(b"<i", self.nVersion))
        if include_witness and not self.wit.is_null():
            assert len(self.wit.vtxinwit) == len(self.vin)
            f.write(b'\x00')  # Marker
            f.write(b'\x01')  # Flag
            VectorSerializer.stream_serialize(self.vin, f, **kwargs)
            VectorSerializer.stream_serialize(self.vout, f, **kwargs)
            self.wit.stream_serialize(f, **kwargs)
        else:
            VectorSerializer.stream_serialize(self.vin, f, **kwargs)
            VectorSerializer.stream_serialize(self.vout, f, **kwargs)
        f.write(struct.pack(b"<I", self.nLockTime))

    def get_virtual_size(self) -> int:
        """Calculate virtual size for the transaction.

        Note that calculation does not take sigops into account.
        Sigops-based vsize is only relevant for highly non-standard
        scripts with very high sigop count, and cannot be directly deduced
        giving only the data of one transaction.

        see docstring for `calculate_transaction_virtual_size()`
        for more detailed explanation."""
        f = BytesIO()
        for vin in self.vin:
            vin.stream_serialize(f)
        inputs_size = len(f.getbuffer())
        f = BytesIO()
        for vout in self.vout:
            vout.stream_serialize(f)
        outputs_size = len(f.getbuffer())
        f = BytesIO()
        if self.wit.is_null():
            witness_size = 0
        else:
            self.wit.stream_serialize(f)
            witness_size = len(f.getbuffer())

        return calculate_transaction_virtual_size(
            num_inputs=len(self.vin),
            inputs_serialized_size=inputs_size,
            num_outputs=len(self.vout),
            outputs_serialized_size=outputs_size,
            witness_size=witness_size)


class CMutableTransaction(CTransaction, mutable_of=CTransaction,
                          next_dispatch_final=True):
    nVersion: WriteableField[int]
    vin: WriteableField[List[CMutableTxIn]]  # type: ignore
    vout: WriteableField[List[CMutableTxOut]]  # type: ignore
    nLockTime: WriteableField[int]
    wit: WriteableField[CMutableTxWitness]  # type: ignore


class CBitcoinTransaction(CTransaction, CoreBitcoinClass):
    """Bitcoin transaction"""
    __slots_: List[str] = []

    vin: ReadOnlyField[Tuple[CBitcoinTxIn, ...]]  # type: ignore
    vout: ReadOnlyField[Tuple[CBitcoinTxOut, ...]]  # type: ignore
    wit: ReadOnlyField[CBitcoinTxWitness]  # type: ignore

    to_mutable: ClassVar[Callable[['CBitcoinTransaction'],
                                  'CBitcoinMutableTransaction']]
    to_immutable: ClassVar[Callable[['CBitcoinTransaction'],
                                    'CBitcoinTransaction']]


class CBitcoinMutableTransaction(CBitcoinTransaction,
                                 CMutableTransaction,
                                 mutable_of=CBitcoinTransaction):
    """Bitcoin transaction, mutable version"""
    __slots_: List[str] = []

    vin: WriteableField[List[CBitcoinMutableTxIn]]  # type: ignore
    vout: WriteableField[List[CBitcoinMutableTxOut]]  # type: ignore
    wit: WriteableField[CBitcoinMutableTxWitness]  # type: ignore


class CheckTransactionError(ValidationError):
    pass


def CheckTransaction(tx: CTransaction) -> None:  # noqa
    """Basic transaction checks that don't depend on any context.

    Raises CheckTransactionError
    """

    if not tx.vin:
        raise CheckTransactionError("CheckTransaction() : vin empty")
    if not tx.vout:
        raise CheckTransactionError("CheckTransaction() : vout empty")

    # Size limits
    base_tx = tx.to_immutable()
    weight = (len(base_tx.serialize(include_witness=False))
              * CoreCoinParams.WITNESS_SCALE_FACTOR)
    if weight > CoreCoinParams.MAX_BLOCK_WEIGHT:
        raise CheckTransactionError("CheckTransaction() : size limits failed")

    # Check for negative or overflow output values
    nValueOut = 0
    for txout in tx.vout:
        if txout.nValue < 0:
            raise CheckTransactionError("CheckTransaction() : txout.nValue negative")
        if txout.nValue > CoreCoinParams.MAX_MONEY:
            raise CheckTransactionError("CheckTransaction() : txout.nValue too high")
        nValueOut += txout.nValue
        if not MoneyRange(nValueOut):
            raise CheckTransactionError("CheckTransaction() : txout total out of range")

    # Check for duplicate inputs
    vin_outpoints: Set[COutPoint] = set()
    for txin in tx.vin:
        if txin.prevout in vin_outpoints:
            raise CheckTransactionError("CheckTransaction() : duplicate inputs")
        vin_outpoints.add(txin.prevout)

    if tx.is_coinbase():
        if not (2 <= len(tx.vin[0].scriptSig) <= 100):
            raise CheckTransactionError("CheckTransaction() : coinbase script size")

    else:
        for txin in tx.vin:
            if txin.prevout.is_null():
                raise CheckTransactionError("CheckTransaction() : prevout is null")


def GetLegacySigOpCount(tx: CTransaction) -> int:
    nSigOps = 0
    for txin in tx.vin:
        nSigOps += txin.scriptSig.GetSigOpCount(False)
    for txout in tx.vout:
        nSigOps += txout.scriptPubKey.GetSigOpCount(False)
    return nSigOps


# default dispatcher for the module
activate_class_dispatcher(CoreBitcoinClassDispatcher)

__all__ = (
    'Hash',
    'Hash160',
    'MoneyRange',
    'x',
    'b2x',
    'lx',
    'b2lx',
    'str_money_value',
    'ValidationError',
    'AddressDataEncodingError',
    'COutPoint',
    'CMutableOutPoint',
    'CTxIn',
    'CMutableTxIn',
    'CTxOut',
    'CMutableTxOut',
    'CTransaction',
    'CMutableTransaction',
    'CTxWitness',
    'CMutableTxWitness',
    'CMutableTxInWitness',
    'CMutableTxOutWitness',
    'CTxInWitness',
    'CTxOutWitness',
    'CBitcoinOutPoint',
    'CBitcoinMutableOutPoint',
    'CBitcoinTxIn',
    'CBitcoinMutableTxIn',
    'CBitcoinTxOut',
    'CBitcoinMutableTxOut',
    'CBitcoinTransaction',
    'CBitcoinMutableTransaction',
    'CBitcoinTxWitness',
    'CBitcoinMutableTxWitness',
    'CBitcoinMutableTxInWitness',
    'CBitcoinTxInWitness',
    'CheckTransactionError',
    'CheckTransaction',
    'GetLegacySigOpCount',
    'Uint256',
    'str_money_value_for_repr',
    'satoshi_to_coins',
    'coins_to_satoshi',
    'get_size_of_compact_size',
    'calculate_transaction_virtual_size',
    'CoreCoinClassDispatcher',
    'CoreCoinClass',
    'CoreBitcoinClassDispatcher',
    'CoreBitcoinClass',
    'CoreCoinParams',
    'CoreBitcoinParams',
)
