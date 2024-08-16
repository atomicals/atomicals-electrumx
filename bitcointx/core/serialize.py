# Copyright (C) 2012-2018 The python-bitcoinlib developers
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

"""Serialization routines

You probabably don't need to use these directly.
"""

import hashlib
import struct
from typing import (
    List, Tuple, Sequence, Union, TypeVar, Type, Generic, Any, Optional, cast
)
from ..util import ensure_isinstance
from ._ripemd160 import ripemd160

from io import BytesIO

# Using IOBase here is not possible, because it does not define read(),
# for example. And RawIOBase and BufferedIOBase are distinct, and thus
# we will need to use a Union, and this still will not be universal.
# Better stick with BytesIO for now.
# Might switch to a Protocol later, but to date there was no need
# for anything other than BytesIO.
ByteStream_Type = BytesIO

MAX_SIZE = 0x02000000

T_unbounded = TypeVar('T_unbounded')
T_ImmutableSerializable = TypeVar('T_ImmutableSerializable',
                                  bound='ImmutableSerializable')


def Hash(msg: Union[bytes, bytearray]) -> bytes:
    """SHA256^2)(msg) -> bytes"""
    return hashlib.sha256(hashlib.sha256(msg).digest()).digest()


def Hash160(msg: Union[bytes, bytearray]) -> bytes:
    """RIPEME160(SHA256(msg)) -> bytes"""
    return ripemd160(hashlib.sha256(msg).digest())


class SerializationError(Exception):
    """Base class for serialization errors"""


class SerializationTruncationError(SerializationError):
    """Serialized data was truncated

    Thrown by deserialize() and stream_deserialize()
    """


class DeserializationExtraDataError(SerializationError):
    """Deserialized data had extra data at the end

    Thrown by deserialize() when not all data is consumed during
    deserialization. The deserialized object and extra padding not consumed are
    saved.
    """
    def __init__(self, msg: str, obj: 'Serializable', padding: bytes):
        super().__init__(msg)
        self.obj = obj
        self.padding = padding


class DeserializationValueBoundsError(SerializationError):
    """Deserialized value out of bounds

    Thrown by deserialize() when a deserialized value turns out to be out
    of allowed bounds
    """

    def __init__(self, msg: str, *, klass: Type['Serializer[T_unbounded]'],
                 value: int, upper_bound: int, lower_bound: int):
        super().__init__(msg)
        self.klass = klass
        self.value = value
        self.upper_bound = upper_bound
        self.lower_bound = lower_bound


def ser_read(f: ByteStream_Type, n: int) -> bytes:
    """Read from a stream safely

    Raises SerializationError and SerializationTruncationError appropriately.
    Use this instead of f.read() in your classes stream_(de)serialization()
    functions.
    """
    if n > MAX_SIZE:
        raise SerializationError('Asked to read 0x%x bytes; MAX_SIZE exceeded' % n)
    r = f.read(n)
    if len(r) < n:
        raise SerializationTruncationError('Asked to read %i bytes, but only got %i' % (n, len(r)))
    return r


T_Serializable = TypeVar('T_Serializable', bound='Serializable')


class Serializable(object):
    """Base class for serializable objects"""

    __slots__: List[str] = []

    def stream_serialize(self, f: ByteStream_Type, **kwargs: Any) -> None:
        """Serialize to a stream"""
        raise NotImplementedError

    @classmethod
    def stream_deserialize(cls: Type[T_Serializable], f: ByteStream_Type,
                           **kwargs: Any) -> T_Serializable:
        """Deserialize from a stream"""
        raise NotImplementedError

    def serialize(self, **kwargs: Any) -> bytes:
        """Serialize, returning bytes"""
        f = BytesIO()
        self.stream_serialize(f, **kwargs)
        return f.getvalue()

    @classmethod
    def deserialize(cls: Type[T_Serializable], buf: Union[bytes, bytearray],
                    allow_padding: bool = False, **kwargs: Any
                    ) -> T_Serializable:
        """Deserialize bytes, returning an instance

        allow_padding - Allow buf to include extra padding. (default False)

        If allow_padding is False and not all bytes are consumed during
        deserialization DeserializationExtraDataError will be raised.
        """
        fd = BytesIO(buf)
        r = cls.stream_deserialize(fd, **kwargs)
        if not allow_padding:
            padding = fd.read()
            if len(padding) != 0:
                raise DeserializationExtraDataError('Not all bytes consumed during deserialization',
                                                    r, padding)
        return r

    def GetHash(self) -> bytes:
        """Return the hash of the serialized object"""
        return Hash(self.serialize())

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, self.__class__)\
                and not isinstance(self, other.__class__):
            return NotImplemented
        other_serializable = cast(Serializable, other)
        return self.serialize() == other_serializable.serialize()

    def __ne__(self, other: Any) -> bool:
        return not (self == other)

    def __hash__(self) -> int:
        return hash(self.serialize())


class ImmutableSerializable(Serializable):
    """Immutable serializable object"""

    __slots__: List[str] = ['_cached_GetHash', '_cached__hash__']

    _cached_GetHash: bytes
    _cached__hash__: int

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError('Object is immutable')

    def __delattr__(self, name: str) -> None:
        raise AttributeError('Object is immutable')

    def GetHash(self) -> bytes:
        """Return the hash of the serialized object"""
        try:
            return self._cached_GetHash
        except AttributeError:
            _cached_GetHash = super().GetHash()
            object.__setattr__(self, '_cached_GetHash', _cached_GetHash)
            return _cached_GetHash

    def __hash__(self) -> int:
        try:
            return self._cached__hash__
        except AttributeError:
            _cached__hash__ = hash(self.serialize())
            object.__setattr__(self, '_cached__hash__', _cached__hash__)
            return _cached__hash__


class Serializer(Generic[T_unbounded]):
    """Base class for object serializers"""
    def __new__(cls: Type['Serializer[T_unbounded]']
                ) -> 'Serializer[T_unbounded]':
        raise NotImplementedError

    @classmethod
    def stream_serialize(cls, obj: T_unbounded, f: ByteStream_Type,
                         **kwargs: Any) -> None:
        raise NotImplementedError

    @classmethod
    def stream_deserialize(cls, f: ByteStream_Type,
                           **kwargs: Any) -> T_unbounded:
        raise NotImplementedError

    @classmethod
    def serialize(cls, obj: T_unbounded, **kwargs: Any) -> bytes:
        f = BytesIO()
        cls.stream_serialize(obj, f, **kwargs)
        return f.getvalue()

    @classmethod
    def deserialize_partial(cls, buf: bytes, **kwargs: Any
                            ) -> Tuple[T_unbounded, bytes]:
        ensure_isinstance(buf, (bytes, bytearray), 'data to deserialize')
        f = BytesIO(buf)
        return cls.stream_deserialize(f, **kwargs), f.read(-1)

    @classmethod
    def deserialize(cls, buf: bytes, **kwargs: Any) -> T_unbounded:
        inst: T_unbounded
        inst, tail = cls.deserialize_partial(buf, **kwargs)
        if tail:
            raise ValueError(
                f'stray data after deserialization: '
                f'{len(buf)} byte(s) unaccounted for')
        return inst


class VarIntSerializer(Serializer[int]):
    """Serialization of variable length ints"""
    @classmethod
    def stream_serialize(cls, obj: int, f: ByteStream_Type,
                         **kwargs: Any) -> None:
        i = obj
        if i < 0:
            raise ValueError('varint must be non-negative integer')
        elif i < 0xfd:
            f.write(bytes([i]))
        elif i <= 0xffff:
            f.write(bytes([0xfd]))
            f.write(struct.pack(b'<H', i))
        elif i <= 0xffffffff:
            f.write(bytes([0xfe]))
            f.write(struct.pack(b'<I', i))
        else:
            f.write(bytes([0xff]))
            f.write(struct.pack(b'<Q', i))

    @classmethod
    def stream_deserialize(cls, f: ByteStream_Type,
                           allow_full_range: bool = False, **kwargs: Any
                           ) -> int:
        r = ser_read(f, 1)[0]

        if r < 0xfd:
            return r

        if r == 0xfd:
            v = int(struct.unpack(b'<H', ser_read(f, 2))[0])
            lower_bound = 0xfd
            if v < lower_bound:
                raise DeserializationValueBoundsError(
                    f"non-canonical 3-byte compact size for variable integer: "
                    f"0x{v:x} less than 0x{lower_bound:x}",
                    klass=cls, value=v, lower_bound=lower_bound,
                    upper_bound=0xFFFF)
        elif r == 0xfe:
            v = int(struct.unpack(b'<I', ser_read(f, 4))[0])

            lower_bound = 0x10000
            if v < lower_bound:
                raise DeserializationValueBoundsError(
                    f"non-canonical 5-byte compact size for variable integer: "
                    f"0x{v:x} less than 0x{lower_bound:x}",
                    klass=cls, value=v, lower_bound=lower_bound,
                    upper_bound=0xFFFFFFFF)
        else:
            v = int(struct.unpack(b'<Q', ser_read(f, 8))[0])

            lower_bound = 0x100000000
            if v < lower_bound:
                raise DeserializationValueBoundsError(
                    f"non-canonical 9-byte compact size for variable integer: "
                    f"0x{v:x} less than 0x{lower_bound:x}",
                    klass=cls, value=v, lower_bound=lower_bound,
                    upper_bound=MAX_SIZE)

        if not allow_full_range and v > MAX_SIZE:
            # With MAX_SIZE being defined as less than 32-bit max value,
            # this means that any canonically encoded 64-bit value will be
            # more than MAX_SIZE. This also means that upper_bound supplied
            # to the exception may happen to be less than lower bound.
            raise DeserializationValueBoundsError(
                f"non-canonical compact size for variable integer: "
                f"0x{v:x} more than 0x{MAX_SIZE:x}",
                klass=cls, value=v, lower_bound=lower_bound,
                upper_bound=MAX_SIZE)

        return v


class BytesSerializer(Serializer[bytes]):
    """Serialization of bytes instances"""
    @classmethod
    def stream_serialize(cls, obj: bytes, f: ByteStream_Type,
                         **kwargs: Any) -> None:
        VarIntSerializer.stream_serialize(len(obj), f, **kwargs)
        f.write(obj)

    @classmethod
    def stream_deserialize(cls, f: ByteStream_Type, **kwargs: Any) -> bytes:
        datalen = VarIntSerializer.stream_deserialize(f, **kwargs)
        return ser_read(f, datalen)


class VectorSerializer(Serializer[Sequence[Serializable]]):
    """Base class for serializers of object vectors"""

    @classmethod
    def stream_serialize(cls, obj: Sequence[Serializable],
                         f: ByteStream_Type, **kwargs: Any) -> None:
        obj_seq = obj
        VarIntSerializer.stream_serialize(len(obj_seq), f, **kwargs)
        if not len(obj_seq):
            return
        inner_cls = type(obj_seq[0])
        for inst in obj_seq:
            cur_cls = type(inst)
            if cur_cls is not inner_cls:
                imm_cls = getattr(cur_cls, '_immutable_cls', None)
                if imm_cls and imm_cls is getattr(inner_cls,
                                                  '_immutable_cls', None):
                    # The special-case of mutable/immutable classes is
                    # allowed. Twin classes are OK if they only differ
                    # by their mutability.
                    #
                    # Note that this bypass uses bitcointx-specific convention
                    # of _immutable_cls attribute, and this serialization
                    # method can be called with non-bitcointx objects.
                    # But this is OK because this is only a relaxation of
                    # the check in a very specific circumstance,
                    # and the meaning of the check is only 'extra precaution'.
                    # Additional ergonomics justify this bypass, while
                    # supermajority of erroneous cases are still restricted
                    pass
                else:
                    raise ValueError(
                        f'supplied objects are of different types, '
                        f'first object is of type {inner_cls.__name__}, '
                        f'but there is also an object '
                        f'of type {cur_cls.__name__}')

            inner_cls.stream_serialize(inst, f, **kwargs)

    @classmethod
    def stream_deserialize(
        cls, f: ByteStream_Type,
        element_class: Optional[Type[T_Serializable]] = None,
        **kwargs: Any
    ) -> Sequence[T_Serializable]:
        if element_class is None:
            raise ValueError(
                "The class of the elements in the vector must be supplied")
        n = VarIntSerializer.stream_deserialize(f, **kwargs)
        r = []
        for i in range(n):
            r.append(element_class.stream_deserialize(f, **kwargs))
        return r


class uint256VectorSerializer(Serializer[Sequence[bytes]]):
    """Serialize vectors of uint256"""
    @classmethod
    def stream_serialize(cls, obj: Sequence[bytes], f: ByteStream_Type,
                         **kwargs: Any) -> None:
        uints = obj
        VarIntSerializer.stream_serialize(len(uints), f, **kwargs)
        for uint in uints:
            if len(uint) != 32:
                raise ValueError('elements must be 32 bytes in length each')
            f.write(uint)

    @classmethod
    def stream_deserialize(cls, f: ByteStream_Type, **kwargs: Any
                           ) -> List[bytes]:
        n = VarIntSerializer.stream_deserialize(f, **kwargs)
        r = []
        for i in range(n):
            r.append(ser_read(f, 32))
        return r


class intVectorSerializer(Serializer[Sequence[int]]):

    @classmethod
    def stream_serialize(cls, obj: Sequence[int], f: ByteStream_Type,
                         **kwargs: Any) -> None:
        ints = obj
        datalen = len(ints)
        VarIntSerializer.stream_serialize(datalen, f, **kwargs)
        for i in ints:
            f.write(struct.pack(b"<i", i))

    @classmethod
    def stream_deserialize(cls, f: ByteStream_Type, **kwargs: Any) -> List[int]:
        datalen = VarIntSerializer.stream_deserialize(f, **kwargs)
        ints = []
        for i in range(datalen):
            ints.append(struct.unpack(b"<i", ser_read(f, 4))[0])
        return ints


def uint256_from_bytes(s: bytes) -> int:
    """Convert bytes to uint256"""
    r = 0
    t = struct.unpack(b"<IIIIIIII", s[:32])
    for i in range(8):
        r += t[i] << (i * 32)
    return r


def uint256_to_bytes(u: int) -> bytes:
    r = b""
    for i in range(8):
        r += struct.pack('<I', u >> (i * 32) & 0xffffffff)
    return r


def uint256_to_shortstr(u: int) -> str:
    s = "%064x" % (u,)
    return s[:16]


def make_mutable(cls: Type[T_ImmutableSerializable]
                 ) -> Type[T_ImmutableSerializable]:
    if not issubclass(cls, ImmutableSerializable):
        raise TypeError("make_mutable can only be applied to subclasses "
                        "of ImmutableSerializable")
    # For speed we use a class decorator that removes the immutable
    # restrictions directly. In addition the modified behavior of GetHash() and
    # hash() is undone.
    cls.__setattr__ = object.__setattr__  # type: ignore
    cls.__delattr__ = object.__delattr__  # type: ignore
    cls.GetHash = Serializable.GetHash    # type: ignore
    cls.__hash__ = Serializable.__hash__  # type: ignore
    return cls


__all__ = (
    'MAX_SIZE',
    'Hash',
    'Hash160',
    'SerializationError',
    'SerializationTruncationError',
    'DeserializationExtraDataError',
    'DeserializationValueBoundsError',
    'ser_read',
    'Serializable',
    'ImmutableSerializable',
    'Serializer',
    'VarIntSerializer',
    'BytesSerializer',
    'VectorSerializer',
    'uint256VectorSerializer',
    'intVectorSerializer',
    'uint256_from_bytes',
    'uint256_to_bytes',
    'uint256_to_shortstr',
    'make_mutable',
)
