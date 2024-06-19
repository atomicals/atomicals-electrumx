# Copyright (C) 2013-2015 The python-bitcoinlib developers
#
# This file is part of python-bitcointx.
#
# It is subject to the license terms in the LICENSE-PYTHON-BITCOINTX file found in the top-level
# directory of this distribution.
#
# No part of python-bitcointx, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

from typing import TypeVar, Type, Union, Any

from bitcointx.core.key import CPubKey, CKeyBase
from bitcointx.core.serialize import ImmutableSerializable, ByteStream_Type
from bitcointx.wallet import P2PKHCoinAddress
import bitcointx
import base64

# pylama:ignore=E501


def VerifyMessage(address: P2PKHCoinAddress, message: 'BitcoinMessage',
                  sig: Union[str, bytes],
                  validate_base64: bool = True
                  ) -> bool:

    if isinstance(sig, bytes):
        sig_b64 = sig.decode('ascii')
    else:
        sig_b64 = sig

    sig_bytes = base64.b64decode(sig_b64, validate=validate_base64)
    hash = message.GetHash()

    pubkey = CPubKey.recover_compact(hash, sig_bytes)

    if pubkey is None:
        return False

    return str(P2PKHCoinAddress.from_pubkey(pubkey)) == str(address)


def SignMessage(key: CKeyBase, message: 'BitcoinMessage') -> bytes:
    sig, i = key.sign_compact(message.GetHash())

    meta = 27 + i
    if key.is_compressed():
        meta += 4

    return base64.b64encode(bytes([meta]) + sig)


T_BitcoinMessage = TypeVar('T_BitcoinMessage', bound='BitcoinMessage')


class BitcoinMessage(ImmutableSerializable):
    __slots__ = ['magic', 'message']

    message: bytes
    magic: bytes

    def __init__(self, message: Union[str, bytes] = "",
                 magic: Union[str, bytes] = "Bitcoin Signed Message:\n"
                 ) -> None:
        if isinstance(message, str):
            message_bytes = message.encode("utf-8")
        else:
            message_bytes = message

        if isinstance(magic, str):
            magic_bytes = magic.encode("utf-8")
        else:
            magic_bytes = magic

        object.__setattr__(self, 'message', message_bytes)
        object.__setattr__(self, 'magic', magic_bytes)

    @classmethod
    def stream_deserialize(cls: Type[T_BitcoinMessage],
                           f: ByteStream_Type,
                           **kwargs: Any) -> T_BitcoinMessage:
        magic = bitcointx.core.serialize.BytesSerializer.stream_deserialize(
            f, **kwargs)
        message = bitcointx.core.serialize.BytesSerializer.stream_deserialize(
            f, **kwargs)
        return cls(message, magic)

    def stream_serialize(self, f: ByteStream_Type, **kwargs: Any) -> None:
        bitcointx.core.serialize.BytesSerializer.stream_serialize(
            self.magic, f, **kwargs)
        bitcointx.core.serialize.BytesSerializer.stream_serialize(
            self.message, f, **kwargs)

    def __str__(self) -> str:
        return self.message.decode('utf-8')

    def __repr__(self) -> str:
        try:
            return (f'BitcoinMessage({self.magic.decode("utf-8")}, '
                    f'{self.message.decode("utf-8")})')
        except UnicodeDecodeError:
            return f'BitcoinMessage({self.magic!r}, {self.message!r})'
