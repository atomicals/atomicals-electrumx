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

# pylama:ignore=E501,E221

# NOTE: for simplicity, when we need to pass an array of structs to secp256k1
# function, we will build an array of bytes out of elements, and then pass
# this array. we are dealing with 32 or 64-byte aligned data,
# so this should be safe.

# NOTE: special care should be taken with functions that may write to parts
# of their arguments, like secp256k1_pedersen_blind_generator_blind_sum,
# which will overwrite the element pointed to by blinding_factor.
# python's byte instance is supposed to be immutable, and for mutable byte
# buffers you should use ctypes.create_string_buffer().

import os
import ctypes
import ctypes.util
from types import FunctionType
from typing import Dict, Union, Any, Optional, cast
from dataclasses import dataclass

import bitcointx.util


PUBLIC_KEY_SIZE             = 65
COMPRESSED_PUBLIC_KEY_SIZE  = 33
SIGNATURE_SIZE              = 72
COMPACT_SIGNATURE_SIZE      = 65


class Libsecp256k1Exception(EnvironmentError):
    pass


SECP256K1_FLAGS_TYPE_CONTEXT = (1 << 0)
SECP256K1_FLAGS_BIT_CONTEXT_SIGN = (1 << 9)
SECP256K1_FLAGS_BIT_CONTEXT_VERIFY = (1 << 8)

SECP256K1_CONTEXT_SIGN = \
    (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_SIGN)
SECP256K1_CONTEXT_VERIFY = \
    (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_VERIFY)

SECP256K1_FLAGS_TYPE_COMPRESSION = (1 << 1)
SECP256K1_FLAGS_BIT_COMPRESSION = (1 << 8)

SECP256K1_EC_COMPRESSED = (SECP256K1_FLAGS_TYPE_COMPRESSION | SECP256K1_FLAGS_BIT_COMPRESSION)
SECP256K1_EC_UNCOMPRESSED = (SECP256K1_FLAGS_TYPE_COMPRESSION)


class Secp256k1LastErrorContextVar(bitcointx.util.ContextVarsCompat):
    last_error: Optional[Dict[str, Union[int, str]]]


_secp256k1_error_storage = Secp256k1LastErrorContextVar(last_error=None)

_ctypes_functype = getattr(ctypes, 'WINFUNCTYPE', getattr(ctypes, 'CFUNCTYPE'))


class secp256k1_context_type:
    """dummy type for typecheck purposes"""


@_ctypes_functype(ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p)
def _secp256k1_illegal_callback_fn(error_str, _data):  # type: ignore
    _secp256k1_error_storage.last_error = {'code': -2, 'type': 'illegal_argument', 'message': str(error_str)}


def secp256k1_get_last_error() -> Dict[str, Union[int, str]]:
    return cast(Dict[str, Union[int, str]],
                getattr(_secp256k1_error_storage, 'last_error', None))


def _check_ressecp256k1_void_p(val: int, _func: FunctionType,
                               _args: Any) -> ctypes.c_void_p:
    if val == 0:
        err = getattr(_secp256k1_error_storage, 'last_error', None)
        if err is None:
            raise Libsecp256k1Exception(
                -3, ('error handling callback function was not called, '
                     'error is not known'))
        raise Libsecp256k1Exception(err['code'], err['message'])
    return ctypes.c_void_p(val)


@dataclass(frozen=True)
class Secp256k1_Capabilities:
    has_pubkey_recovery: bool
    has_privkey_negate: bool
    has_pubkey_negate: bool
    has_ecdh: bool
    has_xonly_pubkeys: bool
    has_schnorrsig: bool


@dataclass(frozen=True)
class Secp256k1_Contexts:
    sign: secp256k1_context_type
    verify: secp256k1_context_type


@dataclass(frozen=True)
class Secp256k1:
    lib: ctypes.CDLL
    ctx: Secp256k1_Contexts
    cap: Secp256k1_Capabilities


_secp256k1: Optional[Secp256k1] = None


def get_secp256k1() -> Secp256k1:
    """Will create and initialize an instance of Secp256k1 class, and store
    it as attribute of the module this function resides in. If this attribute
    is already initialized, no new instance will be created, and an existing
    instance will be returned"""

    global _secp256k1

    if _secp256k1 is None:
        _secp256k1 = secp256k1_load_library(bitcointx.util._secp256k1_library_path)
        assert _secp256k1 is not None

    return _secp256k1


def _add_function_definitions(lib: ctypes.CDLL) -> Secp256k1_Capabilities:
    has_pubkey_recovery = False
    has_privkey_negate = False
    has_pubkey_negate = False
    has_ecdh = False
    has_xonly_pubkeys = False
    has_schnorrsig = False

    if getattr(lib, 'secp256k1_ecdsa_sign_recoverable', None):
        has_pubkey_recovery = True
        lib.secp256k1_ecdsa_sign_recoverable.restype = ctypes.c_int
        lib.secp256k1_ecdsa_sign_recoverable.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_void_p]

        lib.secp256k1_ecdsa_recoverable_signature_serialize_compact.restype = ctypes.c_int
        lib.secp256k1_ecdsa_recoverable_signature_serialize_compact.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int), ctypes.c_char_p]

        lib.secp256k1_ecdsa_signature_serialize_compact.restype = ctypes.c_int
        lib.secp256k1_ecdsa_signature_serialize_compact.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]

        lib.secp256k1_ecdsa_recover.restype = ctypes.c_int
        lib.secp256k1_ecdsa_recover.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]

        lib.secp256k1_ecdsa_recoverable_signature_parse_compact.restype = ctypes.c_int
        lib.secp256k1_ecdsa_recoverable_signature_parse_compact.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]

    lib.secp256k1_context_create.restype = ctypes.c_void_p
    lib.secp256k1_context_create.errcheck = _check_ressecp256k1_void_p  # type: ignore
    lib.secp256k1_context_create.argtypes = [ctypes.c_uint]

    lib.secp256k1_context_randomize.restype = ctypes.c_int
    lib.secp256k1_context_randomize.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

    lib.secp256k1_context_set_illegal_callback.restype = None
    lib.secp256k1_context_set_illegal_callback.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

    lib.secp256k1_ecdsa_sign.restype = ctypes.c_int
    lib.secp256k1_ecdsa_sign.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_void_p]

    lib.secp256k1_ecdsa_signature_serialize_der.restype = ctypes.c_int
    lib.secp256k1_ecdsa_signature_serialize_der.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t), ctypes.c_char_p]

    lib.secp256k1_ec_pubkey_create.restype = ctypes.c_int
    lib.secp256k1_ec_pubkey_create.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]

    lib.secp256k1_ec_seckey_verify.restype = ctypes.c_int
    lib.secp256k1_ec_seckey_verify.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

    lib.secp256k1_ecdsa_signature_parse_der.restype = ctypes.c_int
    lib.secp256k1_ecdsa_signature_parse_der.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]

    lib.secp256k1_ecdsa_signature_parse_compact.restype = ctypes.c_int
    lib.secp256k1_ecdsa_signature_parse_compact.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]

    lib.secp256k1_ecdsa_signature_normalize.restype = ctypes.c_int
    lib.secp256k1_ecdsa_signature_normalize.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]

    lib.secp256k1_ecdsa_verify.restype = ctypes.c_int
    lib.secp256k1_ecdsa_verify.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]

    lib.secp256k1_ec_pubkey_parse.restype = ctypes.c_int
    lib.secp256k1_ec_pubkey_parse.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t]

    lib.secp256k1_ec_pubkey_tweak_add.restype = ctypes.c_int
    lib.secp256k1_ec_pubkey_tweak_add.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]

    lib.secp256k1_ec_privkey_tweak_add.restype = ctypes.c_int
    lib.secp256k1_ec_privkey_tweak_add.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]

    lib.secp256k1_ec_pubkey_serialize.restype = ctypes.c_int
    lib.secp256k1_ec_pubkey_serialize.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t), ctypes.c_char_p, ctypes.c_uint]

    if getattr(lib, 'secp256k1_ec_pubkey_negate', None):
        has_pubkey_negate = True
        lib.secp256k1_ec_pubkey_negate.restype = ctypes.c_int
        lib.secp256k1_ec_pubkey_negate.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

    if getattr(lib, 'secp256k1_ec_privkey_negate', None):
        has_privkey_negate = True
        lib.secp256k1_ec_privkey_negate.restype = ctypes.c_int
        lib.secp256k1_ec_privkey_negate.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

    lib.secp256k1_ec_pubkey_combine.restype = ctypes.c_int
    lib.secp256k1_ec_pubkey_combine.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_char_p), ctypes.c_int]

    if getattr(lib, 'secp256k1_ecdh', None):
        has_ecdh = True
        lib.secp256k1_ecdh.restype = ctypes.c_int
        lib.secp256k1_ecdh.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_void_p]

    if getattr(lib, 'secp256k1_xonly_pubkey_parse', None):
        has_xonly_pubkeys = True
        lib.secp256k1_xonly_pubkey_parse.restype = ctypes.c_int
        lib.secp256k1_xonly_pubkey_parse.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
        lib.secp256k1_xonly_pubkey_tweak_add_check.restype = ctypes.c_int
        lib.secp256k1_xonly_pubkey_tweak_add_check.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p]
        lib.secp256k1_xonly_pubkey_tweak_add.restype = ctypes.c_int
        lib.secp256k1_xonly_pubkey_tweak_add.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
        lib.secp256k1_xonly_pubkey_from_pubkey.restype = ctypes.c_int
        lib.secp256k1_xonly_pubkey_from_pubkey.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int), ctypes.c_char_p]
        lib.secp256k1_xonly_pubkey_serialize.restype = ctypes.c_int
        lib.secp256k1_xonly_pubkey_serialize.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
        lib.secp256k1_keypair_create.restype = ctypes.c_int
        lib.secp256k1_keypair_create.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
        lib.secp256k1_keypair_xonly_pub.restype = ctypes.c_int
        lib.secp256k1_keypair_xonly_pub.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int), ctypes.c_char_p]
        lib.secp256k1_keypair_xonly_tweak_add.restype = ctypes.c_int
        lib.secp256k1_keypair_xonly_tweak_add.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]

    # Note that we check specifically for secp256k1_schnorrsig_sign_custom
    # to avoid incompatibility with earlier version of libsecp256k1.
    # Before secp256k1_schnorrsig_sign_custom was itroduced,
    # secp256k1_schnorrsig_sign had different signature, and using it
    # with this signature will result in segfault.
    if getattr(lib, 'secp256k1_schnorrsig_sign_custom', None):
        has_schnorrsig = True
        lib.secp256k1_schnorrsig_verify.restype = ctypes.c_int
        lib.secp256k1_schnorrsig_verify.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p]
        lib.secp256k1_schnorrsig_sign.restype = ctypes.c_int
        lib.secp256k1_schnorrsig_sign.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]

    return Secp256k1_Capabilities(
        has_pubkey_recovery=has_pubkey_recovery,
        has_privkey_negate=has_privkey_negate,
        has_pubkey_negate=has_pubkey_negate,
        has_ecdh=has_ecdh,
        has_xonly_pubkeys=has_xonly_pubkeys,
        has_schnorrsig=has_schnorrsig)


def secp256k1_create_and_init_context(lib: ctypes.CDLL, flags: int
                                      ) -> secp256k1_context_type:
    if flags not in (SECP256K1_CONTEXT_SIGN, SECP256K1_CONTEXT_VERIFY,
                     (SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY)):
        raise ValueError(
            'Value for flags is unexpected. '
            'Must be either SECP256K1_CONTEXT_SIGN, SECP256K1_CONTEXT_VERIFY, '
            'or a combination of these two')

    ctx = lib.secp256k1_context_create(flags)
    if ctx is None:
        raise RuntimeError('secp256k1_context_create() returned None')

    lib.secp256k1_context_set_illegal_callback(ctx, _secp256k1_illegal_callback_fn, 0)

    seed = os.urandom(32)
    # secp256k1 commit 6198375218b8132f016b701ef049fb295ca28c95 comment
    # says that "non-signing contexts may use randomization in the future"
    # so we always call randomize, but check for success only for
    # signing context, because older lib versions return 0 for non-signing ctx.
    res = lib.secp256k1_context_randomize(ctx, seed)
    if res != 1:
        assert res == 0
        if (flags & SECP256K1_CONTEXT_SIGN) == SECP256K1_CONTEXT_SIGN:
            raise RuntimeError("secp256k1 context randomization failed")
        elif flags != SECP256K1_CONTEXT_VERIFY:
            raise AssertionError('unexpected value for flags')

    return cast(secp256k1_context_type, ctx)


def secp256k1_load_library(path: Optional[str] = None) -> Secp256k1:
    """load libsecp256k1 via ctypes, add default function definitions
    to the library handle, create 'sign' and 'verify' contexts,
    and return Secp256k1 class that give access to the handle, contexts,
    and library capabilities.

    Callers of this function must assume responsibility for correct usage
    of the underlying C library.
    ctypes is a low-level foreign function interface, and using the underlying
    library though it should be done with the same care as if you would be
    programming in C directly.

    Note that default function definitions are only those that relevant
    to the code that uses them in python code within this library.
    You probably should to add your own definitions for the functions that
    you want to call directly, even if they are defined here by default.
    Although removing the default function definition should be considered
    mild API breakage and should be communicated via release notes.
    """

    if path is None:
        path = ctypes.util.find_library('secp256k1')
        if path is None:
            raise ImportError('secp256k1 library not found')

    try:
        handle = ctypes.cdll.LoadLibrary(path)
    except Exception as e:
        raise ImportError('Cannot load secp256k1 library: {}'.format(e))

    cap = _add_function_definitions(handle)
    ctx = Secp256k1_Contexts(
        sign=secp256k1_create_and_init_context(handle, SECP256K1_CONTEXT_SIGN),
        verify=secp256k1_create_and_init_context(handle, SECP256K1_CONTEXT_VERIFY))

    return Secp256k1(lib=handle, ctx=ctx, cap=cap)


__all__ = (
    'secp256k1_load_library',
    'SIGNATURE_SIZE',
    'COMPACT_SIGNATURE_SIZE',
    'PUBLIC_KEY_SIZE',
    'COMPRESSED_PUBLIC_KEY_SIZE',
    'SECP256K1_EC_COMPRESSED',
    'SECP256K1_EC_UNCOMPRESSED',
    'SECP256K1_CONTEXT_SIGN',
    'SECP256K1_CONTEXT_VERIFY',
    'get_secp256k1',
)
