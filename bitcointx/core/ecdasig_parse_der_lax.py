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
#
# This code is ported from Bitcoin Core, and it was ported to there from
# libsecp256k1 library
# Original C code was Copyright (c) 2015 Pieter Wuille
# Original C code was licensed under MIT software license.

# This function is ported from the libsecp256k1 distribution and implements
# DER parsing for ECDSA signatures, while supporting an arbitrary subset of
# format violations.
#
# Supported violations include negative integers, excessive padding, garbage
# at the end, and overly long length descriptors. This is safe to use in
# Bitcoin because since the activation of BIP66, signatures are verified to be
# strict DER before being passed to this module, and we know it supports all
# violations present in the blockchain before that point.

import ctypes

from typing import Optional

from bitcointx.core.secp256k1 import (
    get_secp256k1, COMPACT_SIGNATURE_SIZE
)


def ecdsa_signature_parse_der_lax(laxinput: bytes) -> Optional[bytes]:  # noqa
    rpos: int
    rlen: int
    spos: int
    slen: int
    pos: int = 0
    lenbyte: int
    tmpsig = bytearray([0 for _ in range(64)])
    overflow: int = 0

    inputlen = len(laxinput)

    sig = ctypes.create_string_buffer(COMPACT_SIGNATURE_SIZE)

    secp256k1 = get_secp256k1()

    # Hack to initialize sig with a correctly-parsed but invalid signature. */
    secp256k1.lib.secp256k1_ecdsa_signature_parse_compact(
        secp256k1.ctx.verify, sig, bytes(tmpsig))

    # Sequence tag byte
    if pos == inputlen or laxinput[pos] != 0x30:
        return None

    pos += 1

    # Sequence length bytes
    if pos == inputlen:
        return None

    lenbyte = laxinput[pos]
    pos += 1

    if lenbyte & 0x80:
        lenbyte -= 0x80
        if lenbyte > inputlen - pos:
            return None

        pos += lenbyte

    # Integer tag byte for R
    if pos == inputlen or laxinput[pos] != 0x02:
        return None

    pos += 1

    # Integer length for R
    if pos == inputlen:
        return None

    lenbyte = laxinput[pos]
    pos += 1

    if lenbyte & 0x80:
        lenbyte -= 0x80
        if lenbyte > inputlen - pos:
            return None

        while lenbyte > 0 and laxinput[pos] == 0:
            pos += 1
            lenbyte -= 1

        if lenbyte >= 4:
            return None

        rlen = 0
        while lenbyte > 0:
            rlen = (rlen << 8) + laxinput[pos]
            pos += 1
            lenbyte -= 1

    else:
        rlen = lenbyte

    if rlen > inputlen - pos:
        return None

    rpos = pos
    pos += rlen

    # Integer tag byte for S
    if pos == inputlen or laxinput[pos] != 0x02:
        return None

    pos += 1

    # Integer length for S
    if pos == inputlen:
        return None

    lenbyte = laxinput[pos]
    pos += 1

    if lenbyte & 0x80:
        lenbyte -= 0x80
        if lenbyte > inputlen - pos:
            return None

        while lenbyte > 0 and laxinput[pos] == 0:
            pos += 1
            lenbyte -= 1

        if lenbyte >= 4:
            return None

        slen = 0
        while lenbyte > 0:
            slen = (slen << 8) + laxinput[pos]
            pos += 1
            lenbyte -= 1

    else:
        slen = lenbyte

    if slen > inputlen - pos:
        return None

    spos = pos

    # Ignore leading zeroes in R
    while rlen > 0 and laxinput[rpos] == 0:
        rlen -= 1
        rpos += 1

    # Copy R value
    if rlen > 32:
        overflow = 1
    else:
        tmpsig[32-rlen:32] = laxinput[rpos:rpos+rlen]

    # Ignore leading zeroes in S
    while slen > 0 and laxinput[spos] == 0:
        slen -= 1
        spos += 1

    # Copy S value
    if slen > 32:
        overflow = 1
    else:
        tmpsig[64-slen:64] = laxinput[spos:spos+slen]

    if not overflow:
        parse_result = secp256k1.lib.secp256k1_ecdsa_signature_parse_compact(
            secp256k1.ctx.verify, sig, bytes(tmpsig))
        overflow = int(not parse_result)

    if overflow:
        # Overwrite the result again with a correctly-parsed but invalid
        # signature if parsing failed.
        tmpsig = bytearray([0 for _ in range(64)])
        secp256k1.lib.secp256k1_ecdsa_signature_parse_compact(
            secp256k1.ctx.verify, sig, bytes(tmpsig))

    return sig.raw
