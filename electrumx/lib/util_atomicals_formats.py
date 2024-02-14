# Copyright (c) 2023, The Atomicals Developers
# Copyright (c) 2016-2017, Neil Booth
#
# All rights reserved.
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
# and warranty status of this software.

'''Miscellaneous atomicals utility classes and functions.'''

from array import array
from electrumx.lib.script import OpCodes, ScriptError, Script, is_unspendable_legacy, is_unspendable_genesis, SCRIPTHASH_LEN
from electrumx.lib.util import pack_le_uint64, unpack_le_uint16_from, unpack_le_uint64, unpack_le_uint32, unpack_le_uint32_from, pack_le_uint16, pack_le_uint32
from electrumx.lib.hash import hash_to_hex_str, hex_str_to_hash, double_sha256, HASHX_LEN
import re
import os
import sys
import base64
import krock32
import pickle
import math
from electrumx.lib.hash import sha256, double_sha256
from cbor2 import dumps, loads, CBORDecodeError
from collections.abc import Mapping
from functools import reduce
from merkletools import MerkleTools

 
# Check whether the value is a 36 byte sequence
def is_atomical_id_long_form_bytes(value):
    if not isinstance(value, bytes):
        return False 
    try:
        if len(value) == 36:
            return True
    except (ValueError, TypeError):
        pass
    return False

# Check whether the value is a compact form location/atomical id 
def is_compact_atomical_id(value):
    '''Whether this is a compact atomical id or not
    '''
    if isinstance(value, int):
        return False
    if value == None or value == "":
        return False
    index_of_i = value.find("i")
    if index_of_i != 64: 
        return False
    raw_hash = hex_str_to_hash(value[ : 64])
    if len(raw_hash) == 32:
        return True
    return False

# Convert the compact string form to the expanded 36 byte sequence
def compact_to_location_id_bytes(value):
    '''Convert the 36 byte atomical_id to the compact form with the "i" at the end
    '''
    if not value:
        raise TypeError(f'value in compact_to_location_id_bytes is not set')

    index_of_i = value.index("i")
    if index_of_i != 64: 
        raise TypeError(f'{value} should be 32 bytes hex followed by i<number>')
    
    raw_hash = hex_str_to_hash(value[ : 64])
    
    if len(raw_hash) != 32:
        raise TypeError(f'{value} should be 32 bytes hex followed by i<number>')

    num = int(value[ 65: ])

    if num < 0 or num > 100000:
        raise TypeError(f'{value} index output number was parsed to be less than 0 or greater than 100000')

    return raw_hash + pack_le_uint32(num)
 
# Convert 36 byte sequence to compact form string
def location_id_bytes_to_compact(location_id):
    digit, = unpack_le_uint32_from(location_id[32:])
    return f'{hash_to_hex_str(location_id[:32])}i{digit}'
 
# Get the tx hash from the location/atomical id
def get_tx_hash_index_from_location_id(location_id): 
    output_index, = unpack_le_uint32_from(location_id[ 32 : 36])
    return location_id[ : 32], output_index 
 