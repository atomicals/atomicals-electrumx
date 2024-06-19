import sha3

from electrumx.lib.hash import (
  sha512_256,
  sha512_224,
  sha512
)
 
from electrumx.lib.eaglesong import (
    EaglesongHash
)

def calc_sha512(bytes_to_hash):
    return sha512(bytes_to_hash)

def calc_sha512_256(bytes_to_hash):
    return sha512_256(bytes_to_hash)

def calc_sha512_224(bytes_to_hash):
    return sha512_224(bytes_to_hash)

def calc_sha3_256(bytes_to_hash):
    return sha3.sha3_256(bytes_to_hash).digest()

def calc_eaglesong(bytes_to_hash):
    return bytearray(EaglesongHash(bytes_to_hash))
 