import hashlib

from . import base58
from . import ecc


def read_varint(data: bytes) -> (int, int):
    first = data[0]
    bo = 'little'
    if first <= b'\xFC':
        return 1, int.from_bytes(first, bo)
    elif first == b'\xFD':
        return 3, int.from_bytes(data[1:3], bo)
    elif first == b'\xFE':
        return 5, int.from_bytes(data[1:5], bo)
    elif first == b'\xFF':
        return 9, int.from_bytes(data[1:9], bo)
    raise ValueError('not a VarInt')


def hash160(data: bytes) -> bytes:
    return hashlib.new('ripemd160', hashlib.sha256(data).digest()).digest()


def pub_to_addr(pub):
    compressed_pub = ecc.compress_pub(pub)
    h160 = hash160(compressed_pub)
    address = base58.b58encode_check(b'\x00' + h160)
    return address
