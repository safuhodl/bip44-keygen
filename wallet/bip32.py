import binascii
import hashlib
import hmac
from typing import List, Tuple

from . import ecc
from . import utils

# Registered HD version bytes (SLIP-0132)
x = ("0488b21e", "0488ade4")
y = ("049d7cb2", "049d7878")
z = ("04b24746", "04b2430c")
Y = ("0295b43f", "0295b005")
Z = ("02aa7ed3", "02aa7a99")

class InvalidKeyException(Exception):
    pass

def ser32(i: int) -> bytes:
    return int.to_bytes(i, length=4, byteorder="big")

def ser256(i: int) -> bytes:
    return int.to_bytes(i, length=32, byteorder="big")

def parse256(b: bytes) -> int:
    return int.from_bytes(b, byteorder="big")

def parse_path(path: str) -> List[int]:
    def error():
        raise Exception("invalid BIP32 derivation path")
    H = 2**31
    segments = path.split("/")
    if segments[0] != "m":
        error()
    result = [0]
    for s in segments[1:]:
        if len(s) == 0:
            error()
        if hardened := (s[-1] == "'"):
            s = s[:-1]
        i = int(s)
        if i >= H:
            error()
        result.append(i + (H if hardened else 0))
    return result

def CKDpriv(k_par: int , c_par: bytes, i: int) -> (int, bytes, bytes, bool):
    if i >= 2**31:
        # hardened
        data = b'\x00' + ser256(k_par) + ser32(i)
    else:
        # normal
        data = ecc.compress_pub(ecc.priv_to_pub(k_par)) + ser32(i)
        
    digest = hmac.digest(key=c_par, msg=data, digest=hashlib.sha512)
    left, right = digest[:32], digest[32:]
    l_parsed = parse256(left)
    k_i = ecc.add_priv(l_parsed, k_par)
    chain_code = right
    fingerprint = utils.hash160(ecc.compress_pub(ecc.priv_to_pub(k_i)))[:4]
    is_valid = not(l_parsed >= ecc.N or k_i == 0)
    return k_i, chain_code, fingerprint, is_valid


def seed_to_root_key(seed, vbyte_pair: Tuple[bytes, bytes]):
    if type(seed) != bytes:
        raise Exception("seed should be bytes")
    if type(vbyte_pair) != tuple and (vbyte_pair[0] != bytes or vbyte_pair[1] != bytes):
        raise Exception("vbytes should be a pair of bytes")

    digest = hmac.digest(key=b"Bitcoin seed", msg=seed, digest=hashlib.sha512)
    key_bytes, chain_code = digest[:32], digest[32:]
    key_int = parse256(key_bytes)
    fingerprint = utils.hash160(ecc.compress_pub(ecc.priv_to_pub(key_int)))[:4]
    
    if key_int == 0 or key_int >= ecc.N:
        raise Exception("Invalid master key (invalid exponent)")

    return Node(
            vbyte_pair,
            0, # depth
            fingerprint,
            b'\x00\x00\x00\x00', # parent fingerprint
            0, # child index
            chain_code,
            key_int)

class Node:
    def __init__(self, vbyte_pair, depth, fingerprint,
            parent_fingerprint, child_number, 
            chain_code, key):
        self.vbyte_pair = vbyte_pair
        self.depth = depth
        self.fingerprint = fingerprint
        self.parent_fingerprint = parent_fingerprint
        self.child_number = child_number
        self.chain_code = chain_code
        self.key = key

    def child(self, child_index):
        key_int, chain_code, fingerprint, is_valid = CKDpriv(self.key, self.chain_code, child_index)
        if not is_valid:
            raise InvalidKeyException()
        return Node(
                self.vbyte_pair,
                self.depth + 1,
                fingerprint,
                self.fingerprint,
                child_index,
                chain_code,
                key_int)

    def xpub(self):
        data = self.vbyte_pair[0]
        data += int.to_bytes(self.depth, length=1, byteorder="big")
        data += self.parent_fingerprint
        data += ser32(self.child_number)
        data += self.chain_code
        data += ecc.compress_pub(ecc.priv_to_pub(self.key))
        return data

    def xpriv(self):
        data = self.vbyte_pair[1]
        data += int.to_bytes(self.depth, length=1, byteorder="big")
        data += self.parent_fingerprint
        data += ser32(self.child_number)
        data += self.chain_code
        data += (b'\x00' + ser256(self.key))
        return data

