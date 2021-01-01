import binascii
import hashlib
import sys

from typing import List

DERIVATION_ALGO = "sha512"
DERIVATION_ITER = 2048
DERIVATION_DKLEN = 32

def load_wordlist() -> List[str]:
    with open("wordlist/english.txt") as f:
        return [word.rstrip() for word in f.readlines()]

def mnemonic_to_seed(mnemonic: str, passphrase: str="") -> bytes:
    bin_seed = hashlib.pbkdf2_hmac("sha512", mnemonic.encode("utf-8"), ("mnemonic" + passphrase).encode("utf-8"), 2048)
    return bin_seed

def expand(wordlist: List[str], mnemonic: str) -> str:
    wordmap = { word[:4]: word for word in wordlist }
    return " ".join([wordmap[w[:4]] for w in mnemonic.split()])

def check(wordlist: List[str], mnemonic: str) -> bool:
    mnemonic_list = mnemonic.split(" ")
    # list of valid mnemonic lengths
    if len(mnemonic_list) not in [12, 15, 18, 21, 24]:
        return False
    try:
        idx = map(
            lambda x: bin(wordlist.index(x))[2:].zfill(11), mnemonic_list
        )
        b = "".join(idx)
    except ValueError:
        return False
    l = len(b)  # noqa: E741
    d = b[: l // 33 * 32]
    h = b[-l // 33 :]
    nd = int(d, 2).to_bytes(l // 33 * 4, byteorder="big")
    nh = bin(int(hashlib.sha256(nd).hexdigest(), 16))[2:].zfill(256)[: l // 33]
    return h == nh

