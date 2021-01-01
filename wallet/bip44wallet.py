import binascii
import hashlib

from . import base58
from . import bip32
from . import bip39
from . import ecc
from . import utils

from .bip32 import InvalidKeyException

HD_PATH_BIP44 = "m/44'/0'/0'"

class Bip44Wallet:
    def __init__(self, mnemonic: str):
        wordlist = bip39.load_wordlist()
        try:
            expanded = bip39.expand(wordlist, mnemonic)
            if expanded != mnemonic:
                mnemonic = expanded
                print("INFO: mnemonic expanded")
        except:
            raise Exception("ERROR: not a valid BIP39 mnemonic")

        if not bip39.check(wordlist, mnemonic):
            raise Exception("ERROR: BIP39 checksum fail")
        seed = bip39.mnemonic_to_seed(mnemonic)
        
        self.mnemonic_fingerprint = hashlib.sha256(
                mnemonic.encode("utf-8")).digest()[:4].hex().upper()
        self.vbyte_pair = tuple(binascii.unhexlify(b) for b in bip32.x)
        
        path = bip32.parse_path(HD_PATH_BIP44)
        self.root_node = bip32.seed_to_root_key(seed, self.vbyte_pair)

        self.purpose_node = self.root_node.child(path[1])
        self.coin_node = self.purpose_node.child(path[2])
        self.account_node = self.coin_node.child(path[3])
        self.external_node = self.account_node.child(0)
        self.internal_node = self.account_node.child(1)

        self.account_xpriv = base58.b58encode_check(self.account_node.xpriv())
        self.account_xpub = base58.b58encode_check(self.account_node.xpub())

    def generate(self, start: int, end: int, external: bool):
        result = []
        for i in range(start, end):
            node = (self.external_node if external else self.internal_node).child(i)
            priv_int = node.key
            pub_int = ecc.priv_to_pub(priv_int)
            wif = base58.b58encode_check(b'\x80' + bip32.ser256(priv_int) + b'\x01').decode()
            address = utils.pub_to_addr(pub_int).decode()
            result.append((i, address, wif))
        return result

    def xpriv(self):
        return self.account_xpriv.decode()
    
    def xpub(self):
        return self.account_xpub.decode()


