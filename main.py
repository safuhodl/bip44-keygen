#!/usr/bin/env python3

import sys

from wallet.bip44wallet import Bip44Wallet


def main():
    # reads a BIP39 mnemonic from stdin and generates a BIP44 wallet
    print("Enter a BIP39 mnemonic:")
    mnemonic = sys.stdin.readline().strip()

    print("Enter x for legacy or z for segwit:")
    wallet_type= sys.stdin.readline().strip()
    segwit = False
    if wallet_type == "x":
        segwit = False
    elif wallet_type == "z":
        segwit = True
    else:
        print("Invalid wallet type")
        return
    
    wallet_ = Bip44Wallet(mnemonic, segwit)

    print("Mnemonic fingerprint:\t{}".format(wallet_.mnemonic_fingerprint))
    print("Master fingerprint:\t{}\n".format(wallet_.root_node.fingerprint.hex().upper()))
    print(wallet_.account_xpub.decode())
    print(wallet_.account_xpriv.decode())
    print()

    entries = wallet_.generate(0, 20, True)
    for (i, address, wif) in entries:
        print("{}\t{}\t{}".format(i, address, wif))


if __name__ == "__main__":
    main()
