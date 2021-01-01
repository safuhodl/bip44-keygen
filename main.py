#!/usr/bin/env python3

import sys

from wallet.bip44wallet import Bip44Wallet


def main():
    # reads a BIP39 mnemonic from stdin and generates a BIP44 wallet
    print("Enter a BIP39 mnemonic:")

    mnemonic = sys.stdin.readline().strip()
    wallet_ = Bip44Wallet(mnemonic)

    print("Mnemonic fingerprint: {}\n".format(wallet_.mnemonic_fingerprint))
    print(wallet_.account_xpub.decode())
    print(wallet_.account_xpriv.decode())
    print()

    entries = wallet_.generate(0, 20, True)
    for (i, address, wif) in entries:
        print("{}\t{}\t{}".format(i, address, wif))


if __name__ == "__main__":
    main()
