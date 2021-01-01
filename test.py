from wallet import bip44wallet

# test vectors
mnemonic = "fat juice calm early dynamic swim timber winter camp dwarf town better vehicle legal mobile drastic hour baby wheel regular express raccoon output empower"

expected_external_addresses = """\
1Hn5ATnB11XEMw4WA8uiLWPYqmdr9MYQzA L1sa9pbr4YkgZq312stqLbx8HCMb97bKY6Rgm58xbWaKL4tzCGgR
1HGv6MvsLmeCMzZ7Qg7jnZqirtnd3hrBBu L48hoPPCn5t1viFnwCMYCBmiEx9SsRbnSps6HQpihvp15xniz9C3
15NxHz8L6834w7wvvgxN8ha4kJHbj2nRVm L3c98mrXWcJ212ekfR8D3JXBHbW2G6UYpqEgYkogUoRULJwrmohE
1GJfgtHQiBNQCfLdPtbnemE2eVpscyut7V L4MzSqC3f4u1MCjH5RXcEUTg9F6Xd6BMhZBiNMDwa2D8XnxtapNK
1Mh8RvZtsMjeqWzWkHPKvCGNyFX36BEj8W L3o4RaEkKBbi3JKGxE8dpep3y84yinPgQtW32WPmzsG2vKHHXh6P
1D2nrRcTqsK7EkYioKNw2E1gjSJm8H514 L1544821A87odhCw16HvMy4jqdffJ5XHFjEKX62qgKnY9SSB8N6d
12YrWk6LxgaFBDh94Bys1BwfpKLuxugEE9 KynnGHBdy1Rr2H3dF25UJf6hp9qMfTuUswUXsXhGT1EVbhzKp9ju
1PjztXEJDVqGu7jzBMgqdeo6zYZQvguH6z Kxz3GPFNbNBe4RKTeCXjEegyPJGN4au9nPE6Qsoa56iVdtUqmAAb
1fFM33pgnbN6SACXCGzanS8BMUp2Rdktr L3LmbFHQFn4wxL3WdHgnJXkG7MMLHS23WVG2RuQWbxWcmbPWFbDH
1NHy45o89hSB5Ccj98MetM1zy43TXj4biS L3MrQhn9e1HSUikfvjuRfWHmL8oJkvYyG7o7cpZzH3guCYJ8rtNb
"""

expected_change_addresses = """\
14m98tEQNHuExk7YUtRTfh2sWmGU8Tzb6s L3t2WHeU52cj4cLpCfdev8DiDucizVELD6cX3Mb3y2tLh6cj4Vjt
1AbFLdt52yhD8mQ3FyP5mTV8EQLyS5RucX L1NwgeAXRACoWkzuL3hDUu6bDeMp62DvTeKcBzaxQUaoxv7SM5GH
1HSiCPVD9LMZaEBr3pAH491ZZviT1Za3Ad KyddNqRh4jqyWQpQmV6TH7qm679yip4YyZvmBGCUUPFyzzfa8haq
1PoYp3abx9XSbTokqPxjnhDnUNU4fdqmpv Kx9Xx1tZmJrfKikiJX4His1MgJBwtLz7vYGrAFZmqdKjs6YJFz3y
19icqZjZSno8PK8GZqAGXGvsbQ26QePWdR KzMXyGTJMeBpH2dC1HmhdWAhxEjbFuHFJDpHq1Rv95PZ3zPs6E86
16xVjEhfHXtkYLWyvjns3TcmssydkdrkLt L33zNiKm5NSVpVmQa2uTaE5MMCS18ckXcqA3b3ix44BUbEoFBPAx
1BZFcTtVJRMfUuhvmsKzfkXuVToUoDPBCD L3Q9ens2YCsahcrnKZwPJunefHBbkr4Goz8Xb6AEXiNEoKQ3G1ph
1JaDgNeSgGZN9YCWL5bw38UMSn3KjCakZw L1eRBMny3Q7gKwcCxjtFHcvmxY9V4Fd5CAWeQiELE6vx8vzokso1
199rds9SzSm2NNrksubJii9bm169WS6CfD L4rUDxqeF97eGK9C9HUiadXC5Bgoy22U1hzy8GbxhNHrYATcCBAm
1DE8gLFf7GGKWXw7N7VeptZy7xuoLQphVf L5WSME3jN6XuJRGTZMWGm2LtBPibri2vPmWY8iNComYtNY3v47Hn
"""

expected_root_xpriv = "xprv9s21ZrQH143K2dmRJxRAKNBdywxnz4epAmQ26Fs92vzzHqSFB5ePRhFY9Rg2hpL2ieyCdUd8BDywm7A7psx2uZZwyDZjqLwqcZ6oXqcpRnP"
expected_acc_xpub = "xpub6CoXZ5MT9hcuD9VMgbVeoSYFVAmaMua4MmcAFcskorEYVUsEP5eKmYMKaSJaV8gfE4omAj8V6DARSi7DbBM4RfVAQXKoqgDvcxFm8ZhgkMT"
expected_acc_xpriv = "xprv9ypB9ZpZKL4bzfQtaZxeSJbWw8w5xSrCzYgZTEU9FWhZcgY5qYL5Dk2qjBwbQiZav3Y2hXSPhd1gj4zginkqhiedEBznAMpW2xnyrVpmmQD"

# setup
wallet = bip44wallet.Bip44Wallet(mnemonic)
ext_addresses = wallet.generate(0, 10, True)
int_addresses = wallet.generate(0, 10, False)

# assertions

# external
for i, line in enumerate(expected_external_addresses.splitlines()):
    _, act_address, act_wif = ext_addresses[i]
    exp_address, exp_wif = line.split()
    assert act_address == exp_address
    assert act_wif == exp_wif

# change (internal)
for i, line in enumerate(expected_change_addresses.splitlines()):
    _, act_address, act_wif = int_addresses[i]
    exp_address, exp_wif = line.split()
    assert act_address == exp_address
    assert act_wif == exp_wif

# extended account keys
assert expected_acc_xpriv == wallet.xpriv()
assert expected_acc_xpub == wallet.xpub()

# test mnemonic expansion
from wallet import bip39
wordlist = bip39.load_wordlist()

# test vector 1
short_mnemonic = "pric flus asth symb craz dirt fram net medi reti ladd aero huma cano toke"
expanded_mnemonic = "price flush asthma symbol crazy dirt frame net media retire ladder aerobic human canoe token"
assert bip39.expand(wordlist, short_mnemonic) == expanded_mnemonic

# test vector 2
short_mnemonic = "cup craft casin staf incr try neck green civil beach vital paddle"
expanded_mnemonic = "cup craft casino staff increase try neck green civil beach vital paddle"
assert bip39.expand(wordlist, short_mnemonic) == expanded_mnemonic

