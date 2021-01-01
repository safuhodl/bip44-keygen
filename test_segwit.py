from wallet import bip44wallet

# test vectors
mnemonic = "fat juice calm early dynamic swim timber winter camp dwarf town better vehicle legal mobile drastic hour baby wheel regular express raccoon output empower"

expected_external_addresses = """\
bc1qr8ul8epn27r5v5gu4thlth5ze04ha542xy9tg8 Ky9XrySZEisXPzqKyQhjjLyyUYTYMz9aWyCvrBBQhhCBiJRKaYjj
bc1qe4gkgqa9kq3me4gdq5hjlrckj8vefus4fx87sm L4W5nvTHu944LoqfYNw1W91kcCx9urC9JANQwRRYwj7EArwZkyHG
bc1q296hs6zfu48p8aeafgv27lu6pdveyjy97j9hw7 KxyscdwWryHXn44g4DcUjDVQco2fReGsrKMXCoXzgJdJ2qo95A56
bc1qzm3jrv8fcft7yw7jgygh4phwn2ddtfj7pjvtj5 L2WdKw1ivsTtt6iqmcSzmR5LauTRjY1AXfati8Xh6U1cS4QnQxCf
bc1qh0qntjw5nz0uqea8msj00c2e5nd9vvj0nc6kvl L2wWRhTs88qGgYLanQ5FwzazpBikgrSCYwDVEH36VNdiod3zULTR
bc1q8yc0ek6cpsuxd7u3ta9uyw283rcwh0z3fes66z L1EVDggiTrrZj1e8xspyE3dRJVVdfJf4P7kRoEf2khowYZbnh5ux
bc1q7zu66nz8kcddvgjy5wx2lfpetd82sdgdll8cu4 KxrX1AJjUbDDZeT9JBiWsDHBDQFVZ85AKFWCdemcggqMn6UNVY8P
bc1q9jw57ktjy7fcrze7g6gksvl6km5csgn7rqemwm Kzu6GNJbA3nEHffs6WiutpvZa6hQmn51wmMRuUbao8drEeZ8X1rT
bc1qgtl62vvjnzq7ev85xnsw5h8ug845ayayvdt349 L4dNsX62zxoDLTVnVZzcEKjJg1K3VcaNcpSJL9EpAZnKjTiaDVGt
bc1qzfuxvdkj2tsnjcepvnasu04efuzaj966azacsm L5PJr2gEegFnx4HHc2JGQNkz7aW9y8FxwjFfmwe2oL99RYB9bpj7
"""

expected_change_addresses = """\
bc1q4vv33a840c7j037y40g4w5fvrasjt2r96l0pae L4scTFrvKW8cpJQaFKz3WfHvb4k7cXN8BiyoNbtUsGeV97Y8o7bM
bc1qjdpdx8rqx9eda9glrhkcfrxaf59kfhm43lk46d Kzvya668Q8B7oYzMGisdFgrmGT1x1ao2Cng6b3Yrh18KtnE9v86F
bc1q96uax7zfms9djvg9yxhg7umpuyqad3xaqpq67n L2FTxj828id9y9WeeYocNCJ3J1ve1zZtpWMdgVvRu6Svx78QkHSx
bc1qh9j8fl9uvqetcmmjsgumfh9dqj7gfh0tgnejgc L4EXTHyjauaKsxVNmV2KExgckzZyVExKWLsCoXWFuMNFP15E27Ez
bc1qwmfma5p7j4zlg07pyynw4x92yt8xhdysvrgjx0 KwnxyJCPMEnd1ByM7VWYPV3EWd1zBr7g5EnsKtiEA6f9RKPu5s4o
bc1qx87aur9tgk0jsy9new576nsg7m797jaqc0ldj3 L2uMMpj5DVJyocFokuGMZBeD5zThbQFwVcvVUzXPiCbsCNd1jr3g
bc1qg0u6ul7mej95ln6jxdze8eup89yvydfnvkfc70 KzrPrip9axnTKyVgLaEmd8C5vhmEcVwnYE5V1qVsDcUt8NsdiqK1
bc1q7mx7dnfk73m4zsrw0wxs24vju79nussw339f6l KwtjrLv9YDCAB9LHxCrv5F7iudLzW2tQ7xLtEw4BV2Gcf5y5tyik
bc1q7keqf9mxfzyy7ee4sevz05y8vqqy2lmdfz74tu L56L1ywFmo88PhxdCD1KaG7a2JvTryY23xWbXnjq8bakY3CdkRd7
bc1qxlh7cypt8sngcupzvksc55ykt58s3z4jar2tws L4JHPRa8uFNk5maiftDnGxtMD7MAsboXSDYSdRXanV9A6DbPPVgi
"""

expected_root_xpriv = "zprvAWgYBBk7JR8GjE9eyfzQjYNeKtFgsJdozzSTf3eunwkkQ34hgPyWfpZpBqbChddsXwCp8RpF6Yh3XgPFGGn4W2w9htxb1AapA1E6JxpyJdS"
expected_acc_xpub = "zpub6qgUtGRB3Vt4DTynTsDf3xy6j63BsjUKKsrq7wB8pWAiEhs6ouabybS3TSZiFhKfXVXSc2q1xAbvd1j9Tjtcvh5L1n9EtxBuwJaGdpVcHeD"
expected_acc_xpriv = "zprvAch8UktHD8KkzyuKMqgegq2NB4ChUGkTxewEKYmXGAdjMuXxGNGMRo7Zc83a5HR1aqG6kbp7byc1qSRy8TVLCavTncRhpQLUj4voWvUVaYw"

# setup
wallet = bip44wallet.Bip44Wallet(mnemonic, True)
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

