"""
hconfig.py:     parameters that are used to configure Helium.
"""

conf = {
    # The Helium Version number:
    'VERSION_NO': 1,

    # Max number of Helium coins that can be mined:
    'MAX_HELIUM_COINS': 21_000_000,

    # Smallest Helium currency unit in terms of one Helium coin
    'HELIUM_CENT': 1/100_000_000,

    # The max size of a Helium block in bytes
    'MAX_BLOCK_SIZE': 1_000_000,

    # Max amount of time (seconds) that a transaction can be locked
    'MAX_LOCKTIME': 30*1440*60,

    # Max number of Inputs in a Helium Transaction
    'MAX_INPUTS': 10,

    # Max number of Outputs in a Helium Transaction
    'MAX_OUTPUTS': 10,

    # Number of new blocks from a reference block that must
    # be mined before coinbase transaction in the previous
    # reference block can be spent
    'COINBASE_INTERVAL': 100,

    # Starting Nonce value for the mining proof of work computation
    'NONCE': 0,

    # Difficulty Number used in mining proof of work computation
    'DIFFICULTY_BITS': 20,
    'DIFFICULTY_NUMBER': 1/(10**(265 - 20)),

    # Retargeting interval in blocks in order to adjust the DIFFICULTY_NUMBER
    'RETARGET_INTERVAL': 1000,

    # Mining Reward
    'MINING_REWARD': 5_000_000_000,

    # Mining reward halving interval in blocks
    'REWARD_INTERVAL': 210_000
}