import pytest
import asyncio
from pathlib import Path
from starkware.starknet.testing.starknet import Starknet
from starkware.starkware_utils.error_handling import StarkException
from starkware.starknet.definitions.error_codes import StarknetErrorCode
from utils import TestSigner, assert_revert, contract_path
from eth_keys import keys
import eth_keys
import sys
from Crypto.Hash import keccak
from nile.signer import Signer, from_call_to_call_array, get_transaction_hash

private_key = b'\x01' * 32
pk = eth_keys.keys.PrivateKey(private_key)        
eth_address = pk.public_key.to_checksum_address()


IACCOUNT_ID = 0xf10dbd44
TRUE = 1

def from_uint(uint):
    """Takes in uint256-ish tuple, returns value."""
    return uint[0] + (uint[1] << 128)


def to_uint(a):
    """Takes in value, returns uint256-ish tuple."""
    return (a & ((1 << 128) - 1), a >> 128)

@pytest.fixture(scope="module")
def event_loop():
    loop = asyncio.get_event_loop()
    yield loop
    loop.close()

@pytest.fixture(scope='module')
async def account_factory():
    starknet = await Starknet.empty()
    account = await starknet.deploy(
        contract_path("contracts/Test.cairo")
    )

    return account

@pytest.mark.asyncio
async def test_constructor(account_factory):
    account = account_factory
    k = keccak.new(digest_bits=256)
    k.update(b'some message')
    uint_hash = to_uint(int(k.hexdigest(), 16))
    signature = pk.sign_msg_hash(k.digest())
    r = to_uint(signature.r)
    s = to_uint(signature.s)
    parameter = [signature.v, r[0], r[1], s[0], s[1], uint_hash[0], uint_hash[1]]
    execution_info = await account.is_valid_eth_signature(int(eth_address,0)).invoke(signature = parameter)
    print(execution_info.result)
    assert execution_info.result == (1,)


