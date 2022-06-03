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
from nile.signer import Signer, from_call_to_call_array, get_transaction_hash

pk = eth_keys.keys.PrivateKey(b'\x01' * 32)        
pubk = pk.public_key.to_checksum_address()

IACCOUNT_ID = 0xf10dbd44
TRUE = 1

def signing(account):
    message_to_hash = b'testing a message hash'
    hash = get_transaction_hash(account.contract_address, [], [], 0, 0)
    signature = pk.sign_msg_hash(message_to_hash)
    sig_r = to_uint(signature.r)
    sig_s = to_uint(signature.s)
    return hash, signature.v, sig_r, sig_s

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
    hash, v, r, s = signing(account)
    #hash = 
    print(hash,type(hash), int(pubk,0), pubk)
    execution_info = await account._verify_eth_signature_uint256(int(pubk,0), to_uint(hash), v, r, s).invoke()
    assert execution_info.result == (signer.public_key,)
    #150667933682724627262632139063411478963274978545 != 293718746239343348680605004835135740192371701289 son las eth addresses

def to_uint(a):
    """Takes in value, returns uint256-ish tuple."""
    return (a & ((1 << 128) - 1), a >> 128)