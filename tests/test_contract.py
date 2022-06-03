#import pytest
#import asyncio
#from pathlib import Path
#from starkware.starknet.testing.starknet import Starknet
#from starkware.starkware_utils.error_handling import StarkException
#from starkware.starknet.definitions.error_codes import StarknetErrorCode
#from utils import TestSigner, assert_revert, contract_path
#import eth_keys
#
#pysigner = eth_keys.keys.PrivateKey(private_key)        
#pypublic_key = int(pysigner.public_key.to_address(), 16)
#
#private_key = 123456789987654321
#public_key = keys.get_public_key(private_key, curve.secp256k1)
#
#IACCOUNT_ID = 0xf10dbd44
#TRUE = 1
#
#def signing():
#    message_hash = b'testing a message hash'
#    signature = pysigner.sign_msg_hash(message_hash)
#    sig_r = to_uint(signature.r)
#    sig_s = to_uint(signature.s)
#    return [signature.v, sig_r[0], sig_r[1], sig_s[0], sig_s[1]]
#
#@pytest.fixture(scope="module")
#def event_loop():
    loop = asyncio.get_event_loop()
    yield loop
#    loop.close()
#
#@pytest.fixture(scope='module')
#async def account_factory():
#    starknet = await Starknet.empty()
#    account = await starknet.deploy(
#        contract_path("contracts/EthAccount.cairo"),
#        constructor_calldata=[public_key]
#    )
#
#    return account
#
#@pytest.mark.asyncio
#async def test_constructor(account_factory):
#    account = account_factory
#
#    execution_info = await account.get_public_key().call()
#    assert execution_info.result == (signer.public_key,)
#
#    execution_info = await account.supportsInterface(IACCOUNT_ID).call()
#    assert execution_info.result == (TRUE,)
#
#    execution_info = await account.get_public_key().call()
#    assert execution_info.result == (signer.public_key,)
#
#@pytest.mark.asyncio
#async def test_secp256k1_account(account_factory):
#    account = account_factory
#    #is_valid_eth_signature
#    execution_info = await account.is_valid_eth_signature().call()
#    assert execution_info != none
