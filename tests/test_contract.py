import pytest
import asyncio
from pathlib import Path
from starkware.starknet.testing.starknet import Starknet
from starkware.starkware_utils.error_handling import StarkException
from starkware.starknet.definitions.error_codes import StarknetErrorCode
from utils import TestSigner, assert_revert, contract_path
from fastecdsa import keys, curve

private_key = 123456789987654321
public_key = keys.get_public_key(private_key, curve.secp256k1)

IACCOUNT_ID = 0xf10dbd44
TRUE = 1


@pytest.fixture(scope="module")
def event_loop():
    loop = asyncio.get_event_loop()
    yield loop
    loop.close()

@pytest.fixture(scope='module')
async def account_factory():
    starknet = await Starknet.empty()
    account = await starknet.deploy(
        contract_path("contracts/EthAccount.cairo"),
        constructor_calldata=[public_key]
    )

    return account

@pytest.mark.asyncio
async def test_constructor(account_factory):
    account = account_factory

    execution_info = await account.get_public_key().call()
    assert execution_info.result == (signer.public_key,)

    execution_info = await account.supportsInterface(IACCOUNT_ID).call()
    assert execution_info.result == (TRUE,)

@pytest.mark.asyncio
async def test_secp256k1_account(account_factory):
    account = account_factory
    #is_valid_eth_signature
    execution_info = await account.is_valid_eth_signature().call()
    assert execution_info != none
