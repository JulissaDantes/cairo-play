import pytest
import asyncio
from pathlib import Path
from starkware.starknet.testing.starknet import Starknet
from starkware.starkware_utils.error_handling import StarkException
from starkware.starknet.definitions.error_codes import StarknetErrorCode
from utils import TestSigner, assert_revert, contract_path


signer = TestSigner(123456789987654321)
other = TestSigner(987654321123456789)

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
        constructor_calldata=[signer.public_key]
    )
    bad_account = await starknet.deploy(
        contract_path("contracts/EthAccount.cairo"),
        constructor_calldata=[signer.public_key],
    )

    return starknet, account, bad_account

@pytest.mark.asyncio
async def test_constructor(account_factory):
    _, account, _ = account_factory

    execution_info = await account.get_public_key().call()
    assert execution_info.result == (signer.public_key,)

    execution_info = await account.supportsInterface(IACCOUNT_ID).call()
    assert execution_info.result == (TRUE,)