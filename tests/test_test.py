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

private_key = b'\x01' * 32
pk = eth_keys.keys.PrivateKey(private_key)        
pubk = pk.public_key.to_checksum_address()


IACCOUNT_ID = 0xf10dbd44
TRUE = 1

def signing(account):
    message_to_hash = b'testing a message hash'
    #must get account, call_array, calldata, nonce, max_fee
    hash = get_transaction_hash(account.address, [], [], 0, 0)
    print(hash,'im getiing this as a hashy''all')
    #2828821075934055852220125569300886328237608189494176769220760037777757219766
    #of course is different Iam pasing a changing param
    #todo revisit original implementatiomn
    #with static param: 2756949966536968755053797530078455186503706923552182306731355083062150328381
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
    x = to_uint(int(pk.public_key[:32].hex(),16))
    y = to_uint(int(pk.public_key[32:].hex(),16))
    #int(pubk,0)this is the right way to get the eth address
    #print( hash, r, s, v)
    #3390502374062641025540663937380216726131919521463450836644846335041785841004 (70967922200151345553514533283644799340, 300747944610989563154359195732535743235) (196764562288776768217680723670754120955, 92388767693770458896504210395837532470) 0
    #print( int(pubk,0), pk.public_key, pubk)
    #public = await account.get_key(x, y).invoke()
    #print(public.result)
    test_exec = await account._recover_public_key(to_uint(hash), r, s, v).invoke()#This is not returning the right thing
    rx = from_uint(test_exec.result.x)
    ry = from_uint(test_exec.result.y)
    print('this',from_uint(x),from_uint(y))
    print('resulting in', rx, ry)
    execution_info = await account._verify_eth_signature_uint256(int(pubk,0), to_uint(hash), v, r, s).invoke()
    assert execution_info.result == (signer.public_key,)
    #150667933682724627262632139063411478963274978545 != this is the one i got
    #293718746239343348680605004835135740192371701289 son las eth addresses que siempre son diferentes
    #341450081602188049170303368647362638690376738397


#_recover_public_key returns a diferent point everythime
#EcPoint(
#x=BigInt3(d0=42355523410962634072598265, d1=54489418108100514937072803, d2=8284547590306369974861239), 
#y=BigInt3(d0=35517114584224975643378862, d1=32253362464838751594470283, d2=8216016518097359459525859))
#)

def from_uint(uint):
    """Takes in uint256-ish tuple, returns value."""
    return uint[0] + (uint[1] << 128)


def to_uint(a):
    """Takes in value, returns uint256-ish tuple."""
    return (a & ((1 << 128) - 1), a >> 128)