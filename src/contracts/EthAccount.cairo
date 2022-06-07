%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin, BitwiseBuiltin
from openzeppelin.account.library import Account, AccountCallArray
from openzeppelin.introspection.ERC165 import ERC165
from starkware.cairo.common.cairo_secp.bigint import BigInt3
from starkware.cairo.common.cairo_secp.signature import public_key_point_to_eth_address
from starkware.cairo.common.cairo_secp.ec import EcPoint
from starkware.cairo.common.alloc import alloc
#
# Constructor
#

#@constructor
#func constructor{
#        syscall_ptr : felt*,
#        pedersen_ptr : HashBuiltin*,
#        range_check_ptr,
#        bitwise_ptr: BitwiseBuiltin*
#    }(x: BigInt3, y: BigInt3):
#    alloc_locals
#    let (local keccak_ptr : felt*) = alloc()
#    let key_point = EcPoint(x=x,y=y)
#    with keccak_ptr:
#        let (public_key: felt) = public_key_point_to_eth_address(key_point)
#    end
#    Account.constructor(public_key)
#    return ()
#end

@constructor
func constructor{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr,
        bitwise_ptr: BitwiseBuiltin*
    }(public_key: felt):
    #alloc_locals
    #let (local keccak_ptr : felt*) = alloc()
    #let key_point = EcPoint(x=x,y=y)
    #with keccak_ptr:
    #    let (public_key: felt) = public_key_point_to_eth_address(key_point)
    #end
    Account.constructor(public_key)
    return ()
end

#
# Getters
#

@view
func get_public_key{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }() -> (res: felt):
    let (res) = Account.get_public_key()
    return (res=res)
end

@view
func get_nonce{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }() -> (res: felt):
    let (res) = Account.get_nonce()
    return (res=res)
end

@view
func supportsInterface{
        syscall_ptr: felt*,
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    } (interfaceId: felt) -> (success: felt):
    let (success) = ERC165.supports_interface(interfaceId)
    return (success)
end

#
# Setters
#

@external
func set_public_key{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }(new_public_key: felt):
    Account.set_public_key(new_public_key)
    return ()
end

#
# Business logic
#

func is_valid_signature{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr,
        ecdsa_ptr: SignatureBuiltin*,
        bitwise_ptr: BitwiseBuiltin*
    }(
        hash: felt,
        signature_len: felt,
        signature: felt*,
        nonce: felt
    ) -> ():    
    Account.is_valid_eth_signature(hash, signature_len, signature, nonce)    
    return ()
end

@external
func __execute__{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr,
        ecdsa_ptr: SignatureBuiltin*
    }(
        call_array_len: felt,
        call_array: AccountCallArray*,
        calldata_len: felt,
        calldata: felt*,
        nonce: felt
    ) -> (response_len: felt, response: felt*):
    let (response_len, response) = Account.eth_execute(
        call_array_len,
        call_array,
        calldata_len,
        calldata,
        nonce
    )
    return (response_len=response_len, response=response)
end
