# SPDX-License-Identifier: MIT
# OpenZeppelin Contracts for Cairo v0.1.0 (account/Account.cairo)

%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin
from starkware.cairo.common.cairo_secp.signature import verify_eth_signature
(
    AccountCallArray,
    Account_execute,
    Account_get_nonce,
    Account_initializer,
    Account_get_public_key,
    Account_set_public_key,
    Account_is_valid_signature
)
from openzeppelin.introspection.ERC165 import ERC165_supports_interface 

#
# Getters
#

@view
func get_public_key{
        syscall_ptr : felt*,
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }() -> (res: felt):
    let (res) = Account_get_public_key()
    return (res=res)
end

@view
func get_nonce{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }() -> (res: felt):
    let (res) = Account_get_nonce()
    return (res=res)
end

@view
func supportsInterface{
        syscall_ptr: felt*, 
        pedersen_ptr: HashBuiltin*,
        range_check_ptr
    } (interfaceId: felt) -> (success: felt):
    let (success) = ERC165_supports_interface(interfaceId)
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
    Account_set_public_key(new_public_key)
    return ()
end

#
# Constructor
#

@constructor
func constructor{
        syscall_ptr : felt*, 
        pedersen_ptr : HashBuiltin*,
        range_check_ptr
    }(public_key: felt):
    Account_initializer(public_key)
    return ()
end

#
# Business logic
#

@external
func is_valid_eth_signature{
            syscall_ptr : felt*,
            pedersen_ptr : HashBuiltin*,
            range_check_ptr,
            ecdsa_ptr: SignatureBuiltin*
        }(
            hash: felt,
            signature_len: felt,
            signature: felt*,
            nonce: felt
        ) -> ():
        let (_public_key) = Account_public_key.read()
        let (_current_nonce) = Account_current_nonce.read()

        # validate nonce
        assert _current_nonce = nonce


        # This interface expects a signature pointer and length to make
        # no assumption about signature validation schemes.
        # But this implementation does, and it expects a (sig_r, sig_s) pair.
        let sig_r = signature[0]
        let sig_s = signature[1]

        verify_eth_signature(
            msg_hash=hash,
            r=sig_r,
            s=sig_s,
            eth_address=_public_key)

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
    let (response_len, response) = Account_execute(
        call_array_len,
        call_array,
        calldata_len,
        calldata,
        nonce
    )
    return (response_len=response_len, response=response)
end

