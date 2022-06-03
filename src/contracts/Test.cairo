# SPDX-License-Identifier: MIT
# OpenZeppelin Contracts for Cairo v0.1.0 (account/Account.cairo)

%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin, BitwiseBuiltin
from starkware.cairo.common.cairo_secp.signature import verify_eth_signature_uint256, public_key_point_to_eth_address
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_secp.ec import EcPoint
from starkware.cairo.common.cairo_secp.bigint import BigInt3
from starkware.cairo.common.uint256 import Uint256

@external
func _verify_eth_signature_uint256{
            syscall_ptr : felt*,
            pedersen_ptr : HashBuiltin*,
            range_check_ptr,
            bitwise_ptr: BitwiseBuiltin*
        }(
            public_key: felt,
            hash: Uint256,
            sig_v: felt,
            sig_r: Uint256,
            sig_s: Uint256
        ) -> ():
        alloc_locals
        
        let (local keccak_ptr : felt*) = alloc()
        let keccak_ptr_start = keccak_ptr

        verify_eth_signature_uint256{keccak_ptr=keccak_ptr}(
            msg_hash=hash,
            r=sig_r,
            s=sig_s,
            v=sig_v,
            eth_address=public_key)

        return ()
end

func get_key{
            syscall_ptr : felt*,
            pedersen_ptr : HashBuiltin*,
            range_check_ptr,
            bitwise_ptr: BitwiseBuiltin*
        }(
        x: BigInt3,
        y: BigInt3
        ) -> (eth_address: felt):
        alloc_locals  
        
        let (local keccak_ptr : felt*) = alloc()
        let keccak_ptr_start = keccak_ptr
        let point : EcPoint = EcPoint(x=x,y=y)
        let eth_address : felt = public_key_point_to_eth_address{keccak_ptr=keccak_ptr}(point)
        return (eth_address)
        end