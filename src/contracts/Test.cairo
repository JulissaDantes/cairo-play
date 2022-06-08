# SPDX-License-Identifier: MIT
# OpenZeppelin Contracts for Cairo v0.1.0 (account/Account.cairo)

%lang starknet

from starkware.cairo.common.registers import get_fp_and_pc
from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin, BitwiseBuiltin
from starkware.cairo.common.cairo_secp.signature import verify_eth_signature_uint256, public_key_point_to_eth_address, recover_public_key
from starkware.cairo.common.alloc import alloc
from starkware.starknet.common.syscalls import call_contract, get_caller_address, get_tx_info
from starkware.cairo.common.cairo_secp.ec import EcPoint
from starkware.cairo.common.cairo_secp.bigint import BigInt3, uint256_to_bigint, bigint_to_uint256
from starkware.cairo.common.uint256 import Uint256
from starkware.cairo.common.math import split_felt

@external
func is_valid_eth_signature{
            syscall_ptr : felt*,
            pedersen_ptr : HashBuiltin*,
            range_check_ptr,
            bitwise_ptr: BitwiseBuiltin*
        }(
            eth_address: felt
        ) -> (res : felt):
        alloc_locals
        let (__fp__, _) = get_fp_and_pc()
        let (tx_info) = get_tx_info()
        let sig_v: felt = tx_info.signature[0]
        local sig_r : Uint256 = Uint256(low=tx_info.signature[1], high=tx_info.signature[2])
        local sig_s : Uint256 = Uint256(low=tx_info.signature[3], high=tx_info.signature[4])
        local msg_hash : Uint256 = Uint256(low=tx_info.signature[5], high=tx_info.signature[6])
        
        let (local keccak_ptr : felt*) = alloc()
        with keccak_ptr:
            with_attr error_message(
                "The signature is not working"):
            verify_eth_signature_uint256(
                msg_hash=msg_hash,
                r=sig_r,
                s=sig_s,
                v=sig_v,
                eth_address=eth_address)
            end            
        end

        return (1)
    end

