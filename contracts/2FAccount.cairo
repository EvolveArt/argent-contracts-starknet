# SPDX-License-Identifier: MIT
# OpenZeppelin Contracts for Cairo v0.1.0 (account/Account.cairo)

%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin, SignatureBuiltin
from openzeppelin.account.library import (
    AccountCallArray, Account_execute, Account_get_nonce, Account_initializer,
    Account_get_public_key, Account_set_public_key, Account_is_valid_signature)

from openzeppelin.introspection.ERC165 import ERC165_supports_interface
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.math import assert_le, assert_lt
from starkware.starknet.common.syscalls import call_contract, get_caller_address
from starkware.cairo.common.bool import FALSE, TRUE

#
# Events
#

@event
func SubmitTransaction(owner : felt, tx_index : felt, to : felt):
end

@event
func ConfirmTransaction(owner : felt, tx_index : felt):
end

@event
func RevokeConfirmation(owner : felt, tx_index : felt):
end

@event
func ExecuteTransaction(owner : felt, tx_index : felt):
end

#
# Storage
#

struct Transaction:
    member to : felt
    member function_selector : felt
    member calldata_len : felt
    member executed : felt
    member num_confirmations : felt
end

@storage_var
func _next_tx_index() -> (res : felt):
end

@storage_var
func _transactions(tx_index : felt, field : felt) -> (res : felt):
    # Field enum pattern described in https://hackmd.io/@RoboTeddy/BJZFu56wF#Concise-way
end

@storage_var
func _transaction_calldata(tx_index : felt, calldata_index : felt) -> (res : felt):
end

@storage_var
func _is_confirmed(tx_index : felt, owner : felt) -> (res : felt):
end

#
# Getters
#

@view
func get_public_key{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}() -> (
        res : felt):
    let (res) = Account_get_public_key()
    return (res=res)
end

@view
func get_nonce{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}() -> (res : felt):
    let (res) = Account_get_nonce()
    return (res=res)
end

@view
func supportsInterface{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        interfaceId : felt) -> (success : felt):
    let (success) = ERC165_supports_interface(interfaceId)
    return (success)
end

@view
func is_confirmed{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        tx_index : felt, owner : felt) -> (res : felt):
    let (res) = _is_confirmed.read(tx_index=tx_index, owner=owner)
    return (res)
end

#
# Setters
#

@external
func set_public_key{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        new_public_key : felt):
    Account_set_public_key(new_public_key)
    return ()
end

#
# Constructor
#

@constructor
func constructor{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        public_key : felt):
    Account_initializer(public_key)
    return ()
end

#
# Business logic
#

@view
func is_valid_signature{
        syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr,
        ecdsa_ptr : SignatureBuiltin*}(hash : felt, signature_len : felt, signature : felt*) -> ():
    Account_is_valid_signature(hash, signature_len, signature)
    return ()
end

@external
func __execute__{
        syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr,
        ecdsa_ptr : SignatureBuiltin*}(
        call_array_len : felt, call_array : AccountCallArray*, calldata_len : felt,
        calldata : felt*, nonce : felt) -> (response_len : felt, response : felt*):
    let (response_len, response) = Account_execute(
        call_array_len, call_array, calldata_len, calldata, nonce)
    return (response_len=response_len, response=response)
end
