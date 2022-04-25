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
from starkware.starknet.common.syscalls import (
    call_contract, get_caller_address, get_contract_address)
from starkware.cairo.common.hash import hash2
from starkware.cairo.common.bool import FALSE, TRUE

const VERSION = '0.1.0'

#
# Events
#

@event
func SubmitTransaction(nonce : felt):
end

@event
func ConfirmTransaction(nonce : felt):
end

@event
func ExecuteTransaction(nonce : felt):
end

#
# Storage
#

@storage_var
func _pending_tx_call_array_len() -> (call_array_len : felt):
end

@storage_var
func _pending_tx_call_array(index : felt) -> (call_array : AccountCallArray):
end

@storage_var
func _pending_tx_calldata_len() -> (calldata_len : felt):
end

@storage_var
func _pending_tx_calldata(index : felt) -> (calldata : felt):
end

@storage_var
func _pending_tx_nonce() -> (nonce : felt):
end

@storage_var
func _code_hash() -> (res : felt):
end

@storage_var
func _is_confirmed() -> (res : felt):
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
func get_version() -> (version : felt):
    return (version=VERSION)
end

@view
func supportsInterface{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        interfaceId : felt) -> (success : felt):
    let (success) = ERC165_supports_interface(interfaceId)
    return (success)
end

func assert_only_self{syscall_ptr : felt*}() -> ():
    let (self) = get_contract_address()
    let (caller_address) = get_caller_address()
    with_attr error_message("must be called via execute"):
        assert self = caller_address
    end
    return ()
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

func _populate_transaction_calldata{
        syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        calldata_index : felt, calldata_len : felt, calldata : felt*):
    if calldata_index == calldata_len:
        return ()
    end

    _pending_tx_calldata.write(calldata_index, calldata[calldata_index])

    _populate_transaction_calldata(
        calldata_index=calldata_index + 1, calldata_len=calldata_len, calldata=calldata)
    return ()
end

func _get_transaction_calldata{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        calldata_index : felt, calldata_len : felt, calldata : felt*):
    if calldata_index == calldata_len:
        return ()
    end

    let (value) = _pending_tx_calldata.read(calldata_index)
    assert calldata[calldata_index] = value

    _get_transaction_calldata(
        calldata_index=calldata_index + 1, calldata_len=calldata_len, calldata=calldata)

    return ()
end

func _get_transaction_call_array{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        call_index : felt, call_array_len : felt, call_array : AccountCallArray*):
    if call_index == call_array_len:
        return ()
    end

    let (value : AccountCallArray) = _pending_tx_call_array.read(call_index)
    assert call_array[call_index] = value

    _get_transaction_call_array(
        call_index=call_index + 1, call_array_len=call_array_len, call_array=call_array)

    return ()
end

func _populate_transaction_callarray{
        syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        call_index : felt, call_array_len : felt, call_array : AccountCallArray*):
    if call_index == call_array_len:
        return ()
    end

    _pending_tx_call_array.write(call_index, call_array[call_index])

    _populate_transaction_callarray(
        call_index=call_index + 1, call_array_len=call_array_len, call_array=call_array)
    return ()
end

@external
func submit_transaction{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
        call_array_len : felt, call_array : AccountCallArray*, calldata_len : felt,
        calldata : felt*, nonce : felt):
    alloc_locals
    assert_only_self()

    # Store new TX info
    _pending_tx_call_array_len.write(call_array_len)
    _pending_tx_calldata_len.write(calldata_len)
    _pending_tx_nonce.write(nonce)

    local calldata_index = 0
    local call_index = 0
    _populate_transaction_calldata(calldata_index, calldata_len, calldata)
    _populate_transaction_callarray(call_index, call_array_len, call_array)

    # Reset 2FA
    _is_confirmed.write(FALSE)

    # Emit event & update tx count
    SubmitTransaction.emit(nonce=nonce)

    return ()
end

@external
func confirm_transaction{
        syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr,
        ecdsa_ptr : SignatureBuiltin*}(code : felt) -> (response_len : felt, response : felt*):
    alloc_locals
    assert_only_self()

    let (_hash) = _code_hash.read()
    let (code_hash) = hash2{hash_ptr=pedersen_ptr}(code, 0)

    with_attr error_message("2FArgent::Wrong 2FA Code"):
        assert code_hash = _hash
    end

    let (_nonce) = _pending_tx_nonce.read()
    local calldata_index = 0
    local call_index = 0
    let (local new_calldata : felt*) = alloc()
    let (local new_call_array : AccountCallArray*) = alloc()

    let (_call_array_len) = _pending_tx_call_array_len.read()
    let (_calldata_len) = _pending_tx_calldata_len.read()

    _get_transaction_calldata(calldata_index, _calldata_len, new_calldata)
    _get_transaction_call_array(call_index, _call_array_len, new_call_array)

    let (response_len, response) = Account_execute(
        _call_array_len, new_call_array, _calldata_len, new_calldata, _nonce)

    # Emit event
    ConfirmTransaction.emit(nonce=_nonce)
    _is_confirmed.write(TRUE)

    return (response_len=response_len, response=response)
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
