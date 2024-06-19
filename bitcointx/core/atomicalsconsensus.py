# Copyright (C) 2024 The Atomicals Developers
# Copyright (C) 2019 The python-bitcointx developers
#
# This file is part of python-bitcointx.
#
# It is subject to the license terms in the LICENSE-PYTHON-BITCOINTX file found in the top-level
# directory of this distribution.
#
# No part of python-bitcointx, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.
# pylama:ignore=E501

from dotenv import load_dotenv
load_dotenv()

import ctypes
from typing import Optional
from bitcointx.core import CTransaction
from os import environ

  
from cbor2 import dumps

from electrumx.lib.avm.util import (
    RequestBlockchainContext,
    RequestTxContext,
    ReactorContext,
    ScriptContext
)

ATOMICALSCONSENSUS_LIB_PATH = environ.get('ATOMICALSCONSENSUS_LIB_PATH')
if ATOMICALSCONSENSUS_LIB_PATH is None:
    assert 'ATOMICALSCONSENSUS_LIB_PATH not set' == True

ATOMICALSCONSENSUS_API_VER = 1

MAX_STATE_FINAL_BYTES =      1000000
MAX_STATE_UPDATE_BYTES =     1000000
MAX_BALANCES_BYTES =         1000000
MAX_BALANCES_UPDATE_BYTES =   100000

class AtomicalConsensusExecutionError(BaseException):
    """Exception raised for script execution error

    Attributes:
        error_code -- Error returned by the interpretor
    """
    def __init__(self, error_code, script_error, script_error_op_num):
        self.error_code = error_code
        self.script_error = script_error
        self.script_error_op_num = script_error_op_num

_libatomicals_consensus = None

# typedef enum atomicalsconsensus_error_t
atomicalsconsensus_ERR_OK = 0
atomicalsconsensus_ERR_TX_INDEX = 1                       
atomicalsconsensus_ERR_TX_SIZE_MISMATCH = 2                  
atomicalsconsensus_ERR_INVALID_FLAGS = 3                     
atomicalsconsensus_ERR_INVALID_FT_WITHDRAW = 4     
atomicalsconsensus_ERR_INVALID_NFT_WITHDRAW = 5     
atomicalsconsensus_ERR_EXCEED_MAX_STATE_FINAL_BYTES = 6    
atomicalsconsensus_ERR_EXCEED_MAX_STATE_UPDATE_BYTES = 7     
atomicalsconsensus_ERR_EXCEED_MAX_BALANCES_BYTES = 8     
atomicalsconsensus_ERR_EXCEED_MAX_BALANCES_UPDATE_BYTES = 9    
ATOMICALSCONENSUS_LAST_ERROR_VALUE = atomicalsconsensus_ERR_EXCEED_MAX_BALANCES_UPDATE_BYTES

def _add_function_definitions(handle: ctypes.CDLL) -> None:
    # Returns 1 if the input nIn of the serialized transaction pointed to by
    # txTo correctly spends the scriptPubKey pointed to by scriptPubKey under
    # the additional constraints specified by flags.
    # If not nullptr, err will contain an error/success code for the operation
    handle.atomicalsconsensus_verify_script_avm.restype = ctypes.c_int
    handle.atomicalsconsensus_verify_script_avm.argtypes = [
        ctypes.c_char_p,    # const unsigned char *scriptPubKey
        ctypes.c_uint,      # unsigned int scriptPubKeyLen
        ctypes.c_char_p,    # const unsigned char *unlockScriptPubKey
        ctypes.c_uint,      # unsigned int unlockScriptPubKeyLen
        ctypes.c_char_p,    # const unsigned char *txTo
        ctypes.c_uint,      # unsigned int txToLen
        ctypes.c_char_p,    # const unsigned char *ftStateCbor
        ctypes.c_uint,      # unsigned int ftStateCborLen
        ctypes.c_char_p,    # const unsigned char *ftStateIncomingCbor
        ctypes.c_uint,      # unsigned int ftStateIncomingCborLen
        ctypes.c_char_p,    # const unsigned char *nftStateCbor
        ctypes.c_uint,      # unsigned int nftStateCborLen
        ctypes.c_char_p,    # const unsigned char *nftStateIncomingCbor
        ctypes.c_uint,      # unsigned int nftStateIncomingCborLen
        ctypes.c_char_p,    # const unsigned char *contractExternalStateCbor
        ctypes.c_uint,      # unsigned int contractExternalStateCborLen
        ctypes.c_char_p,    # const unsigned char *contractStateCbor
        ctypes.c_uint,      # unsigned int contractStateCborLen
        ctypes.c_char_p,    # const unsigned char *prevStateHash
        ctypes.POINTER(ctypes.c_uint),                              # atomicalsconsensus_error* err
        ctypes.POINTER(ctypes.c_uint),                              # script error code
        ctypes.POINTER(ctypes.c_uint),                              # script error code op num
        ctypes.POINTER(ctypes.c_char * 32),                         # State hash bytes (hash of state updates, ft/nft balance updates and ft/nft withdraws)
        ctypes.POINTER(ctypes.c_char * MAX_STATE_FINAL_BYTES),      # State final cbor bytes
        ctypes.POINTER(ctypes.c_uint),                              # State final cbor byte length
        ctypes.POINTER(ctypes.c_uint),                              # State final data byte length (actually used by the data)
        ctypes.POINTER(ctypes.c_char * MAX_STATE_UPDATE_BYTES),     # State updates bytes
        ctypes.POINTER(ctypes.c_uint),                              # State updates cbor byte length
        ctypes.POINTER(ctypes.c_uint),                              # State updates length (actually used by the data)
        ctypes.POINTER(ctypes.c_char * MAX_STATE_UPDATE_BYTES),     # State deletes bytes
        ctypes.POINTER(ctypes.c_uint),                              # State deletes cbor byte length
        ctypes.POINTER(ctypes.c_uint),                              # State deletes length (actually used by the data)
        ctypes.POINTER(ctypes.c_char * MAX_BALANCES_BYTES),         # FT balance result cbor bytes
        ctypes.POINTER(ctypes.c_uint),                              # FT balance result cbor byte length
        ctypes.POINTER(ctypes.c_uint),                              # FT balance result byte length (actually used by the data)
        ctypes.POINTER(ctypes.c_char * MAX_BALANCES_UPDATE_BYTES),  # FT balance changes cbor bytes
        ctypes.POINTER(ctypes.c_uint),                              # FT balance changes cbor byte length
        ctypes.POINTER(ctypes.c_uint),                              # FT balance changes byte length (actually used by the data)
        ctypes.POINTER(ctypes.c_char * MAX_BALANCES_BYTES),         # NFT balance result cbor bytes
        ctypes.POINTER(ctypes.c_uint),                              # NFT balance result cbor byte length
        ctypes.POINTER(ctypes.c_uint),                              # NFT balance result byte length (actually used by the data)
        ctypes.POINTER(ctypes.c_char * MAX_BALANCES_UPDATE_BYTES),  # NFT balance changes cbor bytes
        ctypes.POINTER(ctypes.c_uint),                              # NFT balance changes cbor byte length
        ctypes.POINTER(ctypes.c_uint),                              # NFT balance changes byte length (actually used by the data)
        ctypes.POINTER(ctypes.c_char * MAX_BALANCES_UPDATE_BYTES),  # State ft withdraw cbor bytes
        ctypes.POINTER(ctypes.c_uint),                              # State ft withdraw cbor byte length
        ctypes.POINTER(ctypes.c_uint),                              # State ft withdraw data byte length (actually used by the data)
        ctypes.POINTER(ctypes.c_char * MAX_BALANCES_UPDATE_BYTES),  # State nft withdraw cbor bytes
        ctypes.POINTER(ctypes.c_uint),                              # State nft withdraw cbor byte length
        ctypes.POINTER(ctypes.c_uint)                               # State nft withdraw data byte length (actually used by the data)
    ]

    handle.atomicalsconsensus_version.restype = ctypes.c_int
    handle.atomicalsconsensus_version.argtypes = []

def load_atomicalsconsensus_library(library_name: Optional[str] = None,
                                  path: Optional[str] = None
                                  ) -> ctypes.CDLL:
    """load libatomicalsconsensus via ctypes, add default function definitions
    to the library handle, and return this handle.

    The caller is not supposed to use the handle themselves,
    as there are no known functionality at the time of writing
    that is not exposed through ConsensusVerifyScriptAvmExecute

    The caller can specify their own name for the library, if they
    want to supply their own `consensus_library_hanlde` to
    `ConsensusVerifyScriptAvmExecute()`. In that case, library must be fully
    ABI-compatible with libatomicalsconsenssus.

    """
    path = ATOMICALSCONSENSUS_LIB_PATH
    if path:
        if library_name is not None:
            raise ValueError(
                'Either path or library_name must be supplied, but not both')
    else:
        if library_name is None:
            library_name = 'atomicalsconsensus'

        path = ctypes.util.find_library(library_name)
        if path is None:
            raise ImportError('atomicalsconsensus library not found')

    try:
        print(f'path={path}')
        handle = ctypes.cdll.LoadLibrary(path)
    except Exception as e:
        raise ImportError('Cannot import atomicalsconsensus library: {}'.format(e))

    _add_function_definitions(handle)

    lib_version = handle.atomicalsconsensus_version()
    if lib_version != ATOMICALSCONSENSUS_API_VER:
        raise ImportError('atomicalsconsensus_version returned {}, '
                          'while this library only knows how to work with '
                          'version {}'.format(lib_version,
                                              ATOMICALSCONSENSUS_API_VER))

    return handle

def ConsensusVerifyScriptAvmExecute(script_context: ScriptContext,
                                    blockchain_context: RequestBlockchainContext, 
                                    request_tx_context: RequestTxContext, 
                                    reactor_context: ReactorContext): 
    global _libatomicals_consensus
    if _libatomicals_consensus is None:
        _libatomicals_consensus = load_atomicalsconsensus_library()
    handle = _libatomicals_consensus

    error_code = ctypes.c_uint()
    error_code.value = 0

    cTx = CTransaction.deserialize(request_tx_context.rawtx_bytes)
    tx_data = cTx.serialize()
    assert(tx_data == request_tx_context.rawtx_bytes)

    len_lock_script_code = len(script_context.lock_script)
    len_unlock_script_code = len(script_context.unlock_script)
 
    error_code = ctypes.c_uint()
    error_code.value = 0
    script_error_code = ctypes.c_uint()
    script_error_code.value = 0
    script_error_code_op_num = ctypes.c_uint()
    script_error_code_op_num.value = 0

    state_hash = (ctypes.c_char * 32)()
    
    state_final = (ctypes.c_char * MAX_STATE_FINAL_BYTES)()
    state_final_len = ctypes.c_uint()
    state_final_len.value = 0
    state_final_data_len = ctypes.c_uint()
    state_final_data_len.value = 0

    state_updates = (ctypes.c_char * MAX_STATE_UPDATE_BYTES)()
    state_updates_len = ctypes.c_uint()
    state_updates_len.value = 0
    state_updates_data_len = ctypes.c_uint()
    state_updates_data_len.value = 0

    state_deletes = (ctypes.c_char * MAX_STATE_UPDATE_BYTES)()
    state_deletes_len = ctypes.c_uint()
    state_deletes_len.value = 0
    state_deletes_data_len = ctypes.c_uint()
    state_deletes_data_len.value = 0

    ft_balances_result = (ctypes.c_char * MAX_BALANCES_BYTES)()
    ft_balances_result_len = ctypes.c_uint()
    ft_balances_result_len.value = 0
    ft_balances_result_data_len = ctypes.c_uint()
    ft_balances_result_data_len.value = 0

    ft_balances_updates = (ctypes.c_char * MAX_BALANCES_UPDATE_BYTES)()
    ft_balances_updates_len = ctypes.c_uint()
    ft_balances_updates_len.value = 0
    ft_balances_updates_data_len = ctypes.c_uint()
    ft_balances_updates_data_len.value = 0

    nft_balances_result = (ctypes.c_char * MAX_BALANCES_BYTES)()
    nft_balances_result_len = ctypes.c_uint()
    nft_balances_result_len.value = 0
    nft_balances_result_data_len = ctypes.c_uint()
    nft_balances_result_data_len.value = 0

    nft_balances_updates = (ctypes.c_char * MAX_BALANCES_UPDATE_BYTES)()
    nft_balances_updates_len = ctypes.c_uint()
    nft_balances_updates_len.value = 0
    nft_balances_updates_data_len = ctypes.c_uint()
    nft_balances_updates_data_len.value = 0

    ft_withdraws = (ctypes.c_char * MAX_BALANCES_UPDATE_BYTES)()
    ft_withdraws_len = ctypes.c_uint()
    ft_withdraws_len.value = 0
    ft_withdraws_data_len = ctypes.c_uint()
    ft_withdraws_data_len.value = 0

    nft_withdraws = (ctypes.c_char * MAX_BALANCES_UPDATE_BYTES)()
    nft_withdraws_len = ctypes.c_uint()
    nft_withdraws_len.value = 0
    nft_withdraws_data_len = ctypes.c_uint()
    nft_withdraws_data_len.value = 0

    ft_state_cbor = reactor_context.ft_balances
    nft_state_cbor = reactor_context.nft_balances
    ft_state_incoming_cbor = reactor_context.ft_incoming 
    nft_state_incoming_cbor = reactor_context.nft_incoming
    blockchain_context_cbor = dumps({
        'headers': blockchain_context.headers,
        'height': blockchain_context.current_height
    })
    contract_state_cbor = reactor_context.state
    print(f'reactor_context.state_hash ={reactor_context.state_hash}')
    # Any runtime error/exception caused by the library is intentionally meant to percolate up to halt the indexer
    # Any response errors are all those caused by the contract execution resulting in an error due to user input or contract setup 
    execute_result = handle.atomicalsconsensus_verify_script_avm(script_context.lock_script, len_lock_script_code, 
                                                                script_context.unlock_script, len_unlock_script_code, 
                                                                tx_data, len(tx_data), 
                                                                ft_state_cbor, len(ft_state_cbor),
                                                                ft_state_incoming_cbor, len(ft_state_incoming_cbor),
                                                                nft_state_cbor, len(nft_state_cbor),
                                                                nft_state_incoming_cbor, len(nft_state_incoming_cbor),
                                                                blockchain_context_cbor, len(blockchain_context_cbor),
                                                                contract_state_cbor, len(contract_state_cbor),
                                                                reactor_context.state_hash,
                                                                ctypes.byref(error_code),
                                                                ctypes.byref(script_error_code), 
                                                                ctypes.byref(script_error_code_op_num), 
                                                                ctypes.byref(state_hash),
                                                                ctypes.byref(state_final),
                                                                ctypes.byref(state_final_len),
                                                                ctypes.byref(state_final_data_len),
                                                                ctypes.byref(state_updates),
                                                                ctypes.byref(state_updates_len),
                                                                ctypes.byref(state_updates_data_len),
                                                                ctypes.byref(state_deletes),
                                                                ctypes.byref(state_deletes_len),
                                                                ctypes.byref(state_deletes_data_len),
                                                                ctypes.byref(ft_balances_result),
                                                                ctypes.byref(ft_balances_result_len),
                                                                ctypes.byref(ft_balances_result_data_len),
                                                                ctypes.byref(ft_balances_updates),
                                                                ctypes.byref(ft_balances_updates_len),
                                                                ctypes.byref(ft_balances_updates_data_len),
                                                                ctypes.byref(nft_balances_result),
                                                                ctypes.byref(nft_balances_result_len),
                                                                ctypes.byref(nft_balances_result_data_len),
                                                                ctypes.byref(nft_balances_updates),
                                                                ctypes.byref(nft_balances_updates_len),
                                                                ctypes.byref(nft_balances_updates_data_len),
                                                                ctypes.byref(ft_withdraws),
                                                                ctypes.byref(ft_withdraws_len),
                                                                ctypes.byref(ft_withdraws_data_len),
                                                                ctypes.byref(nft_withdraws),
                                                                ctypes.byref(nft_withdraws_len),
                                                                ctypes.byref(nft_withdraws_data_len))
    
    err = error_code.value
    print(f'error_code: {error_code.value}')
    print(f'script_error_code: {script_error_code.value}')
    print(f'script_error_code_op_num: {script_error_code_op_num.value}')
 
    # The error code of 999 is used to indicate a critical failure intentionally raised from within the consensus code to cause a crash of indexer
    # This is done regardless of whether execute_result returns 1 (True)
    if err == 999:
        raise RuntimeError('atomicalsconsensus_verify_script_avm raised panic')
    
    # Execution completed successfully
    if execute_result == 1:
        updated_reactor_context = ReactorContext(bytes(state_hash),
                                                 bytes(state_final)[:state_final_len.value], 
                                                 bytes(state_updates)[:state_updates_len.value], 
                                                 bytes(state_deletes)[:state_deletes_len.value], 
                                                 bytes(nft_state_incoming_cbor),
                                                 bytes(ft_state_incoming_cbor),
                                                 bytes(nft_balances_result)[:nft_balances_result_len.value], 
                                                 bytes(nft_balances_updates)[:nft_balances_updates_len.value], 
                                                 bytes(ft_balances_result)[:ft_balances_result_len.value], 
                                                 bytes(ft_balances_updates)[:ft_balances_updates_len.value], 
                                                 bytes(nft_withdraws)[:nft_withdraws_len.value], 
                                                 bytes(ft_withdraws)[:ft_withdraws_len.value])
        return updated_reactor_context

    assert execute_result == 0

    if err > ATOMICALSCONENSUS_LAST_ERROR_VALUE:
        raise RuntimeError(
            'atomicalsconsensus_verify_script_avm failed with '
            'unknown error code {}'.format(err))
 
    # Raise an expected exception due to smart contract logic failure
    raise AtomicalConsensusExecutionError(err, script_error_code.value, script_error_code_op_num.value)

__all__ = (
    'load_atomicalsconsensus_library',
    'ConsensusVerifyScriptAvmExecute'
)
